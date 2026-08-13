"""
Hash-chained, HMAC-signed audit log — tamper-evident by construction,
not just "logged and trusted." Maps directly to EU AI Act Article 12
("tamper-evident logging," specifically named, not just "logging") and
to OWASP's Agentic AI Top 10 (insufficient/unverifiable audit trails
as a named risk).

Design: each entry's hash incorporates the previous entry's hash (a
standard hash chain / blockchain-style linkage), and each entry is also
HMAC-signed with a secret key. The distinction matters: the hash chain
alone proves internal consistency (no entry was inserted, removed, or
reordered without every subsequent hash changing) — but without a
signature, someone who can rewrite the whole log file could also just
recompute every hash from scratch to match a modified entry, since
SHA-256 itself needs no secret to compute. The HMAC signature is what
actually requires knowledge of a secret the attacker doesn't have —
without it, "tamper-evident" would only be true against an attacker
who edits one entry and forgets to touch the ones after it.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Optional

GENESIS_HASH = "0" * 64


def _canonical_json(data: dict) -> str:
    """
    Deterministic serialization — sort_keys=True so the same logical
    content always hashes to the same bytes regardless of dict
    insertion order. Without this, two entries with identical content
    but different key order would hash differently, which would make
    the hash chain unreliable for anything except the exact process
    that first created it (e.g. reloading from JSON and re-verifying
    would fail spuriously even with no actual tampering).
    """
    return json.dumps(data, sort_keys=True, default=str, separators=(",", ":"))


@dataclass(frozen=True)
class AuditEntry:
    sequence: int
    timestamp: str
    event_type: str
    payload: dict[str, Any]
    previous_hash: str
    entry_hash: str
    signature: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class VerificationResult:
    is_valid: bool
    entries_checked: int
    first_invalid_sequence: Optional[int] = None
    reason: Optional[str] = None


class AuditLog:
    """
    In-memory by default — `entries` is a plain list, and
    `export_entries()`/`from_entries()` handle persistence to whatever
    backing store a caller wants (a file, a database table, etc.) so
    this class itself doesn't need to know about storage. Thread-safe:
    every mutating operation holds a lock, since an agent runtime is
    very plausibly logging from multiple worker threads concurrently
    and a hash chain built from out-of-order or interleaved appends
    would be actively wrong, not just messy.
    """

    def __init__(self, secret_key: str, entries: Optional[list[AuditEntry]] = None):
        if not secret_key:
            raise ValueError(
                "AuditLog requires a non-empty secret_key — an empty key would make "
                "every signature trivially forgeable, defeating the entire point of "
                "signing entries in the first place."
            )
        self._secret_key = secret_key.encode("utf-8")
        self._entries: list[AuditEntry] = list(entries) if entries else []
        self._lock = threading.Lock()

    def _sign(self, entry_hash: str) -> str:
        return hmac.new(self._secret_key, entry_hash.encode("utf-8"), hashlib.sha256).hexdigest()

    def _compute_entry_hash(
        self, sequence: int, timestamp: str, event_type: str, payload: dict, previous_hash: str
    ) -> str:
        content = _canonical_json(
            {
                "sequence": sequence,
                "timestamp": timestamp,
                "event_type": event_type,
                "payload": payload,
                "previous_hash": previous_hash,
            }
        )
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def append(self, event_type: str, payload: dict[str, Any]) -> AuditEntry:
        with self._lock:
            sequence = len(self._entries)
            previous_hash = self._entries[-1].entry_hash if self._entries else GENESIS_HASH
            timestamp = datetime.now(timezone.utc).isoformat()

            entry_hash = self._compute_entry_hash(sequence, timestamp, event_type, payload, previous_hash)
            signature = self._sign(entry_hash)

            entry = AuditEntry(
                sequence=sequence,
                timestamp=timestamp,
                event_type=event_type,
                payload=payload,
                previous_hash=previous_hash,
                entry_hash=entry_hash,
                signature=signature,
            )
            self._entries.append(entry)
            return entry

    @property
    def entries(self) -> list[AuditEntry]:
        with self._lock:
            return list(self._entries)

    def export_entries(self) -> list[dict]:
        return [e.to_dict() for e in self.entries]

    @classmethod
    def from_entries(cls, secret_key: str, raw_entries: list[dict]) -> "AuditLog":
        """Rebuild an AuditLog from persisted dicts (e.g. loaded from a
        file or database) — used when re-attaching to a log that was
        started in a previous process. Does NOT verify on load; call
        verify() explicitly afterward if you want that checked."""
        entries = [AuditEntry(**raw) for raw in raw_entries]
        return cls(secret_key=secret_key, entries=entries)

    def verify(self) -> VerificationResult:
        """
        Walks the entire chain from the genesis hash forward,
        recomputing every entry's hash and signature independently and
        checking them against the stored values — this is a real
        recomputation, not just comparing entry.previous_hash to the
        prior entry.entry_hash (which would only catch reordering, not
        an entry whose *content* was edited in place along with a
        hand-crafted matching hash for that single entry).
        """
        entries = self.entries
        expected_previous_hash = GENESIS_HASH

        for entry in entries:
            if entry.previous_hash != expected_previous_hash:
                return VerificationResult(
                    is_valid=False,
                    entries_checked=entry.sequence,
                    first_invalid_sequence=entry.sequence,
                    reason=(
                        f"Entry {entry.sequence}'s previous_hash doesn't match the prior "
                        "entry's actual hash — an entry was likely reordered, deleted, or inserted."
                    ),
                )

            recomputed_hash = self._compute_entry_hash(
                entry.sequence, entry.timestamp, entry.event_type, entry.payload, entry.previous_hash
            )
            if recomputed_hash != entry.entry_hash:
                return VerificationResult(
                    is_valid=False,
                    entries_checked=entry.sequence,
                    first_invalid_sequence=entry.sequence,
                    reason=f"Entry {entry.sequence}'s content was modified after it was logged — recomputed hash doesn't match.",
                )

            expected_signature = self._sign(entry.entry_hash)
            if not hmac.compare_digest(expected_signature, entry.signature):
                return VerificationResult(
                    is_valid=False,
                    entries_checked=entry.sequence,
                    first_invalid_sequence=entry.sequence,
                    reason=f"Entry {entry.sequence}'s signature doesn't match — either the entry or the signature itself was tampered with.",
                )

            expected_previous_hash = entry.entry_hash

        return VerificationResult(is_valid=True, entries_checked=len(entries))
