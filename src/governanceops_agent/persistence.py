"""
JSONL file persistence for AuditLog — the one piece of durable storage
this library ships out of the box. AuditLog itself is deliberately
storage-agnostic (see its own docstring); this module is one concrete,
optional choice for callers who just want "write to a file" without
building their own adapter.

Not the only reasonable choice — a real deployment logging to a
database table, a SIEM, or object storage would want its own adapter
following the same shape (override `append`, call `super().append()`
first, then persist) — but a local JSONL file is the simplest thing
that's still genuinely useful, and needs no extra dependency.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional, Union

from governanceops_agent.audit_log import AuditEntry, AuditLog


class PersistentAuditLog(AuditLog):
    """
    Same guarantees as AuditLog (hash-chained, HMAC-signed,
    thread-safe) — `append` just also writes the new entry to a JSONL
    file immediately after the in-memory chain accepts it, one JSON
    object per line, append-only. Deliberately calls super().append()
    FIRST and only writes to disk once that succeeds — if hashing or
    signing somehow failed, there'd be nothing valid to persist yet,
    and persisting first would risk writing a line that doesn't
    actually match what ends up in the in-memory chain.
    """

    def __init__(
        self,
        secret_key: str,
        path: Union[str, Path],
        entries: Optional[list[AuditEntry]] = None,
    ):
        super().__init__(secret_key=secret_key, entries=entries)
        self.path = Path(path)

    def append(self, event_type: str, payload: dict[str, Any]) -> AuditEntry:
        entry = super().append(event_type, payload)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry.to_dict(), default=str) + "\n")
        return entry


def load_persistent_audit_log(secret_key: str, path: Union[str, Path]) -> PersistentAuditLog:
    """
    Rebuilds a PersistentAuditLog from an existing JSONL file — e.g.
    re-attaching to yesterday's log after a process restart. Reads the
    whole file into memory as the chain's starting state; further
    `append()` calls continue writing new lines to the same file. Does
    NOT verify the loaded chain automatically — call `.verify()`
    explicitly afterward, the same as AuditLog.from_entries().
    """
    path = Path(path)
    raw_entries: list[dict] = []
    if path.exists():
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    raw_entries.append(json.loads(line))

    entries = [AuditEntry(**raw) for raw in raw_entries]
    return PersistentAuditLog(secret_key=secret_key, path=path, entries=entries)
