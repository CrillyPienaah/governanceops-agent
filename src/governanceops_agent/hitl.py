"""
Human-in-the-loop checkpoints -- what a PolicyEngine's REQUIRE_APPROVAL
decision actually creates and waits on. Maps to OSFI's agentic bulletin
(explicit human checkpoints for actions above a risk threshold) and to
EU AI Act Article 14 ("technically enforced" human oversight -- the
distinction that article draws matters here: a checkpoint that an
agent can just skip past if no human responds in time is not
technically-enforced oversight, it's a suggestion. See `resolve_expired`
below for how this library defaults on the side of blocking, not
allowing, when nobody actually shows up to approve something.)
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Optional

from governanceops_agent.audit_log import AuditLog


class CheckpointStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


class CheckpointError(Exception):
    """Raised for any invalid checkpoint operation -- resolving a
    checkpoint that's already resolved, or looking up one that doesn't
    exist."""


@dataclass
class Checkpoint:
    checkpoint_id: str
    action: str
    reason: str
    created_at: datetime
    status: CheckpointStatus = CheckpointStatus.PENDING
    resolved_by: Optional[str] = None
    resolved_at: Optional[datetime] = None
    resolution_notes: Optional[str] = None
    expires_at: Optional[datetime] = None

    @property
    def is_resolved(self) -> bool:
        return self.status != CheckpointStatus.PENDING


class CheckpointStore:
    """
    In-memory store, same rationale as AuditLog: this class owns the
    checkpoint *lifecycle* (create/approve/reject/expire), not
    persistence -- a real deployment would back this with a database
    row per checkpoint so a human's approval can survive a process
    restart, but that's a storage-adapter concern layered on top of
    this class's interface, not something this class needs to know
    about itself.

    Every state-changing operation is written to the audit log if one
    is provided -- a HITL checkpoint that approved a high-risk action
    is exactly the kind of event EU AI Act Article 12 wants captured,
    and exactly the kind of event that matters most if it's ever later
    disputed ("who approved this, and when").

    Thread-safe: every method that reads or mutates _checkpoints holds
    a lock. Two concurrent approve()/reject() calls on the same
    checkpoint could otherwise both pass the is_resolved guard before
    either one writes its resolution, double-logging the decision and
    leaving whichever call happened to write last as the final state
    -- silently contradicting the "a checkpoint's resolution is final"
    guarantee this class's own docstring makes. sweep_expired()
    iterating the checkpoint dict while create() concurrently inserts
    a new key is the same root cause from the other direction (a
    genuine RuntimeError from Python's dict, not just a race in
    principle) -- the module docstring's own advice to call
    sweep_expired() "periodically from a background task" is exactly
    the concurrent-with-create() pattern that used to break it.
    """

    def __init__(self, audit_log: Optional[AuditLog] = None):
        self._checkpoints: dict[str, Checkpoint] = {}
        self._audit_log = audit_log
        self._lock = threading.Lock()

    def create(
        self, action: str, reason: str, ttl_seconds: Optional[float] = None
    ) -> Checkpoint:
        checkpoint_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=ttl_seconds) if ttl_seconds else None

        checkpoint = Checkpoint(
            checkpoint_id=checkpoint_id,
            action=action,
            reason=reason,
            created_at=now,
            expires_at=expires_at,
        )

        with self._lock:
            self._checkpoints[checkpoint_id] = checkpoint

        if self._audit_log:
            self._audit_log.append(
                "hitl_checkpoint_created",
                {
                    "checkpoint_id": checkpoint_id,
                    "action": action,
                    "reason": reason,
                    "expires_at": expires_at.isoformat() if expires_at else None,
                },
            )
        return checkpoint

    def get(self, checkpoint_id: str) -> Checkpoint:
        with self._lock:
            if checkpoint_id not in self._checkpoints:
                raise CheckpointError(f"No checkpoint found with id {checkpoint_id!r}.")
            return self._checkpoints[checkpoint_id]

    def _resolve(
        self, checkpoint_id: str, status: CheckpointStatus, resolved_by: str, notes: Optional[str]
    ) -> Checkpoint:
        with self._lock:
            if checkpoint_id not in self._checkpoints:
                raise CheckpointError(f"No checkpoint found with id {checkpoint_id!r}.")
            checkpoint = self._checkpoints[checkpoint_id]

            if checkpoint.is_resolved:
                raise CheckpointError(
                    f"Checkpoint {checkpoint_id!r} was already resolved as "
                    f"{checkpoint.status.value!r} -- cannot resolve it again as {status.value!r}. "
                    "A checkpoint's resolution is final, not something a later call can overwrite."
                )

            checkpoint.status = status
            checkpoint.resolved_by = resolved_by
            checkpoint.resolved_at = datetime.now(timezone.utc)
            checkpoint.resolution_notes = notes

        if self._audit_log:
            self._audit_log.append(
                f"hitl_checkpoint_{status.value}",
                {
                    "checkpoint_id": checkpoint_id,
                    "action": checkpoint.action,
                    "resolved_by": resolved_by,
                    "notes": notes,
                },
            )
        return checkpoint

    def approve(self, checkpoint_id: str, approver: str, notes: Optional[str] = None) -> Checkpoint:
        return self._resolve(checkpoint_id, CheckpointStatus.APPROVED, approver, notes)

    def reject(self, checkpoint_id: str, approver: str, notes: Optional[str] = None) -> Checkpoint:
        return self._resolve(checkpoint_id, CheckpointStatus.REJECTED, approver, notes)

    def is_expired(self, checkpoint: Checkpoint) -> bool:
        if checkpoint.expires_at is None:
            return False
        return not checkpoint.is_resolved and datetime.now(timezone.utc) >= checkpoint.expires_at

    def sweep_expired(self) -> list[Checkpoint]:
        """
        Marks every pending-but-past-its-expiry checkpoint as EXPIRED
        (not APPROVED) -- the safe default described in the module
        docstring. Call this periodically (e.g. from a background
        task) rather than relying on expiry being checked only at the
        moment something happens to call is_expired() on one specific
        checkpoint; a checkpoint nobody ever looks at again should
        still end up expired, not stay PENDING forever.
        """
        expired = []
        with self._lock:
            for checkpoint in self._checkpoints.values():
                if self.is_expired(checkpoint):
                    checkpoint.status = CheckpointStatus.EXPIRED
                    checkpoint.resolved_at = datetime.now(timezone.utc)
                    checkpoint.resolution_notes = "Expired without human response -- auto-resolved as EXPIRED, not approved."
                    expired.append(checkpoint)

        for checkpoint in expired:
            if self._audit_log:
                self._audit_log.append(
                    "hitl_checkpoint_expired",
                    {"checkpoint_id": checkpoint.checkpoint_id, "action": checkpoint.action},
                )
        return expired
