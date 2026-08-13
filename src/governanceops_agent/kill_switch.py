"""
Kill switch — an emergency halt that, once engaged, makes every further
governed action refuse rather than proceed, until explicitly cleared by
a human. Maps to EU AI Act Article 14's human oversight requirement
(the ability to "decide not to use... or otherwise disregard, override
or reverse the output") and to OSFI's agentic bulletin's expectation
that agentic systems have a real stop mechanism, not just monitoring
that a human could theoretically act on eventually.

Deliberately the simplest module in this library — a kill switch that
itself has a complicated failure mode defeats its own purpose. It's a
thread-safe boolean flag with an audit trail and a "why" attached to
every engage/clear, nothing cleverer than that.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from governanceops_agent.audit_log import AuditLog


class KillSwitchEngagedError(Exception):
    """Raised by anything that checks the kill switch and finds it
    engaged — callers should let this propagate rather than catching
    and continuing; catching it and proceeding anyway would defeat the
    entire point of having a kill switch."""


@dataclass(frozen=True)
class KillSwitchState:
    is_engaged: bool
    engaged_by: Optional[str]
    engaged_at: Optional[datetime]
    reason: Optional[str]


class KillSwitch:
    def __init__(self, audit_log: Optional[AuditLog] = None):
        self._lock = threading.Lock()
        self._is_engaged = False
        self._engaged_by: Optional[str] = None
        self._engaged_at: Optional[datetime] = None
        self._reason: Optional[str] = None
        self._audit_log = audit_log

    def engage(self, engaged_by: str, reason: str) -> None:
        with self._lock:
            self._is_engaged = True
            self._engaged_by = engaged_by
            self._engaged_at = datetime.now(timezone.utc)
            self._reason = reason

        if self._audit_log:
            self._audit_log.append(
                "kill_switch_engaged", {"engaged_by": engaged_by, "reason": reason}
            )

    def clear(self, cleared_by: str, notes: Optional[str] = None) -> None:
        """
        Deliberately requires an explicit `cleared_by` — there's no
        "auto-clear after N minutes" path anywhere in this class. An
        emergency stop that quietly resumes on its own is arguably
        worse than not having one: it gives the *appearance* of a
        working safeguard right up until the moment nobody's watching.
        """
        with self._lock:
            was_engaged = self._is_engaged
            engaged_by, engaged_at, reason = self._engaged_by, self._engaged_at, self._reason
            self._is_engaged = False
            self._engaged_by = None
            self._engaged_at = None
            self._reason = None

        if self._audit_log:
            self._audit_log.append(
                "kill_switch_cleared",
                {
                    "cleared_by": cleared_by,
                    "notes": notes,
                    "was_engaged": was_engaged,
                    "original_engaged_by": engaged_by,
                    "original_reason": reason,
                },
            )

    def check(self) -> None:
        """Raises KillSwitchEngagedError if engaged; returns normally
        otherwise. Call this at the start of any governed action —
        e.g. PolicyEngine.evaluate or ToolPermissionRegistry.check_and_record
        would each call this first in a fully wired-up setup, so that
        engaging the kill switch actually stops new actions rather than
        just being a flag nothing consults."""
        with self._lock:
            if self._is_engaged:
                raise KillSwitchEngagedError(
                    f"Kill switch is engaged by {self._engaged_by!r}: {self._reason!r}. "
                    "No governed action may proceed until it's explicitly cleared."
                )

    @property
    def state(self) -> KillSwitchState:
        with self._lock:
            return KillSwitchState(
                is_engaged=self._is_engaged,
                engaged_by=self._engaged_by,
                engaged_at=self._engaged_at,
                reason=self._reason,
            )
