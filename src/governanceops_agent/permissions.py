"""
Scoped tool permissions -- deny-by-default allow-listing of which
tools/actions an agent may call, with optional per-tool constraints
(parameter limits, call-count caps) and a minimum autonomy tier. Maps
to OWASP's Agentic AI Top 10 (excessive agency / unbounded tool access
is a named top risk) and to OSFI's agentic bulletin's expectation that
an agent's tool access be explicitly scoped, not "whatever the
framework happens to expose."

Deny-by-default is the load-bearing design decision here: a tool with
no registered scope is refused, not allowed. The alternative (allow
anything not explicitly denied) is the more common default in most
software permission systems, but it's the wrong default for an agent
that can autonomously decide what to call next -- every new tool a
framework adds should require someone to deliberately decide it's in
scope, not silently become reachable.

Thread-safe: every read-then-write against _scopes/_call_counts holds
a lock. The session call cap (max_calls_per_session) is the control
this matters most for -- a plain `self._call_counts[k] = get(k, 0) + 1`
is a non-atomic read-modify-write, and under real concurrent tool
calls a cap of 5 can silently become a much larger number, since two
threads can both read the same current count before either writes the
incremented value back.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from governanceops_agent.audit_log import AuditLog
from governanceops_agent.autonomy import AutonomyLevel, at_least


class PermissionDeniedError(Exception):
    """Raised when a tool call is refused -- either because the tool has
    no registered scope at all (deny-by-default), the caller's
    autonomy tier is below the tool's minimum, a per-call constraint
    failed (e.g. an amount over the configured cap), or the tool's
    call-count cap for this session has been reached."""


@dataclass(frozen=True)
class ToolScope:
    tool_name: str
    minimum_autonomy: AutonomyLevel = AutonomyLevel.L0_NO_AUTONOMY
    max_calls_per_session: Optional[int] = None
    constraint: Optional[Callable[[dict[str, Any]], bool]] = None
    constraint_description: Optional[str] = None
    # Calls whose amount is above this need an approved, unused HITL
    # checkpoint bound to that exact call -- see AgentGovernor.evaluate_action.
    approval_above: Optional[float] = None


@dataclass(frozen=True)
class CumulativeLimit:
    """
    A ceiling on the summed amount of ALL listed tools in one session,
    not each tool separately. Per-tool caps alone let an agent spend
    the same budget twice by splitting it across two tools (e.g. a
    refund plus a credit adjustment to the same customer).
    """

    limit_id: str
    tool_names: tuple[str, ...]
    ceiling: float


_AMOUNT_PARAM_CANDIDATES = ("amount", "value", "total")


def _amount_from(params: dict[str, Any]) -> Optional[Any]:
    for key in _AMOUNT_PARAM_CANDIDATES:
        if key in params:
            return params[key]
    return None


class ToolPermissionRegistry:
    def __init__(self, audit_log: Optional[AuditLog] = None):
        self._scopes: dict[str, ToolScope] = {}
        self._call_counts: dict[str, int] = {}
        self._cumulative_limits: dict[str, CumulativeLimit] = {}
        self._cumulative_used: dict[str, Any] = {}
        self._audit_log = audit_log
        self._lock = threading.Lock()

    def register(self, scope: ToolScope) -> None:
        with self._lock:
            self._scopes[scope.tool_name] = scope

    def register_cumulative_limit(self, limit: CumulativeLimit) -> None:
        with self._lock:
            self._cumulative_limits[limit.limit_id] = limit

    def requires_approval(self, tool_name: str, params: Optional[dict[str, Any]] = None) -> bool:
        """True if this call is above its tool's approval_above threshold.
        A call with no amount param fails closed: approval is required."""
        with self._lock:
            scope = self._scopes.get(tool_name)
        if scope is None or scope.approval_above is None:
            return False
        amount = _amount_from(params or {})
        return amount is None or amount > scope.approval_above

    def _deny(self, tool_name: str, reason: str) -> None:
        if self._audit_log:
            self._audit_log.append(
                "tool_call_denied", {"tool_name": tool_name, "reason": reason}
            )
        raise PermissionDeniedError(reason)

    def check_and_record(
        self, tool_name: str, autonomy_level: AutonomyLevel, params: Optional[dict[str, Any]] = None
    ) -> None:
        """
        Raises PermissionDeniedError if the call isn't allowed;
        otherwise records the call (incrementing its session count) and
        returns normally. Deliberately combines the check and the
        recording into one call rather than two separate methods -- a
        caller checking permission and then separately "recording" the
        call afterward could check successfully, get interrupted before
        recording, and let a retry double-count or (worse) never count
        a call that actually happened. The whole check-and-increment
        sequence runs under one lock acquisition, so no other thread's
        check_and_record can interleave between "read the current
        count" and "write the incremented count" -- that's what makes
        this genuinely atomic, not just sequential-looking in the
        source.
        """
        params = params or {}

        with self._lock:
            scope = self._scopes.get(tool_name)
            if scope is None:
                self._deny(
                    tool_name,
                    f"'{tool_name}' has no registered scope -- deny-by-default means an "
                    "unregistered tool is refused, not silently allowed.",
                )

            if not at_least(autonomy_level, scope.minimum_autonomy):
                self._deny(
                    tool_name,
                    f"'{tool_name}' requires autonomy tier {scope.minimum_autonomy.name} or "
                    f"higher; caller is at {autonomy_level.name}.",
                )

            if scope.constraint is not None and not scope.constraint(params):
                description = scope.constraint_description or "a per-call constraint"
                self._deny(tool_name, f"'{tool_name}' call violates {description}.")

            if scope.max_calls_per_session is not None:
                current_count = self._call_counts.get(tool_name, 0)
                if current_count >= scope.max_calls_per_session:
                    self._deny(
                        tool_name,
                        f"'{tool_name}' has reached its session call cap of "
                        f"{scope.max_calls_per_session}.",
                    )

            applicable = [lim for lim in self._cumulative_limits.values() if tool_name in lim.tool_names]
            if applicable:
                amount = _amount_from(params)
                if amount is None:
                    self._deny(
                        tool_name,
                        f"'{tool_name}' is under a cumulative limit but the call has no "
                        "'amount'/'value'/'total' param -- refusing rather than counting it as 0.",
                    )
                for lim in applicable:
                    used = self._cumulative_used.get(lim.limit_id, 0)
                    if used + amount > lim.ceiling:
                        self._deny(
                            tool_name,
                            f"'{tool_name}' call of {amount} would bring cumulative limit "
                            f"{lim.limit_id} to {used + amount}, over its ceiling of {lim.ceiling}.",
                        )
                for lim in applicable:
                    self._cumulative_used[lim.limit_id] = self._cumulative_used.get(lim.limit_id, 0) + amount

            self._call_counts[tool_name] = self._call_counts.get(tool_name, 0) + 1

        if self._audit_log:
            self._audit_log.append(
                "tool_call_allowed",
                {"tool_name": tool_name, "params": params, "autonomy_level": autonomy_level.name},
            )

    def reset_session(self) -> None:
        """Clears per-tool call counts -- call this at the start of a new
        agent session/conversation so caps apply per-session, not
        cumulatively forever across the registry's whole lifetime."""
        with self._lock:
            self._call_counts.clear()
            self._cumulative_used.clear()
