"""
Scoped tool permissions — deny-by-default allow-listing of which
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
that can autonomously decide what to call next — every new tool a
framework adds should require someone to deliberately decide it's in
scope, not silently become reachable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from governanceops_agent.audit_log import AuditLog
from governanceops_agent.autonomy import AutonomyLevel, at_least


class PermissionDeniedError(Exception):
    """Raised when a tool call is refused — either because the tool has
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


class ToolPermissionRegistry:
    def __init__(self, audit_log: Optional[AuditLog] = None):
        self._scopes: dict[str, ToolScope] = {}
        self._call_counts: dict[str, int] = {}
        self._audit_log = audit_log

    def register(self, scope: ToolScope) -> None:
        self._scopes[scope.tool_name] = scope

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
        recording into one call rather than two separate methods — a
        caller checking permission and then separately "recording" the
        call afterward could check successfully, get interrupted before
        recording, and let a retry double-count or (worse) never count
        a call that actually happened. One atomic operation avoids that
        gap entirely.
        """
        params = params or {}

        scope = self._scopes.get(tool_name)
        if scope is None:
            self._deny(
                tool_name,
                f"'{tool_name}' has no registered scope — deny-by-default means an "
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

        self._call_counts[tool_name] = self._call_counts.get(tool_name, 0) + 1
        if self._audit_log:
            self._audit_log.append(
                "tool_call_allowed",
                {"tool_name": tool_name, "params": params, "autonomy_level": autonomy_level.name},
            )

    def reset_session(self) -> None:
        """Clears per-tool call counts — call this at the start of a new
        agent session/conversation so caps apply per-session, not
        cumulatively forever across the registry's whole lifetime."""
        self._call_counts.clear()
