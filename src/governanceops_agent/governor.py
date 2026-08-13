"""
AgentGovernor — the front door. Wires the audit log, kill switch, HITL
checkpoint store, and tool permission registry together behind one
`evaluate_action` call, so a typical integration is "construct one
AgentGovernor, call evaluate_action before every tool call" rather than
manually wiring six separate classes together and remembering to check
the kill switch yourself before every policy evaluation.

Each component is still a fully independent, separately-usable class
(see autonomy.py, audit_log.py, policy.py, hitl.py, permissions.py,
kill_switch.py) for anyone who wants finer-grained control or a
different composition — this class is the common-case convenience
layer, not the only way to use the library.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from governanceops_agent.audit_log import AuditLog
from governanceops_agent.autonomy import AutonomyLevel
from governanceops_agent.hitl import Checkpoint, CheckpointStore
from governanceops_agent.kill_switch import KillSwitch
from governanceops_agent.permissions import PermissionDeniedError, ToolPermissionRegistry
from governanceops_agent.policy import Decision, PolicyDecisionResult, PolicyEngine


@dataclass(frozen=True)
class ActionOutcome:
    """
    What evaluate_action returns. `allowed` is the single field most
    callers actually branch on — True means proceed with the action
    right now; False means don't, and either check `checkpoint` (a
    pending HITL approval to wait on) or `denial_reason` (a hard
    block/permission denial with nothing to wait on) for why.
    """

    allowed: bool
    policy_decision: PolicyDecisionResult
    checkpoint: Optional[Checkpoint] = None
    denial_reason: Optional[str] = None


class AgentGovernor:
    def __init__(
        self,
        secret_key: Optional[str] = None,
        policy_engine: Optional[PolicyEngine] = None,
        audit_log: Optional[AuditLog] = None,
    ):
        """
        Either pass `secret_key` (the common case — constructs a fresh
        in-memory AuditLog) or pass an already-constructed `audit_log`
        directly (e.g. a PersistentAuditLog from persistence.py, which
        durably writes each event as it happens rather than living
        only in this process's memory). Passing neither is an error —
        there's no sensible default AuditLog to fall back to without a
        secret key to sign it with. Passing both is allowed but
        `secret_key` is simply unused in that case, since the supplied
        audit_log already has its own key baked in.
        """
        if audit_log is None and secret_key is None:
            raise ValueError(
                "AgentGovernor needs either secret_key (to construct its own AuditLog) "
                "or an already-constructed audit_log — got neither."
            )
        self.audit_log = audit_log if audit_log is not None else AuditLog(secret_key=secret_key)
        self.kill_switch = KillSwitch(audit_log=self.audit_log)
        self.checkpoints = CheckpointStore(audit_log=self.audit_log)
        self.permissions = ToolPermissionRegistry(audit_log=self.audit_log)
        self.policy_engine = policy_engine or PolicyEngine()

    def evaluate_action(
        self,
        action: str,
        confidence: float,
        autonomy_level: AutonomyLevel,
        tool_name: Optional[str] = None,
        tool_params: Optional[dict[str, Any]] = None,
        checkpoint_ttl_seconds: Optional[float] = None,
    ) -> ActionOutcome:
        """
        The one call most integrations need. Order of checks, and why
        each one can short-circuit the rest:

        1. Kill switch — if engaged, nothing else matters; raises
           immediately rather than returning a "not allowed" outcome,
           since a kill switch being engaged is categorically different
           from an ordinary policy denial and callers shouldn't be able
           to treat it the same way (e.g. by only checking `.allowed`
           and missing that the whole system is supposed to be halted).
        2. Policy decision (BLOCK / REQUIRE_APPROVAL / ALLOW) — the
           confidence/autonomy-based gate.
        3. If ALLOW and a tool_name was given, tool-permission scoping
           — a policy ALLOW doesn't override a tool's own scope; both
           have to agree before the action actually proceeds. This
           matters for the case where policy allows an *action*
           conceptually but the specific *tool* backing it has its own
           narrower constraint (e.g. a dollar cap) that policy
           evaluation has no way to know about.
        """
        self.kill_switch.check()  # raises KillSwitchEngagedError if engaged

        decision = self.policy_engine.evaluate(action, confidence, autonomy_level)
        self.audit_log.append(
            "policy_decision",
            {
                "action": action,
                "confidence": confidence,
                "autonomy_level": autonomy_level.name,
                "decision": decision.decision.value,
                "matched_rule": decision.matched_rule,
                "reason": decision.reason,
            },
        )

        if decision.decision == Decision.BLOCK:
            return ActionOutcome(allowed=False, policy_decision=decision, denial_reason=decision.reason)

        if decision.decision == Decision.REQUIRE_APPROVAL:
            checkpoint = self.checkpoints.create(
                action=action, reason=decision.reason, ttl_seconds=checkpoint_ttl_seconds
            )
            return ActionOutcome(allowed=False, policy_decision=decision, checkpoint=checkpoint)

        # decision.decision == Decision.ALLOW
        if tool_name is not None:
            try:
                self.permissions.check_and_record(tool_name, autonomy_level, tool_params)
            except PermissionDeniedError as exc:
                return ActionOutcome(allowed=False, policy_decision=decision, denial_reason=str(exc))

        return ActionOutcome(allowed=True, policy_decision=decision)
