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

from governanceops_agent.audit_log import AuditEntry, AuditLog
from governanceops_agent.autonomy import AutonomyLevel
from governanceops_agent.hitl import Checkpoint, CheckpointStore
from governanceops_agent.inventory_client import (
    InventoryClientError,
    build_governance_from_bundle,
    fetch_policy_bundle,
    report_runtime_event,
)
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

        # Only meaningful for a governor built via from_governanceops()
        # -- None here means either "not built that way" or "built
        # from a bundle with no version/hash set." report_event() checks
        # for _ai_system_record_id specifically to tell those apart.
        self.policy_version: Optional[int] = None
        self.policy_hash: Optional[str] = None

    @classmethod
    def from_governanceops(
        cls,
        ai_system_record_id: str,
        inventory_base_url: str,
        secret_key: Optional[str] = None,
        audit_log: Optional[AuditLog] = None,
        inventory_token: Optional[str] = None,
    ) -> "AgentGovernor":
        """
        Builds an AgentGovernor from a GovernanceOps Inventory record —
        the concrete mechanism behind "Inventory becomes the source of
        truth for runtime policy": a risk officer's approved autonomy
        tier, permitted/forbidden tools, and confidence/transaction
        thresholds (set in Tool 1) become a real, machine-enforced
        PolicyEngine + ToolScope configuration here, via one HTTP call.

        Raises InventoryClientError if the model has no
        runtime policy configured (autonomy_level unset in Inventory) or if
        Inventory can't be reached — there's no sensible governor to
        construct from a bundle that doesn't exist, so this fails loudly
        rather than silently falling back to an empty, permissive
        PolicyEngine.
        """
        bundle = fetch_policy_bundle(inventory_base_url, ai_system_record_id, inventory_token)
        if bundle is None:
            raise InventoryClientError(
                f"GovernanceOps Inventory record {ai_system_record_id!r} has no runtime "
                "policy configured (autonomy_level is unset) — nothing to build a governor from."
            )

        compiled = build_governance_from_bundle(bundle)
        governor = cls(secret_key=secret_key, audit_log=audit_log, policy_engine=compiled.engine)
        for scope in compiled.tool_scopes:
            governor.permissions.register(scope)

        # Stashed so report_event() knows where to report back to, and
        # so every policy_decision audit entry can record exactly which
        # policy state produced it -- see evaluate_action below.
        governor.policy_version = compiled.policy_version
        governor.policy_hash = compiled.policy_hash
        governor._ai_system_record_id = ai_system_record_id
        governor._inventory_base_url = inventory_base_url
        governor._inventory_token = inventory_token
        return governor

    def report_event(self, entry: AuditEntry, token: Optional[str] = None) -> dict:
        """
        Reports one audit-log entry back to the GovernanceOps Inventory
        record this governor was built from — the return path that
        closes the control loop. Only callable on a governor built via
        from_governanceops(); raises RuntimeError otherwise, since a
        governor built by hand (no secret_key-only construction, no
        Inventory record behind it) has nowhere to report to.

        Deliberately explicit and caller-invoked, not automatic —
        evaluate_action() never calls this itself. Reporting every
        single ALLOWED action back to Inventory would be noise, not
        evidence; the caller decides which entries are worth reporting
        (almost always: BLOCK/REQUIRE_APPROVAL decisions, tool denials,
        and kill-switch events, not routine allows).
        """
        if not hasattr(self, "_ai_system_record_id"):
            raise RuntimeError(
                "report_event() only works on a governor built via AgentGovernor.from_governanceops() "
                "-- this governor has no Inventory record to report back to."
            )

        event = {
            "occurred_at": entry.timestamp,
            "event_type": entry.event_type,
            "action": entry.payload.get("action"),
            "tool_name": entry.payload.get("tool_name"),
            "decision": entry.payload.get("decision"),
            "reason": entry.payload.get("reason") or entry.payload.get("denial_reason"),
            "policy_version": self.policy_version,
            "policy_hash": self.policy_hash,
            "raw_payload": entry.payload,
        }
        return report_runtime_event(
            self._inventory_base_url,
            self._ai_system_record_id,
            event,
            token or self._inventory_token,
        )

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
                "policy_version": self.policy_version,
                "policy_hash": self.policy_hash,
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
