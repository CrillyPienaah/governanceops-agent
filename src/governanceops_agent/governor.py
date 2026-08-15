"""
AgentGovernor -- the front door. Wires the audit log, kill switch, HITL
checkpoint store, and tool permission registry together behind one
`evaluate_action` call, so a typical integration is "construct one
AgentGovernor, call evaluate_action before every tool call" rather than
manually wiring six separate classes together and remembering to check
the kill switch yourself before every policy evaluation.

Each component is still a fully independent, separately-usable class
(see autonomy.py, audit_log.py, policy.py, hitl.py, permissions.py,
kill_switch.py) for anyone who wants finer-grained control or a
different composition -- this class is the common-case convenience
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
    callers actually branch on -- True means proceed with the action
    right now; False means don't, and either check `checkpoint` (a
    pending HITL approval to wait on) or `denial_reason` (a hard
    block/permission denial with nothing to wait on) for why.
    """

    allowed: bool
    policy_decision: PolicyDecisionResult
    checkpoint: Optional[Checkpoint] = None
    denial_reason: Optional[str] = None


# Maps each event_type this library actually produces to how
# report_event should populate the generic 'decision' column on
# Inventory's side -- several event types are unambiguous even though
# their own payload has no literal "decision" key (a tool_call_denied
# event IS a block; there's no other way to read it).
_EVENT_TYPE_DECISION = {
    "tool_call_allowed": "allow",
    "tool_call_denied": "block",
    "hitl_checkpoint_created": "require_approval",
    "hitl_checkpoint_approved": "allow",
    "hitl_checkpoint_rejected": "block",
    "hitl_checkpoint_expired": "block",
}


class AgentGovernor:
    def __init__(
        self,
        secret_key: Optional[str] = None,
        policy_engine: Optional[PolicyEngine] = None,
        audit_log: Optional[AuditLog] = None,
    ):
        """
        Either pass `secret_key` (the common case -- constructs a fresh
        in-memory AuditLog) or pass an already-constructed `audit_log`
        directly (e.g. a PersistentAuditLog from persistence.py, which
        durably writes each event as it happens rather than living
        only in this process's memory). Passing neither is an error --
        there's no sensible default AuditLog to fall back to without a
        secret key to sign it with. Passing both is allowed but
        `secret_key` is simply unused in that case, since the supplied
        audit_log already has its own key baked in.
        """
        if audit_log is None and secret_key is None:
            raise ValueError(
                "AgentGovernor needs either secret_key (to construct its own AuditLog) "
                "or an already-constructed audit_log -- got neither."
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

        # The autonomy tier actually approved in Inventory, when this
        # governor was built via from_governanceops() -- None means
        # "not built that way, no ceiling to enforce." See
        # evaluate_action's use of this: a caller-supplied autonomy
        # tier ABOVE this ceiling gets clamped down to it, not honored
        # as-is. Without this, evaluate_action's autonomy_level
        # parameter was pure caller input with nothing tying it back to
        # what Inventory actually approved -- passing a higher tier
        # than approved made policy/tool rules match MORE readily, not
        # less, since rules check "is the caller's tier at least X,"
        # and nothing ever checked the caller's tier against a ceiling
        # from above. For a library whose whole pitch is "Inventory is
        # the source of truth for runtime policy," an unenforced
        # approved tier is a real gap in that claim, not a cosmetic one.
        self._approved_autonomy_ceiling: Optional[AutonomyLevel] = None

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
        Builds an AgentGovernor from a GovernanceOps Inventory record --
        the concrete mechanism behind "Inventory becomes the source of
        truth for runtime policy": a risk officer's approved autonomy
        tier, permitted/forbidden tools, and confidence/transaction
        thresholds (set in Tool 1) become a real, machine-enforced
        PolicyEngine + ToolScope configuration here, via one HTTP call.

        Raises InventoryClientError if the model has no
        runtime policy configured (autonomy_level unset in Inventory) or if
        Inventory can't be reached -- there's no sensible governor to
        construct from a bundle that doesn't exist, so this fails loudly
        rather than silently falling back to an empty, permissive
        PolicyEngine.
        """
        bundle = fetch_policy_bundle(inventory_base_url, ai_system_record_id, inventory_token)
        if bundle is None:
            raise InventoryClientError(
                f"GovernanceOps Inventory record {ai_system_record_id!r} has no runtime "
                "policy configured (autonomy_level is unset) -- nothing to build a governor from."
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
        governor._approved_autonomy_ceiling = compiled.autonomy_level
        governor._ai_system_record_id = ai_system_record_id
        governor._inventory_base_url = inventory_base_url
        governor._inventory_token = inventory_token
        return governor

    def _event_dict_from_entry(self, entry: AuditEntry) -> dict:
        """
        Maps an AuditEntry's type-specific payload onto Inventory's
        fixed RuntimeEventCreate columns (action, tool_name, decision,
        reason). Each of the six event types this library actually
        produces shapes its payload differently -- report_event used
        to assume every entry looked like a policy_decision one, which
        silently emptied the typed columns for the other five: a
        kill_switch_cleared event's actual reason lives under
        original_reason, not reason; hitl_checkpoint_approved has no
        "reason" key at all (resolved_by/notes is what it has instead);
        and tool_call_denied's decision was left null even though that
        event type is unambiguously a denial. raw_payload always
        carries the complete original entry regardless -- nothing here
        is ever lost, only the subset that maps onto Inventory's typed,
        queryable columns changes per event type.
        """
        payload = entry.payload
        event_type = entry.event_type

        if event_type == "policy_decision":
            action = payload.get("action")
            tool_name = None
            decision = payload.get("decision")
            reason = payload.get("reason")
            # Prefers the policy_version/hash actually recorded in the
            # entry at decision time over this governor's CURRENT
            # values -- identical today (nothing ever refreshes a
            # governor's policy after construction), but the entry's
            # own value is the more correct source in principle, and
            # "which policy version produced this decision" is the
            # entire point of the version/hash mechanism in the first
            # place.
            policy_version = payload.get("policy_version", self.policy_version)
            policy_hash = payload.get("policy_hash", self.policy_hash)
        elif event_type in ("tool_call_allowed", "tool_call_denied"):
            action = None
            tool_name = payload.get("tool_name")
            decision = _EVENT_TYPE_DECISION.get(event_type)
            reason = payload.get("reason")  # only tool_call_denied carries one
            policy_version = self.policy_version
            policy_hash = self.policy_hash
        elif event_type == "kill_switch_engaged":
            action = None
            tool_name = None
            decision = None
            reason = payload.get("reason")
            policy_version = self.policy_version
            policy_hash = self.policy_hash
        elif event_type == "kill_switch_cleared":
            action = None
            tool_name = None
            decision = None
            reason = payload.get("notes") or payload.get("original_reason")
            policy_version = self.policy_version
            policy_hash = self.policy_hash
        elif event_type in (
            "hitl_checkpoint_created",
            "hitl_checkpoint_approved",
            "hitl_checkpoint_rejected",
            "hitl_checkpoint_expired",
        ):
            action = payload.get("action")
            tool_name = None
            decision = _EVENT_TYPE_DECISION.get(event_type)
            # "reason" only exists on the _created payload; approved/
            # rejected/expired carry resolved_by/notes instead, which
            # have no typed column of their own on Inventory's side yet
            # -- still fully present in raw_payload below.
            reason = payload.get("reason") or payload.get("notes")
            policy_version = self.policy_version
            policy_hash = self.policy_hash
        else:
            # An event type this mapping doesn't know about yet --
            # degrade gracefully rather than crash. Nothing typed, but
            # raw_payload still carries everything, so no data is lost,
            # only its queryability on Inventory's side.
            action = payload.get("action")
            tool_name = payload.get("tool_name")
            decision = payload.get("decision")
            reason = payload.get("reason")
            policy_version = self.policy_version
            policy_hash = self.policy_hash

        return {
            "occurred_at": entry.timestamp,
            "event_type": event_type,
            "action": action,
            "tool_name": tool_name,
            "decision": decision,
            "reason": reason,
            "policy_version": policy_version,
            "policy_hash": policy_hash,
            "raw_payload": payload,
        }

    def report_event(self, entry: AuditEntry, token: Optional[str] = None) -> dict:
        """
        Reports one audit-log entry back to the GovernanceOps Inventory
        record this governor was built from -- the return path that
        closes the control loop. Only callable on a governor built via
        from_governanceops(); raises RuntimeError otherwise, since a
        governor built by hand (no secret_key-only construction, no
        Inventory record behind it) has nowhere to report to.

        Deliberately explicit and caller-invoked, not automatic --
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

        event = self._event_dict_from_entry(entry)
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

        1. Kill switch -- if engaged, nothing else matters; raises
           immediately rather than returning a "not allowed" outcome,
           since a kill switch being engaged is categorically different
           from an ordinary policy denial and callers shouldn't be able
           to treat it the same way (e.g. by only checking `.allowed`
           and missing that the whole system is supposed to be halted).
        2. Autonomy ceiling -- if this governor was built from an
           Inventory record, the caller-supplied autonomy_level is
           capped at the tier actually approved there. A caller
           claiming a HIGHER tier than Inventory approved doesn't get
           evaluated at that higher tier; it gets evaluated at the
           approved ceiling instead, since letting a caller's own
           self-assessment override what was actually approved would
           make the approval meaningless.
        3. Policy decision (BLOCK / REQUIRE_APPROVAL / ALLOW) -- the
           confidence/autonomy-based gate, using the (possibly capped)
           effective autonomy level.
        4. If ALLOW and a tool_name was given, tool-permission scoping
           -- a policy ALLOW doesn't override a tool's own scope; both
           have to agree before the action actually proceeds. This
           matters for the case where policy allows an *action*
           conceptually but the specific *tool* backing it has its own
           narrower constraint (e.g. a dollar cap) that policy
           evaluation has no way to know about.
        """
        self.kill_switch.check()  # raises KillSwitchEngagedError if engaged

        effective_autonomy_level = autonomy_level
        if (
            self._approved_autonomy_ceiling is not None
            and autonomy_level > self._approved_autonomy_ceiling
        ):
            effective_autonomy_level = self._approved_autonomy_ceiling

        decision = self.policy_engine.evaluate(action, confidence, effective_autonomy_level)

        policy_decision_payload = {
            "action": action,
            "confidence": confidence,
            "autonomy_level": effective_autonomy_level.name,
            "decision": decision.decision.value,
            "matched_rule": decision.matched_rule,
            "reason": decision.reason,
            "policy_version": self.policy_version,
            "policy_hash": self.policy_hash,
        }
        if effective_autonomy_level != autonomy_level:
            # Only present when the ceiling actually mattered, so the
            # common case (no clamping) doesn't change the payload
            # shape for anything already reading "autonomy_level" from
            # a policy_decision entry.
            policy_decision_payload["claimed_autonomy_level"] = autonomy_level.name
        self.audit_log.append("policy_decision", policy_decision_payload)

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
                self.permissions.check_and_record(tool_name, effective_autonomy_level, tool_params)
            except PermissionDeniedError as exc:
                return ActionOutcome(allowed=False, policy_decision=decision, denial_reason=str(exc))

        return ActionOutcome(allowed=True, policy_decision=decision)
