"""
GovernanceOps Agent — runtime governance controls for agentic AI
systems. See README.md for the full picture; this file just exposes
the pieces most integrations actually import.

Typical usage:

    from governanceops_agent import AgentGovernor, AutonomyLevel, PolicyEngine, threshold_rule_pair

    engine = PolicyEngine()
    allow_rule, approval_rule = threshold_rule_pair(
        "wire_transfer", min_confidence=0.85, action_prefix="wire_transfer"
    )
    engine.add_rule(allow_rule)
    engine.add_rule(approval_rule)

    governor = AgentGovernor(secret_key="...", policy_engine=engine)
    outcome = governor.evaluate_action(
        "wire_transfer_client_x", confidence=0.6, autonomy_level=AutonomyLevel.L3_BOUNDED_AUTONOMY
    )
    if not outcome.allowed:
        # outcome.checkpoint is set if this is a pending HITL approval,
        # or outcome.denial_reason is set for a hard block/permission denial.
        ...

Or, if you're also running GovernanceOps Inventory (Tool 1), build a
governor directly from a risk officer's approved Inventory record
instead of hand-writing policy rules:

    governor = AgentGovernor.from_governanceops(
        ai_system_record_id="<the model's record_id in Inventory>",
        inventory_base_url="https://your-inventory-instance.example.com/api/v1",
        secret_key="...",
        inventory_token="...",  # a valid bearer token, since Inventory requires auth
    )
    # governor's PolicyEngine and ToolPermissionRegistry are now built
    # directly from that model's autonomy_level, permitted_tools,
    # forbidden_tools, confidence_threshold, and transaction_limit —
    # set once in Inventory by a risk officer, enforced here at runtime.
"""

from governanceops_agent.audit_log import AuditEntry, AuditLog, VerificationResult
from governanceops_agent.autonomy import AutonomyLevel, AutonomyProfile, at_least, profile_for
from governanceops_agent.governor import ActionOutcome, AgentGovernor
from governanceops_agent.hitl import Checkpoint, CheckpointError, CheckpointStatus, CheckpointStore
from governanceops_agent.inventory_client import InventoryClientError, build_governance_from_bundle, fetch_policy_bundle, report_runtime_event, CompiledPolicy
from governanceops_agent.kill_switch import KillSwitch, KillSwitchEngagedError, KillSwitchState
from governanceops_agent.permissions import PermissionDeniedError, ToolPermissionRegistry, ToolScope
from governanceops_agent.policy import (
    Decision,
    PolicyDecisionResult,
    PolicyEngine,
    PolicyRule,
    block_rule,
    threshold_rule_pair,
)
from governanceops_agent.crosswalk import CrosswalkEntry, crosswalk_for_component, crosswalk_for_framework
from governanceops_agent.persistence import PersistentAuditLog, load_persistent_audit_log
from governanceops_agent.gate import GateConfigError, GateReport, ScenarioResult, load_gate_config, run_gate

__all__ = [
    "AuditEntry",
    "AuditLog",
    "VerificationResult",
    "AutonomyLevel",
    "AutonomyProfile",
    "at_least",
    "profile_for",
    "ActionOutcome",
    "AgentGovernor",
    "Checkpoint",
    "CheckpointError",
    "CheckpointStatus",
    "CheckpointStore",
    "KillSwitch",
    "KillSwitchEngagedError",
    "KillSwitchState",
    "PermissionDeniedError",
    "ToolPermissionRegistry",
    "ToolScope",
    "Decision",
    "PolicyDecisionResult",
    "PolicyEngine",
    "PolicyRule",
    "block_rule",
    "threshold_rule_pair",
    "CrosswalkEntry",
    "crosswalk_for_component",
    "crosswalk_for_framework",
    "PersistentAuditLog",
    "load_persistent_audit_log",
    "GateConfigError",
    "GateReport",
    "ScenarioResult",
    "load_gate_config",
    "run_gate",
    "InventoryClientError",
    "build_governance_from_bundle",
    "fetch_policy_bundle",
    "report_runtime_event",
    "CompiledPolicy",
]

__version__ = "0.1.0"
