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
"""

from governanceops_agent.audit_log import AuditEntry, AuditLog, VerificationResult
from governanceops_agent.autonomy import AutonomyLevel, AutonomyProfile, at_least, profile_for
from governanceops_agent.governor import ActionOutcome, AgentGovernor
from governanceops_agent.hitl import Checkpoint, CheckpointError, CheckpointStatus, CheckpointStore
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
]

__version__ = "0.1.0"
