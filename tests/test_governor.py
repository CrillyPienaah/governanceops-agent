import pytest

from governanceops_agent.autonomy import AutonomyLevel
from governanceops_agent.governor import AgentGovernor
from governanceops_agent.kill_switch import KillSwitchEngagedError
from governanceops_agent.permissions import ToolScope
from governanceops_agent.policy import PolicyEngine, block_rule, threshold_rule_pair


def test_kill_switch_blocks_evaluate_action_entirely():
    gov = AgentGovernor(secret_key="test-secret")
    gov.kill_switch.engage(engaged_by="ops", reason="incident")
    with pytest.raises(KillSwitchEngagedError):
        gov.evaluate_action("any_action", confidence=0.99, autonomy_level=AutonomyLevel.L4_FULL_AUTONOMY)


def test_policy_block_result_has_no_checkpoint():
    engine = PolicyEngine([block_rule("no_wires", action_prefix="wire_transfer", reason="never allowed")])
    gov = AgentGovernor(secret_key="test-secret", policy_engine=engine)
    outcome = gov.evaluate_action("wire_transfer_5000", confidence=0.99, autonomy_level=AutonomyLevel.L4_FULL_AUTONOMY)
    assert outcome.allowed is False
    assert outcome.checkpoint is None
    assert outcome.denial_reason == "never allowed"


def test_require_approval_creates_a_real_queryable_checkpoint():
    allow_rule, approval_rule = threshold_rule_pair("email", min_confidence=0.9, action_prefix="send_email")
    gov = AgentGovernor(secret_key="test-secret", policy_engine=PolicyEngine([allow_rule, approval_rule]))
    outcome = gov.evaluate_action("send_email_x", confidence=0.5, autonomy_level=AutonomyLevel.L2_HUMAN_ON_LOOP)
    assert outcome.allowed is False
    assert outcome.checkpoint is not None
    assert outcome.checkpoint.status.value == "pending"
    retrieved = gov.checkpoints.get(outcome.checkpoint.checkpoint_id)
    assert retrieved.action == "send_email_x"


def test_policy_allow_with_no_tool_name_is_simply_allowed():
    allow_rule, approval_rule = threshold_rule_pair("email", min_confidence=0.9, action_prefix="send_email")
    gov = AgentGovernor(secret_key="test-secret", policy_engine=PolicyEngine([allow_rule, approval_rule]))
    outcome = gov.evaluate_action("send_email_x", confidence=0.95, autonomy_level=AutonomyLevel.L2_HUMAN_ON_LOOP)
    assert outcome.allowed is True


def test_tool_level_constraint_overrides_a_policy_allow():
    """The key integration case: policy ALLOWs the action conceptually,
    but the specific tool's own scope still has the final say."""
    allow_rule, approval_rule = threshold_rule_pair("transfer", min_confidence=0.5, action_prefix="transfer_funds")
    gov = AgentGovernor(secret_key="test-secret", policy_engine=PolicyEngine([allow_rule, approval_rule]))
    gov.permissions.register(
        ToolScope(
            tool_name="transfer_funds_tool",
            constraint=lambda params: params.get("amount", 0) <= 1000,
            constraint_description="the $1,000 cap",
        )
    )
    outcome = gov.evaluate_action(
        "transfer_funds_big",
        confidence=0.9,
        autonomy_level=AutonomyLevel.L3_BOUNDED_AUTONOMY,
        tool_name="transfer_funds_tool",
        tool_params={"amount": 5000},
    )
    assert outcome.allowed is False
    assert outcome.policy_decision.decision.value == "allow"  # policy itself said allow
    assert "1,000" in outcome.denial_reason  # tool-level check is what actually blocked it


def test_full_audit_trail_captures_the_lifecycle_and_verifies_clean():
    allow_rule, approval_rule = threshold_rule_pair("transfer", min_confidence=0.5, action_prefix="transfer_funds")
    gov = AgentGovernor(secret_key="test-secret", policy_engine=PolicyEngine([allow_rule, approval_rule]))
    gov.permissions.register(
        ToolScope(tool_name="transfer_funds_tool", constraint=lambda p: p.get("amount", 0) <= 1000)
    )
    gov.evaluate_action(
        "transfer_funds_big", confidence=0.9, autonomy_level=AutonomyLevel.L3_BOUNDED_AUTONOMY,
        tool_name="transfer_funds_tool", tool_params={"amount": 5000},
    )
    event_types = [e.event_type for e in gov.audit_log.entries]
    assert "policy_decision" in event_types
    assert "tool_call_denied" in event_types
    assert gov.audit_log.verify().is_valid is True
