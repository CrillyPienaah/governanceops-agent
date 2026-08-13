import pytest

from governanceops_agent.audit_log import AuditLog
from governanceops_agent.autonomy import AutonomyLevel
from governanceops_agent.permissions import PermissionDeniedError, ToolPermissionRegistry, ToolScope


def test_unregistered_tool_denied_by_default():
    registry = ToolPermissionRegistry()
    with pytest.raises(PermissionDeniedError, match="no registered scope"):
        registry.check_and_record("unregistered_tool", AutonomyLevel.L4_FULL_AUTONOMY, {})


def test_registered_unconstrained_tool_is_allowed():
    registry = ToolPermissionRegistry()
    registry.register(ToolScope(tool_name="read_file"))
    registry.check_and_record("read_file", AutonomyLevel.L0_NO_AUTONOMY, {})  # should not raise


def test_minimum_autonomy_gating():
    registry = ToolPermissionRegistry()
    registry.register(ToolScope(tool_name="delete_file", minimum_autonomy=AutonomyLevel.L3_BOUNDED_AUTONOMY))
    with pytest.raises(PermissionDeniedError):
        registry.check_and_record("delete_file", AutonomyLevel.L1_HUMAN_IN_LOOP, {})
    registry.check_and_record("delete_file", AutonomyLevel.L3_BOUNDED_AUTONOMY, {})  # should not raise


def test_per_call_constraint_dollar_cap():
    registry = ToolPermissionRegistry()
    registry.register(
        ToolScope(
            tool_name="transfer_funds",
            constraint=lambda params: params.get("amount", 0) <= 5000,
            constraint_description="the $5,000 transfer cap",
        )
    )
    registry.check_and_record("transfer_funds", AutonomyLevel.L0_NO_AUTONOMY, {"amount": 3000})
    with pytest.raises(PermissionDeniedError, match="5,000"):
        registry.check_and_record("transfer_funds", AutonomyLevel.L0_NO_AUTONOMY, {"amount": 10000})


def test_max_calls_per_session_cap():
    registry = ToolPermissionRegistry()
    registry.register(ToolScope(tool_name="send_email", max_calls_per_session=2))
    registry.check_and_record("send_email", AutonomyLevel.L0_NO_AUTONOMY, {})
    registry.check_and_record("send_email", AutonomyLevel.L0_NO_AUTONOMY, {})
    with pytest.raises(PermissionDeniedError, match="session call cap"):
        registry.check_and_record("send_email", AutonomyLevel.L0_NO_AUTONOMY, {})


def test_reset_session_clears_call_counts():
    registry = ToolPermissionRegistry()
    registry.register(ToolScope(tool_name="send_email", max_calls_per_session=1))
    registry.check_and_record("send_email", AutonomyLevel.L0_NO_AUTONOMY, {})
    registry.reset_session()
    registry.check_and_record("send_email", AutonomyLevel.L0_NO_AUTONOMY, {})  # should not raise


def test_audit_log_captures_both_allow_and_deny():
    log = AuditLog(secret_key="test-secret")
    registry = ToolPermissionRegistry(audit_log=log)
    registry.register(ToolScope(tool_name="allowed_tool"))
    registry.check_and_record("allowed_tool", AutonomyLevel.L0_NO_AUTONOMY, {})
    with pytest.raises(PermissionDeniedError):
        registry.check_and_record("denied_tool", AutonomyLevel.L0_NO_AUTONOMY, {})
    event_types = [e.event_type for e in log.entries]
    assert event_types == ["tool_call_allowed", "tool_call_denied"]
    assert log.verify().is_valid is True
