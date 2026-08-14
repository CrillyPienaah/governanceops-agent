import json

import pytest

from governanceops_agent.gate import GateConfigError, load_gate_config, run_gate


def _base_config(**overrides):
    config = {
        "ai_system_id": "AI-TEST-001",
        "ai_system_name": "Test Agent",
        "policy_rules": [
            {
                "type": "threshold",
                "name": "invoice_match",
                "min_confidence": 0.90,
                "minimum_autonomy": "L3_BOUNDED_AUTONOMY",
                "action_prefix": "approve_invoice",
            }
        ],
        "tool_scopes": [
            {
                "tool_name": "auto_approve",
                "minimum_autonomy": "L3_BOUNDED_AUTONOMY",
                "constraint": {"kind": "max_param", "param": "amount", "max": 5000},
            }
        ],
        "scenarios": [],
    }
    config.update(overrides)
    return config


def test_all_scenarios_passing_produces_approved_verdict():
    config = _base_config(
        scenarios=[
            {
                "name": "confident match under cap",
                "action": "approve_invoice",
                "confidence": 0.97,
                "autonomy_level": "L3_BOUNDED_AUTONOMY",
                "tool_name": "auto_approve",
                "tool_params": {"amount": 3000},
                "expect": "allowed",
            }
        ]
    )
    report = run_gate(config)
    assert report.all_passed is True
    assert report.passed_count == 1
    assert report.score == 100.0


def test_a_failing_scenario_produces_blocked_verdict():
    """The core value proposition: a scenario whose actual outcome
    doesn't match its declared expectation is a real governance gap,
    and the gate must report it as such."""
    config = _base_config(
        tool_scopes=[{"tool_name": "auto_approve", "minimum_autonomy": "L3_BOUNDED_AUTONOMY"}],  # no cap!
        scenarios=[
            {
                "name": "should have been blocked by a cap that was never configured",
                "action": "approve_invoice",
                "confidence": 0.99,
                "autonomy_level": "L3_BOUNDED_AUTONOMY",
                "tool_name": "auto_approve",
                "tool_params": {"amount": 500000},
                "expect": "blocked",
            }
        ],
    )
    report = run_gate(config)
    assert report.all_passed is False
    assert report.passed_count == 0
    result = report.results[0]
    assert result.expected == "blocked"
    assert result.actual == "allowed"


def test_requires_approval_scenario():
    config = _base_config(
        scenarios=[
            {
                "name": "low confidence needs a human",
                "action": "approve_invoice",
                "confidence": 0.5,
                "autonomy_level": "L3_BOUNDED_AUTONOMY",
                "expect": "requires_approval",
            }
        ]
    )
    report = run_gate(config)
    assert report.all_passed is True


def test_mixed_pass_and_fail_scenarios_compute_correct_score():
    config = _base_config(
        scenarios=[
            {"name": "a", "action": "approve_invoice", "confidence": 0.95, "autonomy_level": "L3_BOUNDED_AUTONOMY",
             "tool_name": "auto_approve", "tool_params": {"amount": 100}, "expect": "allowed"},
            {"name": "b", "action": "approve_invoice", "confidence": 0.95, "autonomy_level": "L3_BOUNDED_AUTONOMY",
             "tool_name": "auto_approve", "tool_params": {"amount": 100}, "expect": "blocked"},  # wrong on purpose
        ]
    )
    report = run_gate(config)
    assert report.passed_count == 1
    assert report.total_count == 2
    assert report.score == 50.0
    assert report.all_passed is False


def test_block_rule_type_in_config():
    config = _base_config(
        policy_rules=[
            {"type": "block", "name": "no_closure", "action_prefix": "close_account", "reason": "never allowed"}
        ],
        scenarios=[
            {"name": "account closure always blocked", "action": "close_account_x", "confidence": 0.99,
             "autonomy_level": "L4_FULL_AUTONOMY", "expect": "blocked"}
        ],
    )
    report = run_gate(config)
    assert report.all_passed is True


def test_unknown_autonomy_level_raises_gate_config_error():
    config = _base_config(
        scenarios=[{"name": "x", "action": "y", "autonomy_level": "L99_MADE_UP", "expect": "allowed"}]
    )
    with pytest.raises(GateConfigError, match="Unknown autonomy level"):
        run_gate(config)


def test_unknown_policy_rule_type_raises_gate_config_error():
    config = _base_config(policy_rules=[{"type": "not_a_real_type", "name": "x"}])
    with pytest.raises(GateConfigError, match="Unknown policy rule type"):
        run_gate(config)


def test_unknown_constraint_kind_raises_gate_config_error():
    config = _base_config(
        tool_scopes=[{"tool_name": "x", "constraint": {"kind": "not_a_real_kind"}}]
    )
    with pytest.raises(GateConfigError, match="Unknown constraint kind"):
        run_gate(config)


def test_invalid_expect_value_raises_gate_config_error():
    config = _base_config(
        scenarios=[{"name": "x", "action": "y", "expect": "maybe"}]
    )
    with pytest.raises(GateConfigError, match="invalid expect"):
        run_gate(config)


def test_load_gate_config_missing_file_raises():
    with pytest.raises(GateConfigError, match="not found"):
        load_gate_config("/nonexistent/path/config.json")


def test_load_gate_config_invalid_json_raises(tmp_path):
    bad_file = tmp_path / "bad.json"
    bad_file.write_text("{not valid json")
    with pytest.raises(GateConfigError, match="not valid JSON"):
        load_gate_config(bad_file)


def test_load_gate_config_valid_file(tmp_path):
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps(_base_config()))
    loaded = load_gate_config(config_file)
    assert loaded["ai_system_id"] == "AI-TEST-001"


def test_report_render_includes_verdict_and_score():
    config = _base_config(
        scenarios=[
            {"name": "a", "action": "approve_invoice", "confidence": 0.95, "autonomy_level": "L3_BOUNDED_AUTONOMY",
             "tool_name": "auto_approve", "tool_params": {"amount": 100}, "expect": "allowed"},
        ]
    )
    report = run_gate(config)
    rendered = report.render()
    assert "DEPLOYMENT APPROVED" in rendered
    assert "1/1" in rendered
    assert "100.0%" in rendered
