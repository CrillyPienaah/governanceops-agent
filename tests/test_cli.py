"""
Tests for the governanceops-gate CLI, via subprocess against the real
installed entry point behavior (python -m governanceops_agent.cli) —
exit codes are the actual contract a CI pipeline depends on, so they're
tested by actually invoking the command, not just calling main()
in-process and inspecting a return value.
"""

import json
import subprocess
import sys


def _write_config(tmp_path, **overrides):
    config = {
        "ai_system_id": "AI-CLI-TEST",
        "ai_system_name": "CLI Test Agent",
        "policy_rules": [
            {"type": "threshold", "name": "t", "min_confidence": 0.9, "action_prefix": "act"}
        ],
        "scenarios": [
            {"name": "confident action allowed", "action": "act_x", "confidence": 0.95, "expect": "allowed"}
        ],
    }
    config.update(overrides)
    path = tmp_path / "config.json"
    path.write_text(json.dumps(config))
    return path


def _run_cli(*args):
    return subprocess.run(
        [sys.executable, "-m", "governanceops_agent.cli", *args],
        capture_output=True,
        text=True,
    )


def test_cli_exits_zero_on_all_passing_scenarios(tmp_path):
    config_path = _write_config(tmp_path)
    result = _run_cli("run", str(config_path))
    assert result.returncode == 0
    assert "DEPLOYMENT APPROVED" in result.stdout


def test_cli_exits_one_on_a_failing_scenario(tmp_path):
    config_path = _write_config(
        tmp_path,
        scenarios=[
            {"name": "wrongly expects blocked", "action": "act_x", "confidence": 0.95, "expect": "blocked"}
        ],
    )
    result = _run_cli("run", str(config_path))
    assert result.returncode == 1
    assert "DEPLOYMENT BLOCKED" in result.stdout


def test_cli_exits_two_on_missing_config_file():
    result = _run_cli("run", "/nonexistent/config.json")
    assert result.returncode == 2
    assert "not found" in result.stderr


def test_cli_quiet_flag_suppresses_per_scenario_detail(tmp_path):
    config_path = _write_config(tmp_path)
    result = _run_cli("run", str(config_path), "--quiet")
    assert result.returncode == 0
    assert "confident action allowed" not in result.stdout
    assert "AI ASSURANCE SCORE" in result.stdout
