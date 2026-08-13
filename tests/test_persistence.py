import json
import os

import pytest

from governanceops_agent.autonomy import AutonomyLevel
from governanceops_agent.governor import AgentGovernor
from governanceops_agent.persistence import PersistentAuditLog, load_persistent_audit_log
from governanceops_agent.policy import PolicyEngine, threshold_rule_pair


@pytest.fixture
def log_path(tmp_path):
    return tmp_path / "audit.jsonl"


def test_append_writes_real_jsonl_lines(log_path):
    log = PersistentAuditLog(secret_key="test-secret", path=log_path)
    log.append("event_a", {"x": 1})
    log.append("event_b", {"y": 2})
    lines = log_path.read_text().splitlines()
    assert len(lines) == 2
    parsed = json.loads(lines[0])
    assert parsed["event_type"] == "event_a"
    assert parsed["sequence"] == 0


def test_in_memory_chain_still_verifies(log_path):
    log = PersistentAuditLog(secret_key="test-secret", path=log_path)
    log.append("event_a", {"x": 1})
    assert log.verify().is_valid is True


def test_reload_after_simulated_process_restart(log_path):
    log = PersistentAuditLog(secret_key="test-secret", path=log_path)
    log.append("event_a", {"x": 1})
    log.append("event_b", {"y": 2})

    reloaded = load_persistent_audit_log(secret_key="test-secret", path=log_path)
    assert len(reloaded.entries) == 2
    assert reloaded.entries[0].event_type == "event_a"
    assert reloaded.verify().is_valid is True


def test_appending_after_reload_continues_the_same_chain(log_path):
    log = PersistentAuditLog(secret_key="test-secret", path=log_path)
    log.append("event_a", {"x": 1})
    e2 = log.append("event_b", {"y": 2})

    reloaded = load_persistent_audit_log(secret_key="test-secret", path=log_path)
    e3 = reloaded.append("event_c", {"z": 3})
    assert e3.previous_hash == e2.entry_hash
    assert reloaded.verify().is_valid is True
    assert len(log_path.read_text().splitlines()) == 3


def test_wrong_secret_key_fails_even_for_a_persisted_log(log_path):
    log = PersistentAuditLog(secret_key="test-secret", path=log_path)
    log.append("event_a", {"x": 1})
    wrong_key_log = load_persistent_audit_log(secret_key="wrong-secret", path=log_path)
    assert wrong_key_log.verify().is_valid is False


def test_tampering_the_file_directly_is_detected_on_reload(log_path):
    log = PersistentAuditLog(secret_key="test-secret", path=log_path)
    log.append("event_a", {"x": 1})

    lines = log_path.read_text().splitlines()
    tampered = json.loads(lines[0])
    tampered["payload"]["x"] = 999
    log_path.write_text(json.dumps(tampered) + "\n")

    tampered_reload = load_persistent_audit_log(secret_key="test-secret", path=log_path)
    assert tampered_reload.verify().is_valid is False


def test_loading_a_nonexistent_file_starts_fresh_without_crashing(tmp_path):
    fresh_path = tmp_path / "does_not_exist_yet.jsonl"
    fresh_log = load_persistent_audit_log(secret_key="test-secret", path=fresh_path)
    assert len(fresh_log.entries) == 0
    assert fresh_log.verify().is_valid is True
    fresh_log.append("first_event", {"a": 1})
    assert fresh_path.exists()


def test_agent_governor_accepts_an_injected_persistent_audit_log(log_path):
    persistent_log = PersistentAuditLog(secret_key="gov-secret", path=log_path)
    allow_rule, approval_rule = threshold_rule_pair("test", min_confidence=0.5, action_prefix="test_action")
    governor = AgentGovernor(policy_engine=PolicyEngine([allow_rule, approval_rule]), audit_log=persistent_log)
    governor.evaluate_action("test_action_1", confidence=0.9, autonomy_level=AutonomyLevel.L2_HUMAN_ON_LOOP)
    assert log_path.exists()
    assert len(log_path.read_text().splitlines()) >= 1
    assert governor.audit_log.verify().is_valid is True


def test_governor_requires_either_secret_key_or_audit_log():
    with pytest.raises(ValueError):
        AgentGovernor()
