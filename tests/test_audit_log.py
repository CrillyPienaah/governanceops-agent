import hashlib
import json

import pytest

from governanceops_agent.audit_log import AuditLog, GENESIS_HASH


def _recompute_hash(seq, ts, event_type, payload, prev_hash):
    content = json.dumps(
        {"sequence": seq, "timestamp": ts, "event_type": event_type, "payload": payload, "previous_hash": prev_hash},
        sort_keys=True, default=str, separators=(",", ":"),
    )
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def test_empty_log_verifies_as_valid():
    log = AuditLog(secret_key="test-secret")
    result = log.verify()
    assert result.is_valid is True
    assert result.entries_checked == 0


def test_chain_builds_correctly_and_verifies():
    log = AuditLog(secret_key="test-secret")
    e1 = log.append("agent_action", {"tool": "send_email", "confidence": 0.9})
    e2 = log.append("agent_action", {"tool": "delete_file", "confidence": 0.4})
    assert e1.previous_hash == GENESIS_HASH
    assert e2.previous_hash == e1.entry_hash
    assert e1.sequence == 0 and e2.sequence == 1
    assert log.verify().is_valid is True


def test_tampering_with_a_past_entrys_payload_is_detected():
    log = AuditLog(secret_key="test-secret")
    log.append("agent_action", {"confidence": 0.4})
    tampered = log.export_entries()
    tampered[0]["payload"]["confidence"] = 0.99
    tampered_log = AuditLog.from_entries(secret_key="test-secret", raw_entries=tampered)
    result = tampered_log.verify()
    assert result.is_valid is False
    assert result.first_invalid_sequence == 0


def test_recomputing_the_hash_correctly_still_fails_without_the_secret():
    """The real security property: an attacker who edits an entry AND
    correctly recomputes its hash (SHA-256 needs no secret) still can't
    produce a valid signature without knowing secret_key."""
    log = AuditLog(secret_key="test-secret")
    log.append("agent_action", {"confidence": 0.4})
    tampered = log.export_entries()
    tampered[0]["payload"]["confidence"] = 0.99
    tampered[0]["entry_hash"] = _recompute_hash(
        0, tampered[0]["timestamp"], "agent_action", tampered[0]["payload"], GENESIS_HASH
    )
    # signature left as the OLD (now-mismatched) value — attacker has no way to produce a new valid one
    tampered_log = AuditLog.from_entries(secret_key="test-secret", raw_entries=tampered)
    result = tampered_log.verify()
    assert result.is_valid is False
    assert "signature" in result.reason


def test_wrong_secret_key_fails_verification_of_an_otherwise_untouched_log():
    log = AuditLog(secret_key="real-secret")
    log.append("test", {"x": 1})
    wrong_key_log = AuditLog.from_entries(secret_key="wrong-secret", raw_entries=log.export_entries())
    assert wrong_key_log.verify().is_valid is False


def test_empty_secret_key_rejected_outright():
    with pytest.raises(ValueError):
        AuditLog(secret_key="")


def test_reordering_entries_is_detected():
    log = AuditLog(secret_key="test-secret")
    log.append("a", {"i": 1})
    log.append("b", {"i": 2})
    log.append("c", {"i": 3})
    raw = log.export_entries()
    raw[1], raw[2] = raw[2], raw[1]
    reordered_log = AuditLog.from_entries(secret_key="test-secret", raw_entries=raw)
    assert reordered_log.verify().is_valid is False
