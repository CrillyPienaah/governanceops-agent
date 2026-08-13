import time

import pytest

from governanceops_agent.audit_log import AuditLog
from governanceops_agent.hitl import CheckpointError, CheckpointStatus, CheckpointStore


def test_basic_create_and_approve():
    store = CheckpointStore()
    cp = store.create("wire_transfer_5000", "Confidence below threshold.")
    assert cp.status == CheckpointStatus.PENDING
    approved = store.approve(cp.checkpoint_id, approver="jane.doe", notes="Verified by phone.")
    assert approved.status == CheckpointStatus.APPROVED
    assert approved.resolved_by == "jane.doe"


def test_reject():
    store = CheckpointStore()
    cp = store.create("delete_records", "High-risk action.")
    rejected = store.reject(cp.checkpoint_id, approver="john.smith", notes="Not authorized.")
    assert rejected.status == CheckpointStatus.REJECTED


def test_double_resolution_is_blocked():
    store = CheckpointStore()
    cp = store.create("action", "reason")
    store.approve(cp.checkpoint_id, approver="alice")
    with pytest.raises(CheckpointError):
        store.approve(cp.checkpoint_id, approver="bob")


def test_looking_up_a_nonexistent_checkpoint_raises():
    store = CheckpointStore()
    with pytest.raises(CheckpointError):
        store.get("nonexistent-id")


def test_expiry_defaults_to_expired_never_approved():
    """The critical safety property — see the module docstring on why
    an unattended checkpoint must not silently become an approval."""
    store = CheckpointStore()
    cp = store.create("risky_action", "needs review", ttl_seconds=0.1)
    assert store.is_expired(cp) is False
    time.sleep(0.15)
    assert store.is_expired(cp) is True
    swept = store.sweep_expired()
    assert len(swept) == 1
    assert swept[0].status == CheckpointStatus.EXPIRED
    assert swept[0].status != CheckpointStatus.APPROVED


def test_sweep_does_not_touch_already_resolved_checkpoints():
    store = CheckpointStore()
    cp = store.create("action", "reason", ttl_seconds=0.05)
    store.approve(cp.checkpoint_id, approver="someone")
    time.sleep(0.1)
    swept = store.sweep_expired()
    assert len(swept) == 0
    assert store.get(cp.checkpoint_id).status == CheckpointStatus.APPROVED


def test_audit_log_captures_every_lifecycle_event():
    log = AuditLog(secret_key="test-secret")
    store = CheckpointStore(audit_log=log)
    cp = store.create("test_action", "test reason")
    store.approve(cp.checkpoint_id, approver="approver1")
    event_types = [e.event_type for e in log.entries]
    assert event_types == ["hitl_checkpoint_created", "hitl_checkpoint_approved"]
    assert log.verify().is_valid is True
