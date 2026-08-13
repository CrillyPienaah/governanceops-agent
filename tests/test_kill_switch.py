import threading

from governanceops_agent.audit_log import AuditLog
from governanceops_agent.kill_switch import KillSwitch, KillSwitchEngagedError

import pytest


def test_not_engaged_initially():
    ks = KillSwitch()
    ks.check()  # should not raise
    assert ks.state.is_engaged is False


def test_engage_blocks_check():
    ks = KillSwitch()
    ks.engage(engaged_by="ops-oncall", reason="Agent made repeated unauthorized transfers.")
    with pytest.raises(KillSwitchEngagedError, match="ops-oncall"):
        ks.check()
    assert ks.state.is_engaged is True
    assert ks.state.engaged_by == "ops-oncall"


def test_clear_restores_normal_operation():
    ks = KillSwitch()
    ks.engage(engaged_by="ops", reason="incident")
    ks.clear(cleared_by="ops-lead", notes="Root cause fixed.")
    ks.check()  # should not raise
    assert ks.state.is_engaged is False


def test_audit_log_captures_full_lifecycle_with_context():
    log = AuditLog(secret_key="test-secret")
    ks = KillSwitch(audit_log=log)
    ks.engage(engaged_by="alice", reason="test reason")
    ks.clear(cleared_by="bob", notes="resolved")
    entries = log.entries
    assert [e.event_type for e in entries] == ["kill_switch_engaged", "kill_switch_cleared"]
    assert entries[0].payload["engaged_by"] == "alice"
    assert entries[1].payload["cleared_by"] == "bob"
    assert entries[1].payload["original_engaged_by"] == "alice"
    assert log.verify().is_valid is True


def test_thread_safety_under_concurrent_access():
    ks = KillSwitch()
    errors = []

    def worker(should_engage):
        try:
            if should_engage:
                ks.engage(engaged_by="worker", reason="concurrent test")
            else:
                try:
                    ks.check()
                except KillSwitchEngagedError:
                    pass
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(i == 0,)) for i in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
