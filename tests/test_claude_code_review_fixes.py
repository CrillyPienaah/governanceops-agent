"""
Regression tests for a second Claude Code review pass against this
repo. Each test is named after the specific bug it was written to
catch, matching the pattern already used in
governanceops-inventory/backend/tests/test_api_models.py for its own
review-pass fixes.
"""

import threading
import time
from decimal import Decimal

import pytest

from governanceops_agent.audit_log import AuditLog
from governanceops_agent.autonomy import AutonomyLevel
from governanceops_agent.governor import AgentGovernor
from governanceops_agent.hitl import CheckpointStore
from governanceops_agent.inventory_client import (
    InventoryClientError,
    _under_transaction_limit,
    report_runtime_event,
)
from governanceops_agent.permissions import ToolPermissionRegistry, ToolScope


# =========================================================
# Fix #1: ToolPermissionRegistry had no lock -- the session
# call cap lost increments under concurrency.
# =========================================================


def test_session_call_cap_is_exact_under_concurrency():
    registry = ToolPermissionRegistry()
    registry.register(ToolScope(tool_name="send_email", max_calls_per_session=50))

    allowed = 0
    denied = 0
    lock = threading.Lock()

    def worker():
        nonlocal allowed, denied
        try:
            registry.check_and_record("send_email", AutonomyLevel.L4_FULL_AUTONOMY)
            with lock:
                allowed += 1
        except Exception:
            with lock:
                denied += 1

    threads = [threading.Thread(target=worker) for _ in range(200)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert allowed == 50, f"expected exactly 50 allowed calls, got {allowed}"
    assert denied == 150


# =========================================================
# Fix #2: PersistentAuditLog wrote to disk outside its lock --
# concurrent appends could serialize in-memory in one order and
# hit the file in another.
# =========================================================


def test_concurrent_persistent_appends_produce_a_file_that_verifies(tmp_path):
    from governanceops_agent.persistence import PersistentAuditLog

    path = tmp_path / "audit.jsonl"
    log = PersistentAuditLog(secret_key="test-secret", path=path)

    def worker(n):
        for i in range(20):
            log.append("test_event", {"worker": n, "i": i})

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert log.verify().is_valid is True

    from governanceops_agent.persistence import load_persistent_audit_log

    reloaded = load_persistent_audit_log(secret_key="test-secret", path=path)
    result = reloaded.verify()
    assert result.is_valid is True, result.reason
    assert len(reloaded.entries) == 160


# =========================================================
# Fix #7: AuditLog stored the caller's payload dict by reference --
# mutating it after logging corrupted an otherwise-untampered entry.
# =========================================================


def test_mutating_the_original_payload_after_append_does_not_affect_the_log():
    log = AuditLog(secret_key="test-secret")
    payload = {"amount": 100}
    log.append("test_event", payload)

    payload["amount"] = 999999  # mutate the caller's own dict after logging

    assert log.entries[0].payload["amount"] == 100
    assert log.verify().is_valid is True


def test_mutating_a_payload_read_from_entries_does_not_affect_the_log():
    log = AuditLog(secret_key="test-secret")
    log.append("test_event", {"amount": 100})

    entries = log.entries
    entries[0].payload["amount"] = 999999  # mutate the returned copy

    assert log.entries[0].payload["amount"] == 100
    assert log.verify().is_valid is True


# =========================================================
# The CheckpointStore._resolve race: concurrent approve()/reject()
# on the same checkpoint could both pass the is_resolved guard.
# =========================================================


def test_only_one_concurrent_resolution_of_the_same_checkpoint_succeeds():
    store = CheckpointStore()
    checkpoint = store.create(action="wire_transfer", reason="test")

    succeeded = []
    failed = []
    lock = threading.Lock()

    def worker(n):
        try:
            store.approve(checkpoint.checkpoint_id, approver=f"user-{n}")
            with lock:
                succeeded.append(n)
        except Exception:
            with lock:
                failed.append(n)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(succeeded) == 1, f"expected exactly one resolution to succeed, got {len(succeeded)}"
    assert len(failed) == 49


# =========================================================
# Fix #8: sweep_expired() iterated the checkpoint dict unguarded --
# a concurrent create() could raise "dictionary changed size during
# iteration".
# =========================================================


def test_sweep_expired_does_not_crash_under_concurrent_create():
    store = CheckpointStore()
    stop = threading.Event()
    errors = []

    def creator():
        while not stop.is_set():
            store.create(action="some_action", reason="test", ttl_seconds=0.001)

    def sweeper():
        for _ in range(200):
            try:
                store.sweep_expired()
            except Exception as exc:
                errors.append(exc)
            time.sleep(0.001)

    creator_thread = threading.Thread(target=creator)
    sweeper_thread = threading.Thread(target=sweeper)
    creator_thread.start()
    sweeper_thread.start()
    sweeper_thread.join()
    stop.set()
    creator_thread.join()

    assert errors == [], f"sweep_expired raised under concurrency: {errors}"


# =========================================================
# Fix #4: report_runtime_event's json.dumps had no default=str --
# a Decimal/datetime/UUID in raw_payload raised a bare TypeError.
# =========================================================


def test_report_runtime_event_serializes_a_decimal_payload(monkeypatch):
    captured = {}

    class _FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b'{"event_id": "fake-id"}'

    def fake_urlopen(request, timeout=15):
        captured["body"] = request.data
        return _FakeResponse()

    import governanceops_agent.inventory_client as ic_module

    monkeypatch.setattr(ic_module.urllib.request, "urlopen", fake_urlopen)

    event = {
        "occurred_at": "2026-08-14T00:00:00",
        "event_type": "tool_call_allowed",
        "raw_payload": {"amount": Decimal("1000.50")},
    }
    result = report_runtime_event("https://example.test/api/v1", "record-1", event)
    assert result == {"event_id": "fake-id"}
    assert b"1000.50" in captured["body"]


# =========================================================
# Fix #5: the transaction-limit constraint defaulted a missing
# "amount" key to 0, which passed the cap unconditionally for any
# tool whose amount param used a different name.
# =========================================================


def test_transaction_limit_recognizes_common_alternate_param_names():
    assert _under_transaction_limit({"value": 400}, limit=500) is True
    assert _under_transaction_limit({"total": 600}, limit=500) is False


def test_transaction_limit_fails_closed_when_no_recognized_param_is_present():
    """The real bug: previously `params.get("amount", 0) <= limit` let
    a call through unconditionally if the tool's amount-like param
    wasn't literally named "amount". Failing closed (denying) when
    none of the recognized keys are present is the safe default,
    matching this library's "unmatched -> don't silently allow"
    philosophy everywhere else."""
    assert _under_transaction_limit({"amount_cents": 999999999}, limit=500) is False


# =========================================================
# Fix #6: the autonomy tier from Inventory was a floor, never a
# ceiling -- a caller-supplied autonomy_level higher than what was
# actually approved made policy/tool rules match MORE readily, with
# nothing comparing the claimed tier against the approved one.
# =========================================================


def _bundle_approved_at_l2():
    return {
        "ai_system_id": "MDL-CEILING-TEST",
        "ai_system_name": "Ceiling Test Agent",
        "risk_rating": "high",
        "autonomy_level": "l2_human_on_loop",
        "permitted_tools": ["send_email"],
        "forbidden_tools": [],
        "confidence_threshold": 0.5,
        "policy_version": 1,
        "policy_hash": "abc123",
    }


def test_a_caller_supplied_autonomy_tier_above_the_approved_ceiling_is_capped(monkeypatch):
    import governanceops_agent.governor as governor_module

    original = governor_module.fetch_policy_bundle
    governor_module.fetch_policy_bundle = lambda *a, **k: _bundle_approved_at_l2()
    try:
        governor = AgentGovernor.from_governanceops(
            ai_system_record_id="MDL-CEILING-TEST",
            inventory_base_url="https://example.test/api/v1",
            secret_key="test-secret",
        )
        # Approved at L2; the tool's rule requires >= L2 with
        # confidence >= 0.5, so evaluated at the TRUE ceiling this
        # should ALLOW -- but claiming a tier the bundle never granted
        # must not itself be what makes the difference.
        outcome_at_ceiling = governor.evaluate_action(
            "send_email_x", confidence=0.6, autonomy_level=AutonomyLevel.L2_HUMAN_ON_LOOP,
            tool_name="send_email", tool_params={},
        )
        assert outcome_at_ceiling.allowed is True

        entry = governor.audit_log.entries[-1]
        assert entry.payload["autonomy_level"] == "L2_HUMAN_ON_LOOP"
        assert "claimed_autonomy_level" not in entry.payload
    finally:
        governor_module.fetch_policy_bundle = original


def test_claiming_a_higher_tier_than_approved_is_recorded_but_evaluated_at_the_ceiling(monkeypatch):
    """The actual regression test for the finding: a bundle approved at
    L2 should not let a caller who simply claims L4 be evaluated as if
    Inventory had approved L4. This constructs a scenario where the
    ceiling matters: a rule that only allows send_email at L3+, on a
    bundle approved at L2 -- claiming L4 must still be capped to L2 and
    therefore NOT match that L3+ rule."""
    import governanceops_agent.governor as governor_module
    from governanceops_agent.policy import block_rule

    bundle = _bundle_approved_at_l2()
    original = governor_module.fetch_policy_bundle
    governor_module.fetch_policy_bundle = lambda *a, **k: bundle
    try:
        governor = AgentGovernor.from_governanceops(
            ai_system_record_id="MDL-CEILING-TEST",
            inventory_base_url="https://example.test/api/v1",
            secret_key="test-secret",
        )
        # Add a rule that ONLY allows this action at L3+ -- something
        # the L2-approved bundle's own compiled rules wouldn't produce,
        # added here specifically to prove the ceiling is enforced
        # independently of what rules happen to already be compiled.
        from governanceops_agent.policy import PolicyRule, Decision
        from governanceops_agent.autonomy import at_least

        governor.policy_engine.add_rule(
            PolicyRule(
                name="l3_plus_only",
                condition=lambda action, confidence, level: (
                    action == "l3_only_action" and at_least(level, AutonomyLevel.L3_BOUNDED_AUTONOMY)
                ),
                decision=Decision.ALLOW,
                reason="Only allowed at L3 or above.",
            )
        )

        # Claiming L4 on a bundle approved at L2 -- if the ceiling
        # weren't enforced, this would match the L3+ rule and be
        # ALLOWED. With the ceiling enforced, it's capped to L2 and
        # falls through to the default REQUIRE_APPROVAL instead.
        outcome = governor.evaluate_action(
            "l3_only_action", confidence=0.99, autonomy_level=AutonomyLevel.L4_FULL_AUTONOMY,
        )
        assert outcome.allowed is False
        assert outcome.policy_decision.decision.value == "require_approval"

        # entries[-1] is the hitl_checkpoint_created entry that
        # evaluate_action also appends for a REQUIRE_APPROVAL decision
        # -- the policy_decision entry itself is the one before it.
        policy_entries = [e for e in governor.audit_log.entries if e.event_type == "policy_decision"]
        entry = policy_entries[-1]
        assert entry.payload["autonomy_level"] == "L2_HUMAN_ON_LOOP"
        assert entry.payload["claimed_autonomy_level"] == "L4_FULL_AUTONOMY"
    finally:
        governor_module.fetch_policy_bundle = original


# =========================================================
# Fix #3: report_event assumed every entry looked like a
# policy_decision -- silently emptying the typed columns for the
# other five event types this library actually produces.
# =========================================================


def test_report_event_maps_tool_call_denied_to_a_block_decision():
    governor = AgentGovernor(secret_key="test-secret")
    governor._ai_system_record_id = "x"
    governor._inventory_base_url = "https://example.test/api/v1"
    governor._inventory_token = None

    governor.audit_log.append("tool_call_denied", {"tool_name": "wire_transfer", "reason": "forbidden"})
    entry = governor.audit_log.entries[-1]
    event = governor._event_dict_from_entry(entry)

    assert event["decision"] == "block"
    assert event["tool_name"] == "wire_transfer"
    assert event["reason"] == "forbidden"


def test_report_event_maps_kill_switch_cleared_reason_from_original_reason():
    governor = AgentGovernor(secret_key="test-secret")
    governor._ai_system_record_id = "x"
    governor._inventory_base_url = "https://example.test/api/v1"
    governor._inventory_token = None

    governor.kill_switch.engage(engaged_by="ops", reason="incident")
    governor.kill_switch.clear(cleared_by="ops", notes="resolved")
    entry = governor.audit_log.entries[-1]
    assert entry.event_type == "kill_switch_cleared"

    event = governor._event_dict_from_entry(entry)
    # Real bug: this used to read entry.payload.get("reason"), which is
    # always None for this event type -- the actual reason lives under
    # "original_reason" (or "notes").
    assert event["reason"] == "resolved"


def test_report_event_maps_hitl_checkpoint_approved_to_an_allow_decision():
    governor = AgentGovernor(secret_key="test-secret")
    governor._ai_system_record_id = "x"
    governor._inventory_base_url = "https://example.test/api/v1"
    governor._inventory_token = None

    checkpoint = governor.checkpoints.create(action="wire_transfer", reason="low confidence")
    governor.checkpoints.approve(checkpoint.checkpoint_id, approver="risk-officer", notes="looks fine")
    entry = governor.audit_log.entries[-1]
    assert entry.event_type == "hitl_checkpoint_approved"

    event = governor._event_dict_from_entry(entry)
    assert event["decision"] == "allow"
    assert event["action"] == "wire_transfer"
    assert event["reason"] == "looks fine"  # from "notes", since this event type has no "reason" key
