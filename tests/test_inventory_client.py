"""
Tests for app.governanceops_agent.inventory_client.build_governance_from_bundle
— the pure mapping logic with no network I/O, tested against hand-built
JSON matching GovernanceOps Inventory's actual documented
RuntimePolicyBundle response shape (see
governanceops-inventory/backend/app/models/schemas.py::RuntimePolicyBundle).

fetch_policy_bundle and report_runtime_event (the actual network calls)
are NOT covered by these unit tests — they're verified via
examples/live_inventory_roundtrip_demo.py against a real deployed
Inventory instance instead (see that file and the README for the
actual live verification this library has been through).
"""

import pytest

from governanceops_agent.autonomy import AutonomyLevel
from governanceops_agent.inventory_client import InventoryClientError, build_governance_from_bundle
from governanceops_agent.governor import AgentGovernor


def _mortgage_bundle(**overrides):
    bundle = {
        "ai_system_id": "MDL-MORTGAGE-001",
        "ai_system_name": "Mortgage Underwriting Agent v4.3",
        "risk_rating": "critical",
        "autonomy_level": "l3_bounded_autonomy",
        "permitted_tools": ["CreditCheck", "CalculateRisk", "ApproveApplication"],
        "forbidden_tools": ["customer_account_close"],
        "confidence_threshold": 0.9,
        "transaction_limit": 750000,
        "policy_version": 3,
        "policy_hash": "abc123def456",
    }
    bundle.update(overrides)
    return bundle


def _build(bundle=None):
    return build_governance_from_bundle(bundle or _mortgage_bundle())


def test_mapping_produces_correct_autonomy_level_and_tool_scopes():
    compiled = _build()
    assert compiled.autonomy_level == AutonomyLevel.L3_BOUNDED_AUTONOMY
    assert {s.tool_name for s in compiled.tool_scopes} == {"CreditCheck", "CalculateRisk", "ApproveApplication"}


def test_mapping_captures_policy_version_and_hash():
    compiled = _build()
    assert compiled.policy_version == 3
    assert compiled.policy_hash == "abc123def456"


def test_mapping_handles_bundle_with_no_version_or_hash():
    bundle = _mortgage_bundle()
    del bundle["policy_version"]
    del bundle["policy_hash"]
    compiled = _build(bundle)
    assert compiled.policy_version is None
    assert compiled.policy_hash is None


def test_permitted_tool_within_confidence_and_limit_is_allowed():
    compiled = _build()
    governor = AgentGovernor(secret_key="test-secret", policy_engine=compiled.engine)
    for scope in compiled.tool_scopes:
        governor.permissions.register(scope)

    outcome = governor.evaluate_action(
        "ApproveApplication_x", confidence=0.95, autonomy_level=AutonomyLevel.L3_BOUNDED_AUTONOMY,
        tool_name="ApproveApplication", tool_params={"amount": 400000},
    )
    assert outcome.allowed is True


def test_permitted_tool_over_transaction_limit_is_blocked():
    compiled = _build()
    governor = AgentGovernor(secret_key="test-secret", policy_engine=compiled.engine)
    for scope in compiled.tool_scopes:
        governor.permissions.register(scope)

    outcome = governor.evaluate_action(
        "ApproveApplication_y", confidence=0.99, autonomy_level=AutonomyLevel.L3_BOUNDED_AUTONOMY,
        tool_name="ApproveApplication", tool_params={"amount": 2000000},
    )
    assert outcome.allowed is False
    assert "750,000" in outcome.denial_reason


def test_forbidden_tool_is_blocked_regardless_of_confidence_or_autonomy():
    compiled = _build()
    governor = AgentGovernor(secret_key="test-secret", policy_engine=compiled.engine)
    for scope in compiled.tool_scopes:
        governor.permissions.register(scope)

    outcome = governor.evaluate_action(
        "customer_account_close_urgent", confidence=0.99, autonomy_level=AutonomyLevel.L4_FULL_AUTONOMY,
    )
    assert outcome.allowed is False
    assert "forbidden" in outcome.denial_reason


def test_low_confidence_on_permitted_tool_requires_approval_not_block_or_allow():
    compiled = _build()
    governor = AgentGovernor(secret_key="test-secret", policy_engine=compiled.engine)
    for scope in compiled.tool_scopes:
        governor.permissions.register(scope)

    outcome = governor.evaluate_action(
        "CreditCheck_z", confidence=0.5, autonomy_level=AutonomyLevel.L3_BOUNDED_AUTONOMY,
        tool_name="CreditCheck", tool_params={},
    )
    assert outcome.allowed is False
    assert outcome.checkpoint is not None


def test_unknown_autonomy_level_string_raises_clear_error():
    with pytest.raises(InventoryClientError, match="l99_made_up"):
        build_governance_from_bundle(_mortgage_bundle(autonomy_level="l99_made_up"))


def test_minimal_bundle_with_explicitly_empty_tools_lists_still_works():
    """The genuinely valid minimal case: permitted_tools/forbidden_tools
    PRESENT but empty is a real, legitimate bundle shape (an approved
    AI system with no tool access at all yet). This is different from
    the keys being ABSENT entirely, which now raises -- see the test
    below."""
    minimal = {
        "ai_system_id": "x", "ai_system_name": "y", "risk_rating": "low",
        "autonomy_level": "l2_human_on_loop",
        "permitted_tools": [], "forbidden_tools": [],
    }
    compiled = _build(minimal)
    assert compiled.tool_scopes == []
    assert compiled.autonomy_level == AutonomyLevel.L2_HUMAN_ON_LOOP
    assert compiled.policy_version is None


def test_bundle_missing_tools_keys_entirely_raises_instead_of_silently_defaulting():
    """Real bug found via a Claude Code review pass: permitted_tools/
    forbidden_tools being ABSENT from the bundle (as opposed to
    present-and-empty) used to silently compile a governor with zero
    rules and zero scopes via a permissive .get(key, []) default --
    indistinguishable from "this AI system is approved for nothing,"
    a very different and much louder thing to actually mean. A missing
    key now means Inventory's response shape doesn't match what this
    library expects, and that should be a loud error, not a silent
    empty policy."""
    incomplete = {
        "ai_system_id": "x", "ai_system_name": "y", "risk_rating": "low",
        "autonomy_level": "l2_human_on_loop",
    }
    with pytest.raises(InventoryClientError, match="permitted_tools"):
        build_governance_from_bundle(incomplete)


def test_rule_ordering_blocks_forbidden_tool_even_if_it_would_otherwise_match_a_permitted_rule():
    """The precedence guarantee: forbidden-tool block rules are added
    BEFORE permitted-tool threshold rules, so a tool name that somehow
    appears in both lists is still blocked, not silently allowed."""
    bundle = _mortgage_bundle(
        permitted_tools=["SharedName"],
        forbidden_tools=["SharedName"],
    )
    compiled = _build(bundle)
    governor = AgentGovernor(secret_key="test-secret", policy_engine=compiled.engine)
    for scope in compiled.tool_scopes:
        governor.permissions.register(scope)

    outcome = governor.evaluate_action(
        "SharedName_action", confidence=0.99, autonomy_level=AutonomyLevel.L4_FULL_AUTONOMY,
        tool_name="SharedName", tool_params={},
    )
    assert outcome.allowed is False


# =========================================================
# AgentGovernor.from_governanceops — the classmethod itself.
# Monkeypatches the module-level fetch_policy_bundle/report_runtime_event
# references governor.py actually holds (not inventory_client's copy —
# governor.py imported its own name binding at import time) to avoid
# needing real network access, while still exercising the real
# end-to-end path: fetch -> map -> build a governor -> evaluate a real
# action against it -> report an event back.
# =========================================================

import governanceops_agent.governor as governor_module


def test_from_governanceops_builds_a_working_governor():
    original = governor_module.fetch_policy_bundle
    governor_module.fetch_policy_bundle = lambda *a, **k: _mortgage_bundle()
    try:
        governor = AgentGovernor.from_governanceops(
            ai_system_record_id="MDL-MORTGAGE-001",
            inventory_base_url="https://example-inventory.test/api/v1",
            secret_key="test-secret",
        )
        outcome = governor.evaluate_action(
            "customer_account_close_urgent", confidence=0.99, autonomy_level=AutonomyLevel.L4_FULL_AUTONOMY,
        )
        assert outcome.allowed is False
        assert "forbidden" in outcome.denial_reason
    finally:
        governor_module.fetch_policy_bundle = original


def test_from_governanceops_raises_when_model_has_no_runtime_policy():
    original = governor_module.fetch_policy_bundle
    governor_module.fetch_policy_bundle = lambda *a, **k: None  # Inventory's documented "no policy configured" response
    try:
        with pytest.raises(InventoryClientError, match="no runtime policy configured"):
            AgentGovernor.from_governanceops(
                ai_system_record_id="MDL-SOME-SCORED-MODEL",
                inventory_base_url="https://example-inventory.test/api/v1",
                secret_key="test-secret",
            )
    finally:
        governor_module.fetch_policy_bundle = original


def test_from_governanceops_captures_policy_version_and_hash_on_the_governor():
    original = governor_module.fetch_policy_bundle
    governor_module.fetch_policy_bundle = lambda *a, **k: _mortgage_bundle()
    try:
        governor = AgentGovernor.from_governanceops(
            ai_system_record_id="MDL-MORTGAGE-001",
            inventory_base_url="https://example-inventory.test/api/v1",
            secret_key="test-secret",
        )
        assert governor.policy_version == 3
        assert governor.policy_hash == "abc123def456"
    finally:
        governor_module.fetch_policy_bundle = original


def test_policy_decision_audit_entries_include_policy_version_and_hash():
    original = governor_module.fetch_policy_bundle
    governor_module.fetch_policy_bundle = lambda *a, **k: _mortgage_bundle()
    try:
        governor = AgentGovernor.from_governanceops(
            ai_system_record_id="MDL-MORTGAGE-001",
            inventory_base_url="https://example-inventory.test/api/v1",
            secret_key="test-secret",
        )
        governor.evaluate_action(
            "customer_account_close_urgent", confidence=0.99, autonomy_level=AutonomyLevel.L4_FULL_AUTONOMY,
        )
        entry = governor.audit_log.entries[0]
        assert entry.payload["policy_version"] == 3
        assert entry.payload["policy_hash"] == "abc123def456"
    finally:
        governor_module.fetch_policy_bundle = original


def test_a_governor_not_built_via_from_governanceops_cannot_report_events():
    governor = AgentGovernor(secret_key="test-secret")
    governor.evaluate_action("some_action", confidence=0.9, autonomy_level=AutonomyLevel.L0_NO_AUTONOMY)
    with pytest.raises(RuntimeError, match="from_governanceops"):
        governor.report_event(governor.audit_log.entries[0])


def test_report_event_posts_the_expected_shape_back_to_inventory():
    """Monkeypatches report_runtime_event to capture what governor.py
    would actually send, without a real network call."""
    original_fetch = governor_module.fetch_policy_bundle
    original_report = governor_module.report_runtime_event
    captured = {}

    def fake_report(base_url, record_id, event, token):
        captured["base_url"] = base_url
        captured["record_id"] = record_id
        captured["event"] = event
        captured["token"] = token
        return {"event_id": "fake-event-id"}

    governor_module.fetch_policy_bundle = lambda *a, **k: _mortgage_bundle()
    governor_module.report_runtime_event = fake_report
    try:
        governor = AgentGovernor.from_governanceops(
            ai_system_record_id="MDL-MORTGAGE-001",
            inventory_base_url="https://example-inventory.test/api/v1",
            secret_key="test-secret",
            inventory_token="test-token",
        )
        governor.evaluate_action(
            "customer_account_close_urgent", confidence=0.99, autonomy_level=AutonomyLevel.L4_FULL_AUTONOMY,
        )
        result = governor.report_event(governor.audit_log.entries[0])

        assert result == {"event_id": "fake-event-id"}
        assert captured["base_url"] == "https://example-inventory.test/api/v1"
        assert captured["record_id"] == "MDL-MORTGAGE-001"
        assert captured["token"] == "test-token"
        assert captured["event"]["event_type"] == "policy_decision"
        assert captured["event"]["decision"] == "block"
        assert captured["event"]["policy_version"] == 3
        assert captured["event"]["policy_hash"] == "abc123def456"
        assert "raw_payload" in captured["event"]
    finally:
        governor_module.fetch_policy_bundle = original_fetch
        governor_module.report_runtime_event = original_report
