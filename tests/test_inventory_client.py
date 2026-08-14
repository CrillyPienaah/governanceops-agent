"""
Tests for app.governanceops_agent.inventory_client.build_governance_from_bundle
— the pure mapping logic with no network I/O, tested against hand-built
JSON matching GovernanceOps Inventory's actual documented
RuntimePolicyBundle response shape (see
governanceops-inventory/backend/app/models/schemas.py::RuntimePolicyBundle).

fetch_policy_bundle itself (the network call) is NOT covered here —
this sandbox had no network egress to test it against a live Inventory
instance. It was written carefully against the documented contract but
is genuinely unverified; its first real run against a live deployment
should be treated as real signal, per this module's own docstring.
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
    }
    bundle.update(overrides)
    return bundle


def test_mapping_produces_correct_autonomy_level_and_tool_scopes():
    engine, tool_scopes, autonomy_level = build_governance_from_bundle(_mortgage_bundle())
    assert autonomy_level == AutonomyLevel.L3_BOUNDED_AUTONOMY
    assert {s.tool_name for s in tool_scopes} == {"CreditCheck", "CalculateRisk", "ApproveApplication"}


def test_permitted_tool_within_confidence_and_limit_is_allowed():
    engine, tool_scopes, _ = build_governance_from_bundle(_mortgage_bundle())
    governor = AgentGovernor(secret_key="test-secret", policy_engine=engine)
    for scope in tool_scopes:
        governor.permissions.register(scope)

    outcome = governor.evaluate_action(
        "ApproveApplication_x", confidence=0.95, autonomy_level=AutonomyLevel.L3_BOUNDED_AUTONOMY,
        tool_name="ApproveApplication", tool_params={"amount": 400000},
    )
    assert outcome.allowed is True


def test_permitted_tool_over_transaction_limit_is_blocked():
    engine, tool_scopes, _ = build_governance_from_bundle(_mortgage_bundle())
    governor = AgentGovernor(secret_key="test-secret", policy_engine=engine)
    for scope in tool_scopes:
        governor.permissions.register(scope)

    outcome = governor.evaluate_action(
        "ApproveApplication_y", confidence=0.99, autonomy_level=AutonomyLevel.L3_BOUNDED_AUTONOMY,
        tool_name="ApproveApplication", tool_params={"amount": 2000000},
    )
    assert outcome.allowed is False
    assert "750,000" in outcome.denial_reason


def test_forbidden_tool_is_blocked_regardless_of_confidence_or_autonomy():
    engine, tool_scopes, _ = build_governance_from_bundle(_mortgage_bundle())
    governor = AgentGovernor(secret_key="test-secret", policy_engine=engine)
    for scope in tool_scopes:
        governor.permissions.register(scope)

    outcome = governor.evaluate_action(
        "customer_account_close_urgent", confidence=0.99, autonomy_level=AutonomyLevel.L4_FULL_AUTONOMY,
    )
    assert outcome.allowed is False
    assert "forbidden" in outcome.denial_reason


def test_low_confidence_on_permitted_tool_requires_approval_not_block_or_allow():
    engine, tool_scopes, _ = build_governance_from_bundle(_mortgage_bundle())
    governor = AgentGovernor(secret_key="test-secret", policy_engine=engine)
    for scope in tool_scopes:
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


def test_minimal_bundle_with_no_tools_keys_still_works():
    minimal = {
        "ai_system_id": "x", "ai_system_name": "y", "risk_rating": "low",
        "autonomy_level": "l2_human_on_loop",
    }
    engine, tool_scopes, autonomy_level = build_governance_from_bundle(minimal)
    assert tool_scopes == []
    assert autonomy_level == AutonomyLevel.L2_HUMAN_ON_LOOP


def test_rule_ordering_blocks_forbidden_tool_even_if_it_would_otherwise_match_a_permitted_rule():
    """The precedence guarantee: forbidden-tool block rules are added
    BEFORE permitted-tool threshold rules, so a tool name that somehow
    appears in both lists is still blocked, not silently allowed."""
    bundle = _mortgage_bundle(
        permitted_tools=["SharedName"],
        forbidden_tools=["SharedName"],
    )
    engine, tool_scopes, _ = build_governance_from_bundle(bundle)
    governor = AgentGovernor(secret_key="test-secret", policy_engine=engine)
    for scope in tool_scopes:
        governor.permissions.register(scope)

    outcome = governor.evaluate_action(
        "SharedName_action", confidence=0.99, autonomy_level=AutonomyLevel.L4_FULL_AUTONOMY,
        tool_name="SharedName", tool_params={},
    )
    assert outcome.allowed is False


# =========================================================
# AgentGovernor.from_governanceops — the classmethod itself.
# Monkeypatches the module-level fetch_policy_bundle reference governor.py
# actually holds (not inventory_client's copy — governor.py imported its
# own name binding at import time) to avoid needing real network access,
# while still exercising the real end-to-end path: fetch -> map -> build
# a governor -> evaluate a real action against it.
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
