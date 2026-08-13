import pytest

from governanceops_agent.autonomy import AutonomyLevel
from governanceops_agent.policy import Decision, PolicyEngine, block_rule, threshold_rule_pair


def test_no_rules_defaults_to_require_approval_never_silently_allows():
    engine = PolicyEngine()
    result = engine.evaluate("send_email", confidence=0.99, autonomy_level=AutonomyLevel.L4_FULL_AUTONOMY)
    assert result.decision == Decision.REQUIRE_APPROVAL
    assert result.matched_rule is None


def test_threshold_rule_pair_gates_on_confidence():
    allow_rule, approval_rule = threshold_rule_pair("email", min_confidence=0.8, action_prefix="send_email")
    engine = PolicyEngine([allow_rule, approval_rule])
    high = engine.evaluate("send_email", confidence=0.9, autonomy_level=AutonomyLevel.L3_BOUNDED_AUTONOMY)
    assert high.decision == Decision.ALLOW
    low = engine.evaluate("send_email", confidence=0.5, autonomy_level=AutonomyLevel.L3_BOUNDED_AUTONOMY)
    assert low.decision == Decision.REQUIRE_APPROVAL


def test_action_prefix_scoping_excludes_unrelated_actions():
    allow_rule, approval_rule = threshold_rule_pair("email", min_confidence=0.8, action_prefix="send_email")
    engine = PolicyEngine([allow_rule, approval_rule])
    unrelated = engine.evaluate("delete_file", confidence=0.99, autonomy_level=AutonomyLevel.L4_FULL_AUTONOMY)
    assert unrelated.decision == Decision.REQUIRE_APPROVAL
    assert unrelated.matched_rule is None


def test_minimum_autonomy_gating():
    allow_rule, approval_rule = threshold_rule_pair(
        "bounded_only", min_confidence=0.5, minimum_autonomy=AutonomyLevel.L3_BOUNDED_AUTONOMY, action_prefix="act"
    )
    engine = PolicyEngine([allow_rule, approval_rule])
    below_min = engine.evaluate("act_x", confidence=0.99, autonomy_level=AutonomyLevel.L1_HUMAN_IN_LOOP)
    assert below_min.matched_rule is None  # neither rule's autonomy condition matched -> falls through to default
    at_min = engine.evaluate("act_x", confidence=0.99, autonomy_level=AutonomyLevel.L3_BOUNDED_AUTONOMY)
    assert at_min.decision == Decision.ALLOW


def test_block_rule_takes_precedence_when_ordered_first():
    blocker = block_rule("never_wire", action_prefix="wire_transfer", reason="Wire transfers always need a human.")
    allow_rule, approval_rule = threshold_rule_pair("wire", min_confidence=0.1, action_prefix="wire_transfer")
    engine = PolicyEngine([blocker, allow_rule, approval_rule])
    result = engine.evaluate("wire_transfer_1000", confidence=0.99, autonomy_level=AutonomyLevel.L4_FULL_AUTONOMY)
    assert result.decision == Decision.BLOCK
    assert result.matched_rule == "never_wire"


def test_ordering_matters_a_block_placed_after_a_permissive_rule_is_shadowed():
    """Documents a real footgun in PolicyRule's own docstring — this
    test proves the warning is accurate, not just plausible-sounding."""
    blocker = block_rule("never_wire", action_prefix="wire_transfer", reason="should have blocked")
    allow_rule, approval_rule = threshold_rule_pair("wire", min_confidence=0.1, action_prefix="wire_transfer")
    engine = PolicyEngine([allow_rule, approval_rule, blocker])  # wrong order
    result = engine.evaluate("wire_transfer_1000", confidence=0.99, autonomy_level=AutonomyLevel.L4_FULL_AUTONOMY)
    assert result.decision == Decision.ALLOW  # the block never got a chance to fire
    assert result.matched_rule != "never_wire"


def test_confidence_out_of_range_raises():
    engine = PolicyEngine()
    with pytest.raises(ValueError):
        engine.evaluate("x", confidence=1.5, autonomy_level=AutonomyLevel.L0_NO_AUTONOMY)
