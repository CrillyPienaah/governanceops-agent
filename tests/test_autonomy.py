from governanceops_agent.autonomy import AUTONOMY_PROFILES, AutonomyLevel, at_least, profile_for


def test_ordering_behaves_as_plain_integer_comparison():
    assert AutonomyLevel.L0_NO_AUTONOMY < AutonomyLevel.L4_FULL_AUTONOMY


def test_at_least_true_when_actual_exceeds_minimum():
    assert at_least(AutonomyLevel.L3_BOUNDED_AUTONOMY, AutonomyLevel.L1_HUMAN_IN_LOOP) is True


def test_at_least_false_when_actual_below_minimum():
    assert at_least(AutonomyLevel.L1_HUMAN_IN_LOOP, AutonomyLevel.L3_BOUNDED_AUTONOMY) is False


def test_at_least_true_when_equal():
    assert at_least(AutonomyLevel.L2_HUMAN_ON_LOOP, AutonomyLevel.L2_HUMAN_ON_LOOP) is True


def test_every_level_has_a_profile():
    assert len(AUTONOMY_PROFILES) == 5
    for level in AutonomyLevel:
        profile = profile_for(level)
        assert profile.level == level
        assert isinstance(profile.description, str) and len(profile.description) > 10


def test_only_l1_requires_human_approval_by_default():
    assert profile_for(AutonomyLevel.L1_HUMAN_IN_LOOP).requires_human_approval_by_default is True
    for level in [
        AutonomyLevel.L0_NO_AUTONOMY,
        AutonomyLevel.L2_HUMAN_ON_LOOP,
        AutonomyLevel.L3_BOUNDED_AUTONOMY,
        AutonomyLevel.L4_FULL_AUTONOMY,
    ]:
        assert profile_for(level).requires_human_approval_by_default is False
