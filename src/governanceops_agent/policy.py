"""
Policy/confidence gating — the decision engine that takes an agent's
proposed action (with a self-reported or measured confidence score)
plus its autonomy tier and decides: allow it, require a human
checkpoint first, or block it outright.

Maps to NIST AI RMF's MANAGE function (risk response should scale with
both the AI system's own confidence and the consequence of being
wrong) and to OSFI's agentic bulletin's expectation that autonomy be
bounded by explicit, checkable rules rather than left to the agent's
own judgment about when to ask for help — an agent should not be the
sole judge of whether it's confident enough to act unsupervised.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable, Optional

from governanceops_agent.autonomy import AutonomyLevel, at_least


class Decision(str, Enum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    BLOCK = "block"


@dataclass(frozen=True)
class PolicyRule:
    """
    One gating rule. Rules are evaluated in the order they're added to
    a PolicyEngine, and the FIRST matching rule wins — this is
    deliberately first-match, not "most restrictive wins" or "all
    rules combined," so that rule ordering is the actual, visible
    mechanism for expressing precedence (e.g. "block this specific
    tool always" ordered before a more general "allow anything above
    0.8 confidence" rule). A most-restrictive-wins design would hide
    that precedence inside implicit severity comparisons instead of
    making it something you can read straight off the rule list.

    `condition` receives the action name, confidence score, and
    autonomy level and returns True if this rule applies.
    """

    name: str
    condition: Callable[[str, float, AutonomyLevel], bool]
    decision: Decision
    reason: str


@dataclass(frozen=True)
class PolicyDecisionResult:
    decision: Decision
    matched_rule: Optional[str]
    reason: str
    action: str
    confidence: float
    autonomy_level: AutonomyLevel


class PolicyEngine:
    def __init__(self, rules: Optional[list[PolicyRule]] = None):
        self._rules: list[PolicyRule] = list(rules) if rules else []

    def add_rule(self, rule: PolicyRule) -> None:
        self._rules.append(rule)

    def evaluate(
        self, action: str, confidence: float, autonomy_level: AutonomyLevel
    ) -> PolicyDecisionResult:
        if not 0.0 <= confidence <= 1.0:
            raise ValueError(
                f"confidence must be between 0.0 and 1.0, got {confidence!r} — a "
                "score outside that range almost certainly indicates the caller is "
                "passing something that isn't actually a normalized confidence "
                "value (e.g. a raw logit or a percentage out of 100)."
            )

        for rule in self._rules:
            if rule.condition(action, confidence, autonomy_level):
                return PolicyDecisionResult(
                    decision=rule.decision,
                    matched_rule=rule.name,
                    reason=rule.reason,
                    action=action,
                    confidence=confidence,
                    autonomy_level=autonomy_level,
                )

        # No rule matched — the safe default is REQUIRE_APPROVAL, not
        # ALLOW. An agent taking an action nobody wrote a rule for is
        # exactly the situation a governance layer exists to catch;
        # silently allowing unrecognized actions would make this
        # library's absence and its presence-with-a-gap indistinguishable.
        return PolicyDecisionResult(
            decision=Decision.REQUIRE_APPROVAL,
            matched_rule=None,
            reason="No policy rule matched this action — defaulting to requiring human approval rather than allowing an unrecognized action through.",
            action=action,
            confidence=confidence,
            autonomy_level=autonomy_level,
        )


def threshold_rule_pair(
    name: str,
    *,
    min_confidence: float,
    minimum_autonomy: AutonomyLevel = AutonomyLevel.L0_NO_AUTONOMY,
    action_prefix: Optional[str] = None,
) -> tuple[PolicyRule, PolicyRule]:
    """
    Returns two rules that together implement "actions [matching this
    prefix,] at or above this autonomy tier: allow if confidence >=
    min_confidence, otherwise require approval." Add both to a
    PolicyEngine, in this order (the ALLOW rule first) — first-match
    ordering means the ALLOW rule needs to be checked before the
    catch-all REQUIRE_APPROVAL rule for the same action space, or the
    second rule would shadow the first and every matching action would
    always require approval regardless of confidence.
    """

    def matches_scope(action: str, autonomy_level: AutonomyLevel) -> bool:
        if action_prefix and not action.startswith(action_prefix):
            return False
        return at_least(autonomy_level, minimum_autonomy)

    allow_rule = PolicyRule(
        name=f"{name}:allow",
        condition=lambda action, confidence, level: (
            matches_scope(action, level) and confidence >= min_confidence
        ),
        decision=Decision.ALLOW,
        reason=f"Confidence {min_confidence:.2f} or higher meets the threshold for '{name}'.",
    )
    require_approval_rule = PolicyRule(
        name=f"{name}:require_approval",
        condition=lambda action, confidence, level: matches_scope(action, level),
        decision=Decision.REQUIRE_APPROVAL,
        reason=f"Confidence below {min_confidence:.2f} for '{name}' — human approval required.",
    )
    return allow_rule, require_approval_rule


def block_rule(name: str, *, action_prefix: str, reason: str) -> PolicyRule:
    """Convenience constructor for an unconditional block on a class of
    actions, regardless of confidence or autonomy tier — e.g. "never
    allow wire_transfer actions through this policy engine at all,"
    which is a fundamentally different statement than "require very
    high confidence for wire transfers." Ordered before any threshold
    rules that might otherwise match the same action_prefix."""
    return PolicyRule(
        name=name,
        condition=lambda action, confidence, level: action.startswith(action_prefix),
        decision=Decision.BLOCK,
        reason=reason,
    )
