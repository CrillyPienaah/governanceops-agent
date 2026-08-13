"""
Autonomy tiering — the L0-L4 scale everything else in this library
keys off (policy gating chooses stricter defaults at higher tiers,
scoped permissions are typically narrower at lower tiers, HITL
checkpoints become mandatory rather than optional past a threshold
tier). Mirrors the same 5-level scale used for the `autonomy_level`
qualitative risk factor in the GovernanceOps Inventory tool (Tool 1),
so a model that graduates from a scored/passive system into an
agentic one carries a consistent autonomy rating across both tools —
same names, same order, same meaning.

Maps to OSFI's July 2026 agentic AI bulletin's expectation that
institutions classify agent autonomy explicitly rather than treating
"agentic AI" as one undifferentiated risk category, and to NIST AI
RMF's MAP function (autonomy is a named risk factor to identify before
deployment, not after).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum


class AutonomyLevel(IntEnum):
    """
    IntEnum (not a plain str Enum, unlike most of Tool 1's enums) —
    autonomy comparisons ("is this action's tier at least L3?") are a
    real, frequent operation throughout this library, and IntEnum gives
    that for free via normal less-than/greater-or-equal comparison
    instead of needing a separate ROLE_HIERARCHY-style lookup table
    (the approach Tool 1's UserRole needed, since plain str Enums
    don't order meaningfully).
    """

    L0_NO_AUTONOMY = 0
    L1_HUMAN_IN_LOOP = 1
    L2_HUMAN_ON_LOOP = 2
    L3_BOUNDED_AUTONOMY = 3
    L4_FULL_AUTONOMY = 4


@dataclass(frozen=True)
class AutonomyProfile:
    """Human-readable description of what a tier actually means in
    practice — used for audit-log entries and error messages, so a
    rejected action's explanation says something a reviewer can
    actually act on, not just "L2"."""

    level: AutonomyLevel
    name: str
    description: str
    requires_human_approval_by_default: bool


AUTONOMY_PROFILES: dict[AutonomyLevel, AutonomyProfile] = {
    AutonomyLevel.L0_NO_AUTONOMY: AutonomyProfile(
        level=AutonomyLevel.L0_NO_AUTONOMY,
        name="No autonomy",
        description="Static or deterministic output — the same input always produces the same action; nothing here is actually a decision.",
        requires_human_approval_by_default=False,
    ),
    AutonomyLevel.L1_HUMAN_IN_LOOP: AutonomyProfile(
        level=AutonomyLevel.L1_HUMAN_IN_LOOP,
        name="Human in the loop",
        description="Every action requires explicit human sign-off before it executes — the agent proposes, a human disposes.",
        requires_human_approval_by_default=True,
    ),
    AutonomyLevel.L2_HUMAN_ON_LOOP: AutonomyProfile(
        level=AutonomyLevel.L2_HUMAN_ON_LOOP,
        name="Human on the loop",
        description="The agent acts without waiting for approval, but a human is actively monitoring and can intervene before consequences compound.",
        requires_human_approval_by_default=False,
    ),
    AutonomyLevel.L3_BOUNDED_AUTONOMY: AutonomyProfile(
        level=AutonomyLevel.L3_BOUNDED_AUTONOMY,
        name="Bounded autonomy",
        description="Fully autonomous within a scoped set of tools/actions and hard limits (e.g. a dollar threshold) — cannot act outside that boundary regardless of what it decides.",
        requires_human_approval_by_default=False,
    ),
    AutonomyLevel.L4_FULL_AUTONOMY: AutonomyProfile(
        level=AutonomyLevel.L4_FULL_AUTONOMY,
        name="Full autonomy",
        description="Self-directed with minimal or no built-in scope limits — the agent's own judgment is the only constraint on what it decides to do next.",
        requires_human_approval_by_default=False,
    ),
}


def profile_for(level: AutonomyLevel) -> AutonomyProfile:
    return AUTONOMY_PROFILES[level]


def at_least(actual: AutonomyLevel, minimum: AutonomyLevel) -> bool:
    """
    Thin wrapper around plain integer comparison rather than just
    telling callers to compare IntEnums directly. Two reasons: it reads
    the same way role_at_least() does in Tool 1 (consistent vocabulary
    across both tools for "is this at least X"), and it's one place to
    change if AutonomyLevel's ordering ever needs to become something
    other than plain integer comparison (e.g. if a future tier gets
    inserted between existing ones without renumbering everything).
    """
    return actual >= minimum
