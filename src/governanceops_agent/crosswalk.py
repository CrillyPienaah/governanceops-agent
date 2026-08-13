"""
Crosswalk — which module/feature in this library maps to which named
requirement in the four frameworks this project targets: OSFI's July
2026 agentic AI supervisory bulletin, the OWASP Agentic AI Top 10,
NIST's AI Risk Management Framework, and the EU AI Act (Articles 12
and 14 specifically, the two that actually govern agentic-system
oversight).

Same honesty rule as Tool 1's crosswalk.py: this is a structural
mapping the library's author is asserting, not a certification that
using this library makes an institution compliant with any of these
frameworks. A human still has to configure the policy rules, tool
scopes, and autonomy tiers correctly for their own actual use case —
this library provides the mechanism, not the judgment.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CrosswalkEntry:
    component: str
    framework: str
    citation: str
    note: str


CROSSWALK: list[CrosswalkEntry] = [
    CrosswalkEntry(
        component="autonomy.AutonomyLevel",
        framework="osfi_agentic_bulletin",
        citation="OSFI, Agentic AI Supervisory Bulletin (July 2026)",
        note="Explicit autonomy classification rather than treating 'agentic AI' as one undifferentiated risk category.",
    ),
    CrosswalkEntry(
        component="autonomy.AutonomyLevel",
        framework="nist_ai_rmf",
        citation="NIST AI RMF, MAP function",
        note="Autonomy is a named risk factor to identify before deployment.",
    ),
    CrosswalkEntry(
        component="audit_log.AuditLog",
        framework="eu_ai_act",
        citation="EU AI Act, Article 12",
        note="'Tamper-evident logging' specifically named — this library's hash-chaining plus HMAC signing is the concrete mechanism, not just 'logging happens.'",
    ),
    CrosswalkEntry(
        component="audit_log.AuditLog",
        framework="owasp_agentic_top_10",
        citation="OWASP Agentic AI Top 10 — insufficient/unverifiable audit trails",
        note="A log that can be silently edited after the fact doesn't satisfy this control even if logging technically happened.",
    ),
    CrosswalkEntry(
        component="policy.PolicyEngine",
        framework="nist_ai_rmf",
        citation="NIST AI RMF, MANAGE function",
        note="Risk response scaled to both the system's own confidence and the consequence of an incorrect action.",
    ),
    CrosswalkEntry(
        component="policy.PolicyEngine",
        framework="osfi_agentic_bulletin",
        citation="OSFI, Agentic AI Supervisory Bulletin (July 2026)",
        note="Autonomy bounded by explicit, checkable rules rather than left to the agent's own judgment about when to escalate.",
    ),
    CrosswalkEntry(
        component="hitl.CheckpointStore",
        framework="eu_ai_act",
        citation="EU AI Act, Article 14",
        note="'Technically enforced' human oversight — the module docstring in hitl.py addresses directly why an expiry must default to blocked, not approved, to actually satisfy this rather than just resembling it.",
    ),
    CrosswalkEntry(
        component="hitl.CheckpointStore",
        framework="osfi_agentic_bulletin",
        citation="OSFI, Agentic AI Supervisory Bulletin (July 2026)",
        note="Explicit human checkpoints for actions above a configured risk threshold.",
    ),
    CrosswalkEntry(
        component="permissions.ToolPermissionRegistry",
        framework="owasp_agentic_top_10",
        citation="OWASP Agentic AI Top 10 — excessive agency",
        note="Deny-by-default tool scoping is the direct mitigation this top risk calls for.",
    ),
    CrosswalkEntry(
        component="permissions.ToolPermissionRegistry",
        framework="osfi_agentic_bulletin",
        citation="OSFI, Agentic AI Supervisory Bulletin (July 2026)",
        note="Tool access explicitly scoped rather than 'whatever the agent framework happens to expose.'",
    ),
    CrosswalkEntry(
        component="kill_switch.KillSwitch",
        framework="eu_ai_act",
        citation="EU AI Act, Article 14",
        note="The ability to disregard, override, or reverse an AI system's output/actions — a kill switch is the concrete mechanism.",
    ),
    CrosswalkEntry(
        component="kill_switch.KillSwitch",
        framework="osfi_agentic_bulletin",
        citation="OSFI, Agentic AI Supervisory Bulletin (July 2026)",
        note="A real stop mechanism, not monitoring a human could theoretically act on eventually.",
    ),
    CrosswalkEntry(
        component="governor.AgentGovernor",
        framework="nist_ai_rmf",
        citation="NIST AI RMF, GOVERN function",
        note="A single, consistently-applied decision path (kill switch, then policy, then tool scope) for every governed action is itself a governance control — the alternative (each integration point independently deciding what to check, in what order) is exactly the inconsistency GOVERN calls out as a risk.",
    ),
    CrosswalkEntry(
        component="persistence.PersistentAuditLog",
        framework="eu_ai_act",
        citation="EU AI Act, Article 12",
        note="Article 12 requires logs be kept for a defined retention period — an in-memory-only AuditLog can't satisfy that across a process restart; this is the concrete durability mechanism.",
    ),
]


def crosswalk_for_component(component: str) -> list[CrosswalkEntry]:
    return [entry for entry in CROSSWALK if entry.component == component]


def crosswalk_for_framework(framework: str) -> list[CrosswalkEntry]:
    return [entry for entry in CROSSWALK if entry.framework == framework]
