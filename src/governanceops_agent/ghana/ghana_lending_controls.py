"""
Ghana Lending-Decisioning Controls — Phase I

Implements Candidates 1 and 2 from the Phase I Regulatory Control
Specification as governanceops_agent PolicyEngine rules, evidenced to
the library's real hash-chained, HMAC-signed AuditLog:

  Candidate 1 — Procedural: credit report required before a credit
    transaction may be concluded (Credit Reporting Act 2007 / Act 726,
    §§24, 26; Credit Reporting Regulations 2020, L.I. 2394, reg. 22).

  Candidate 2 — Disclosure: pre-agreement disclosure statement required
    before agreement execution (Borrowers and Lenders Act 2020, Act 1052,
    §57).

Candidate 3 (Act 843 §41, automated decision-taking) is deliberately NOT
implemented here — see the AAGII-GovernanceOS Phase I Regulatory Control
Specification for why: its legal scope is unresolved and no policy
should be drafted for it until counsel has confirmed how it applies.

IMPORTANT: passing these checks does NOT constitute a claim of legal
compliance. See NOTE at the bottom of each evidence payload.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from governanceops_agent.audit_log import AuditLog
from governanceops_agent.autonomy import AutonomyLevel
from governanceops_agent.policy import Decision, PolicyDecisionResult, PolicyEngine, PolicyRule


class ControlId(str, Enum):
    CREDIT_REPORT_GATE = "candidate_1_credit_report_gate"
    DISCLOSURE_GATE = "candidate_2_disclosure_gate"


# Neither gate's decision actually varies with confidence or autonomy
# tier — these are deterministic procedural/disclosure preconditions,
# not confidence-scored agent actions. PolicyEngine.evaluate() requires
# both arguments anyway (they're part of the general policy-gating
# interface every rule is evaluated against), so fixed neutral values
# are passed through; the rules below never inspect them.
_NEUTRAL_CONFIDENCE = 1.0
_NEUTRAL_AUTONOMY = AutonomyLevel.L0_NO_AUTONOMY


# ---------------------------------------------------------------------------
# Candidate 1 — Credit Report Gate
# ---------------------------------------------------------------------------

CREDIT_REPORT_ACTION = "conclude_credit_transaction"


@dataclass
class CreditReportStatus:
    retrieved: bool
    bureau_id: Optional[str] = None
    retrieval_timestamp: Optional[float] = None


def credit_report_gate_rules(
    credit_report: CreditReportStatus, *, action: str = CREDIT_REPORT_ACTION
) -> tuple[PolicyRule, PolicyRule]:
    """
    Candidate 1 as PolicyEngine rules for one specific applicant's
    already-known credit-report status.

    Source: Credit Reporting Act 2007 (Act 726) §§24, 26; Credit
    Reporting Regulations 2020 (L.I. 2394) reg. 22; Bank of Ghana
    notice BG/GOV/SEC/2021/13.

    The two conditions below are mutually exclusive on
    `credit_report.retrieved`, so match order can't actually change the
    outcome here — but the BLOCK rule is still returned first to keep
    this consistent with the rest of the library's convention (see
    policy.py's `block_rule` / `inventory_client.py`'s forbidden-tool
    rules): the more restrictive rule is always the one a reader should
    expect to see checked first.
    """
    block = PolicyRule(
        name=f"{ControlId.CREDIT_REPORT_GATE.value}:block",
        condition=lambda act, confidence, level: act == action and not credit_report.retrieved,
        decision=Decision.BLOCK,
        reason=(
            "credit_report_not_retrieved -- Credit Reporting Act 2007 (Act 726) "
            "SS24, 26 and L.I. 2394 reg. 22 require a bureau credit report before "
            "a credit transaction may be concluded."
        ),
    )
    allow = PolicyRule(
        name=f"{ControlId.CREDIT_REPORT_GATE.value}:allow",
        condition=lambda act, confidence, level: act == action and credit_report.retrieved,
        decision=Decision.ALLOW,
        reason="credit_report_retrieved -- procedural precondition satisfied.",
    )
    return block, allow


def evaluate_credit_report_gate(
    *,
    system_id: str,
    applicant_ref: str,
    policy_version: str,
    credit_report: CreditReportStatus,
    audit_log: AuditLog,
) -> PolicyDecisionResult:
    """
    Candidate 1: an AI-assisted (or any) lending decision may not
    proceed to conclusion unless a credit report has been retrieved for
    the applicant from a licensed bureau.

    Builds a fresh, single-use PolicyEngine per call rather than
    reusing one across applicants: the two rules close over this
    specific `credit_report` instance, and every applicant shares the
    same `action` string (`conclude_credit_transaction`). Adding rules
    for successive applicants to one long-lived engine would both leak
    memory and, under first-match semantics, let an earlier applicant's
    rule silently shadow a later one for the same action -- so each
    evaluation gets its own short-lived engine instead.
    """
    block_rule, allow_rule = credit_report_gate_rules(credit_report)
    engine = PolicyEngine([block_rule, allow_rule])
    result = engine.evaluate(CREDIT_REPORT_ACTION, _NEUTRAL_CONFIDENCE, _NEUTRAL_AUTONOMY)

    audit_log.append(
        "policy_decision",
        {
            "system_id": system_id,
            "applicant_ref": applicant_ref,
            "policy_version": policy_version,
            "control_id": ControlId.CREDIT_REPORT_GATE.value,
            "action": result.action,
            "decision": result.decision.value,
            "matched_rule": result.matched_rule,
            "reason": result.reason,
            "bureau_id": credit_report.bureau_id,
            "retrieval_timestamp": credit_report.retrieval_timestamp,
            "note": (
                "This control checks retrieval of a bureau credit report "
                "as a procedural precondition. It does not assess the "
                "substance of the credit decision and does not constitute "
                "a legal compliance determination."
            ),
        },
    )
    return result


# ---------------------------------------------------------------------------
# Candidate 2 — Pre-Agreement Disclosure Gate
# ---------------------------------------------------------------------------

DISCLOSURE_ACTION = "execute_agreement"

REQUIRED_DISCLOSURE_FIELDS = [
    "principal_amount",
    "disbursement_schedule",
    "interest_rate",
    "repayment_schedule",
    "insurance",
    "fees",
    "total_cost_of_credit",
]


@dataclass
class DisclosureStatement:
    delivered: bool
    fields: dict = field(default_factory=dict)
    delivery_method: Optional[str] = None
    delivery_timestamp: Optional[float] = None

    def missing_fields(self) -> list[str]:
        return [f for f in REQUIRED_DISCLOSURE_FIELDS if not self.fields.get(f)]


def disclosure_gate_rules(
    disclosure: DisclosureStatement, *, action: str = DISCLOSURE_ACTION
) -> tuple[PolicyRule, PolicyRule]:
    """
    Candidate 2 as PolicyEngine rules for one specific applicant's
    already-known disclosure status.

    Source: Borrowers and Lenders Act 2020 (Act 1052) §57(1)-(3).

    NOTE: this is a terms-disclosure control (loan amount, rate, fees,
    repayment schedule). It is NOT an AI/model-explainability control
    and should never be described as one in partner-facing material.

    As with the credit-report gate, BLOCK is returned first even though
    the two conditions are mutually exclusive on `compliant`, to match
    the rest of the library's block-before-allow ordering convention.
    """
    missing = disclosure.missing_fields()
    compliant = disclosure.delivered and not missing

    if not disclosure.delivered:
        block_reason = (
            "disclosure_not_delivered -- Borrowers and Lenders Act 2020 (Act 1052) "
            "S57(1)-(3) requires a pre-agreement disclosure statement before "
            "agreement execution."
        )
    else:
        block_reason = (
            "disclosure_missing_required_fields -- Borrowers and Lenders Act 2020 "
            f"(Act 1052) S57(1)-(3): missing {', '.join(missing)}."
        )

    block = PolicyRule(
        name=f"{ControlId.DISCLOSURE_GATE.value}:block",
        condition=lambda act, confidence, level: act == action and not compliant,
        decision=Decision.BLOCK,
        reason=block_reason,
    )
    allow = PolicyRule(
        name=f"{ControlId.DISCLOSURE_GATE.value}:allow",
        condition=lambda act, confidence, level: act == action and compliant,
        decision=Decision.ALLOW,
        reason="disclosure_complete_and_delivered -- procedural precondition satisfied.",
    )
    return block, allow


def evaluate_disclosure_gate(
    *,
    system_id: str,
    applicant_ref: str,
    policy_version: str,
    disclosure: DisclosureStatement,
    audit_log: AuditLog,
) -> PolicyDecisionResult:
    """
    Candidate 2: an agreement may not be executed unless a compliant
    pre-agreement disclosure statement has been generated and evidenced
    as delivered to the applicant.

    See `evaluate_credit_report_gate` for why a fresh PolicyEngine is
    built per call rather than reused across applicants.
    """
    block_rule, allow_rule = disclosure_gate_rules(disclosure)
    engine = PolicyEngine([block_rule, allow_rule])
    result = engine.evaluate(DISCLOSURE_ACTION, _NEUTRAL_CONFIDENCE, _NEUTRAL_AUTONOMY)

    audit_log.append(
        "policy_decision",
        {
            "system_id": system_id,
            "applicant_ref": applicant_ref,
            "policy_version": policy_version,
            "control_id": ControlId.DISCLOSURE_GATE.value,
            "action": result.action,
            "decision": result.decision.value,
            "matched_rule": result.matched_rule,
            "reason": result.reason,
            "missing_fields": disclosure.missing_fields(),
            "delivery_method": disclosure.delivery_method,
            "delivery_timestamp": disclosure.delivery_timestamp,
            "note": (
                "This control checks delivery of a First-Schedule-compliant "
                "pre-agreement disclosure statement under Act 1052 §57. It "
                "concerns disclosure of credit-agreement terms, not "
                "explanation of an AI/model decision, and does not "
                "constitute a legal compliance determination."
            ),
        },
    )
    return result


# ---------------------------------------------------------------------------
# Example usage / smoke test — run directly for a quick sanity check
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json

    log = AuditLog(secret_key="replace-with-real-key-management")

    # Candidate 1: report not yet retrieved -> should block
    d1 = evaluate_credit_report_gate(
        system_id="lending-workflow-demo",
        applicant_ref="applicant-001",
        policy_version="v0.1.0",
        credit_report=CreditReportStatus(retrieved=False),
        audit_log=log,
    )
    assert d1.decision == Decision.BLOCK

    # Candidate 1: report retrieved -> should allow
    d2 = evaluate_credit_report_gate(
        system_id="lending-workflow-demo",
        applicant_ref="applicant-001",
        policy_version="v0.1.0",
        credit_report=CreditReportStatus(
            retrieved=True, bureau_id="bureau-xyz", retrieval_timestamp=time.time()
        ),
        audit_log=log,
    )
    assert d2.decision == Decision.ALLOW

    # Candidate 2: incomplete disclosure -> should block
    incomplete = DisclosureStatement(
        delivered=True,
        fields={"principal_amount": 5000, "interest_rate": 0.18},
    )
    d3 = evaluate_disclosure_gate(
        system_id="lending-workflow-demo",
        applicant_ref="applicant-001",
        policy_version="v0.1.0",
        disclosure=incomplete,
        audit_log=log,
    )
    assert d3.decision == Decision.BLOCK

    # Candidate 2: complete disclosure -> should allow
    complete = DisclosureStatement(
        delivered=True,
        fields={f: "value" for f in REQUIRED_DISCLOSURE_FIELDS},
        delivery_method="email",
        delivery_timestamp=time.time(),
    )
    d4 = evaluate_disclosure_gate(
        system_id="lending-workflow-demo",
        applicant_ref="applicant-001",
        policy_version="v0.1.0",
        disclosure=complete,
        audit_log=log,
    )
    assert d4.decision == Decision.ALLOW

    entries = log.export_entries()
    print(f"Ran {len(entries)} evidence-generating checks. Sample entry:")
    print(json.dumps(entries[0], indent=2, default=str))

    verification = log.verify()
    assert verification.is_valid
    print(f"\nAudit log verified: {verification.entries_checked} entries, hash chain and HMAC signatures intact.")
    print("All smoke-test assertions passed.")
