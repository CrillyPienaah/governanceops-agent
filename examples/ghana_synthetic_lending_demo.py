"""
Ghana Phase I Synthetic Lending Demonstration

Runs the five scenarios from the Synthetic Lending Demo Scenario
Definitions document against the real, already-shipped v0.2.0
`governanceops_agent.ghana` controls (credit-report gate, Act 1052 S57
disclosure gate) and the real `AuditLog`. Every decision, audit entry,
and verification result printed here is produced by actually calling
those functions -- nothing in this script's output is fabricated or
hand-written to look plausible.

This is demonstration packaging, not new product development:
  - No new governance controls are introduced.
  - Candidate 3 (Act 843 S41) is NOT implemented here or anywhere else.
  - All applicant data is synthetic and fictional. No real borrower
    information is used anywhere in this script.
  - This demo does not certify Ghanaian legal compliance, Bank of Ghana
    approval, or institutional validation of any kind.

Usage:

    python examples/ghana_synthetic_lending_demo.py

No network access, database, or external service is required -- this
runs entirely against in-memory PolicyEngine/AuditLog instances.
"""

from __future__ import annotations

import json
import sys
import time
from dataclasses import dataclass, field

from governanceops_agent import AuditEntry, AuditLog, Decision, VerificationResult
from governanceops_agent.ghana import (
    CREDIT_REPORT_ACTION,
    DISCLOSURE_ACTION,
    REQUIRED_DISCLOSURE_FIELDS,
    ControlId,
    CreditReportStatus,
    DisclosureStatement,
    evaluate_credit_report_gate,
    evaluate_disclosure_gate,
)

# ---------------------------------------------------------------------------
# Synthetic fixtures — SYNTHETIC INPUT only. No real borrower data.
# ---------------------------------------------------------------------------

SYSTEM_ID = "SYN-SYSTEM-GHANA-LENDING-DEMO"
POLICY_VERSION = "ghana-phase1-lending-v1.0.0-demo"
DEMO_SECRET_KEY = "ghana-synthetic-lending-demo-ephemeral-secret-not-for-production"

APPLICANT_A_REF = "SYN-APPLICANT-A"
APPLICANT_A_NAME = "Ama Mensah (fictional, synthetic)"
APPLICANT_B_REF = "SYN-APPLICANT-B"
APPLICANT_B_NAME = "Kwame Boateng (fictional, synthetic)"
APPLICANT_C_REF = "SYN-APPLICANT-C"
APPLICANT_C_NAME = "Efua Owusu (fictional, synthetic)"
APPLICANT_D_REF = "SYN-APPLICANT-D"
APPLICANT_D_NAME = "Yaw Asante (fictional, synthetic)"


def _credit_report_retrieved(bureau_id: str) -> CreditReportStatus:
    return CreditReportStatus(retrieved=True, bureau_id=bureau_id, retrieval_timestamp=time.time())


def _credit_report_missing() -> CreditReportStatus:
    return CreditReportStatus(retrieved=False)


def _disclosure_complete() -> DisclosureStatement:
    return DisclosureStatement(
        delivered=True,
        fields={f: "synthetic-value" for f in REQUIRED_DISCLOSURE_FIELDS},
        delivery_method="email",
        delivery_timestamp=time.time(),
    )


def _disclosure_missing_insurance_and_total_cost() -> DisclosureStatement:
    # Matches the scenario document's own example verbatim: "e.g.,
    # insurance and total-cost-of-credit fields empty."
    fields = {f: "synthetic-value" for f in REQUIRED_DISCLOSURE_FIELDS}
    fields["insurance"] = None
    fields["total_cost_of_credit"] = None
    return DisclosureStatement(delivered=True, fields=fields, delivery_method="email")


def _disclosure_not_delivered() -> DisclosureStatement:
    return DisclosureStatement(delivered=False)


# ---------------------------------------------------------------------------
# Result scaffolding — bookkeeping for this demo script only, not a new
# library API. Every field here is populated from the real return values
# of evaluate_credit_report_gate / evaluate_disclosure_gate / AuditLog.
# ---------------------------------------------------------------------------


@dataclass
class GateStep:
    gate_label: str
    control_id: str
    requested_action: str
    decision: Decision
    matched_rule: str | None
    reason: str
    audit_entry: AuditEntry
    verification: VerificationResult


@dataclass
class ScenarioRun:
    number: int
    name: str
    applicant_ref: str
    applicant_display_name: str
    steps: list[GateStep] = field(default_factory=list)
    skipped_notes: list[str] = field(default_factory=list)
    summary: str = ""


def _run_gate_step(
    *, log: AuditLog, gate_label: str, control_id: ControlId, requested_action: str, decision_result
) -> GateStep:
    entry = log.entries[-1]  # the entry evaluate_*_gate just appended
    verification = log.verify()
    return GateStep(
        gate_label=gate_label,
        control_id=control_id.value,
        requested_action=requested_action,
        decision=decision_result.decision,
        matched_rule=decision_result.matched_rule,
        reason=decision_result.reason,
        audit_entry=entry,
        verification=verification,
    )


# ---------------------------------------------------------------------------
# Scenario 1 — Clean Pass
# ---------------------------------------------------------------------------


def run_scenario_1(log: AuditLog) -> ScenarioRun:
    run = ScenarioRun(1, "Clean Pass", APPLICANT_A_REF, APPLICANT_A_NAME)

    credit_result = evaluate_credit_report_gate(
        system_id=SYSTEM_ID,
        applicant_ref=APPLICANT_A_REF,
        policy_version=POLICY_VERSION,
        credit_report=_credit_report_retrieved(bureau_id="SYN-BUREAU-01"),
        audit_log=log,
    )
    run.steps.append(
        _run_gate_step(
            log=log, gate_label="Credit-report gate", control_id=ControlId.CREDIT_REPORT_GATE,
            requested_action=CREDIT_REPORT_ACTION, decision_result=credit_result,
        )
    )
    assert credit_result.decision == Decision.ALLOW

    disclosure_result = evaluate_disclosure_gate(
        system_id=SYSTEM_ID,
        applicant_ref=APPLICANT_A_REF,
        policy_version=POLICY_VERSION,
        disclosure=_disclosure_complete(),
        audit_log=log,
    )
    run.steps.append(
        _run_gate_step(
            log=log, gate_label="Disclosure gate", control_id=ControlId.DISCLOSURE_GATE,
            requested_action=DISCLOSURE_ACTION, decision_result=disclosure_result,
        )
    )
    assert disclosure_result.decision == Decision.ALLOW

    run.summary = (
        "Both gates ALLOW. The transaction proceeds to conclusion. Both policy_decision "
        f"entries cite the same policy_version ({POLICY_VERSION})."
    )
    return run


# ---------------------------------------------------------------------------
# Scenario 2 — Blocked: No Credit Report
# ---------------------------------------------------------------------------


def run_scenario_2(log: AuditLog) -> ScenarioRun:
    run = ScenarioRun(2, "Blocked: No Credit Report", APPLICANT_B_REF, APPLICANT_B_NAME)

    credit_result = evaluate_credit_report_gate(
        system_id=SYSTEM_ID,
        applicant_ref=APPLICANT_B_REF,
        policy_version=POLICY_VERSION,
        credit_report=_credit_report_missing(),
        audit_log=log,
    )
    run.steps.append(
        _run_gate_step(
            log=log, gate_label="Credit-report gate", control_id=ControlId.CREDIT_REPORT_GATE,
            requested_action=CREDIT_REPORT_ACTION, decision_result=credit_result,
        )
    )
    assert credit_result.decision == Decision.BLOCK

    # Per the documented workflow ordering, the disclosure gate is never
    # reached once the credit-report gate blocks. Deliberately NOT
    # calling evaluate_disclosure_gate here -- this applicant's
    # disclosure statement is in fact complete (see Scenario 2's setup),
    # but the workflow halts before that ever matters.
    run.skipped_notes.append(
        "Disclosure gate: NOT EVALUATED -- workflow halted after the credit-report "
        "gate's BLOCK. This applicant's disclosure statement was in fact complete, "
        "but the lending workflow never reaches that check."
    )

    run.summary = (
        "Credit-report gate BLOCKs deterministically. No override, no partial credit. "
        "Only one BLOCK record exists for this applicant -- there is deliberately no "
        "disclosure-gate record at all."
    )
    return run


# ---------------------------------------------------------------------------
# Scenario 3 — Blocked: Incomplete Disclosure
# ---------------------------------------------------------------------------


def run_scenario_3(log: AuditLog) -> ScenarioRun:
    run = ScenarioRun(3, "Blocked: Incomplete Disclosure", APPLICANT_C_REF, APPLICANT_C_NAME)

    credit_result = evaluate_credit_report_gate(
        system_id=SYSTEM_ID,
        applicant_ref=APPLICANT_C_REF,
        policy_version=POLICY_VERSION,
        credit_report=_credit_report_retrieved(bureau_id="SYN-BUREAU-02"),
        audit_log=log,
    )
    run.steps.append(
        _run_gate_step(
            log=log, gate_label="Credit-report gate", control_id=ControlId.CREDIT_REPORT_GATE,
            requested_action=CREDIT_REPORT_ACTION, decision_result=credit_result,
        )
    )
    assert credit_result.decision == Decision.ALLOW

    disclosure_result = evaluate_disclosure_gate(
        system_id=SYSTEM_ID,
        applicant_ref=APPLICANT_C_REF,
        policy_version=POLICY_VERSION,
        disclosure=_disclosure_missing_insurance_and_total_cost(),
        audit_log=log,
    )
    run.steps.append(
        _run_gate_step(
            log=log, gate_label="Disclosure gate", control_id=ControlId.DISCLOSURE_GATE,
            requested_action=DISCLOSURE_ACTION, decision_result=disclosure_result,
        )
    )
    assert disclosure_result.decision == Decision.BLOCK
    assert "insurance" in disclosure_result.reason
    assert "total_cost_of_credit" in disclosure_result.reason

    run.summary = (
        "Credit-report gate ALLOWs, but the disclosure gate BLOCKs on missing "
        "First Schedule fields (insurance, total_cost_of_credit) -- the evidence names "
        "the specific missing fields, not just 'incomplete'."
    )
    return run


# ---------------------------------------------------------------------------
# Scenario 4 — Blocked: Both Gates Fail
# ---------------------------------------------------------------------------


def run_scenario_4(log: AuditLog) -> ScenarioRun:
    run = ScenarioRun(4, "Blocked: Both Gates Fail", APPLICANT_D_REF, APPLICANT_D_NAME)

    credit_result = evaluate_credit_report_gate(
        system_id=SYSTEM_ID,
        applicant_ref=APPLICANT_D_REF,
        policy_version=POLICY_VERSION,
        credit_report=_credit_report_missing(),
        audit_log=log,
    )
    run.steps.append(
        _run_gate_step(
            log=log, gate_label="Credit-report gate", control_id=ControlId.CREDIT_REPORT_GATE,
            requested_action=CREDIT_REPORT_ACTION, decision_result=credit_result,
        )
    )
    assert credit_result.decision == Decision.BLOCK

    # This applicant's disclosure statement is ALSO not delivered (see
    # _disclosure_not_delivered), but per the credit-report gate's
    # enforcement-point ordering, the disclosure gate is never reached
    # in this run either -- deliberately not calling it, same rationale
    # as Scenario 2.
    run.skipped_notes.append(
        "Disclosure gate: NOT EVALUATED -- workflow halted after the credit-report "
        "gate's BLOCK, same lending-lifecycle ordering as Scenario 2. This applicant's "
        "disclosure statement was also not delivered, but that fact is never checked "
        "in this run because the workflow never gets there."
    )

    run.summary = (
        "Only the credit-report BLOCK appears in the evidence trail, even though this "
        "applicant would also have failed the disclosure gate. The evidence reflects the "
        "actual sequence of what was checked, not a checklist of everything that could "
        "have been checked."
    )
    return run


# ---------------------------------------------------------------------------
# Scenario 5 — Two Applicants, No Cross-Contamination
# ---------------------------------------------------------------------------


def run_scenario_5(log: AuditLog) -> ScenarioRun:
    run = ScenarioRun(
        5,
        "Two Applicants, No Cross-Contamination",
        f"{APPLICANT_A_REF} + {APPLICANT_B_REF}",
        f"{APPLICANT_A_NAME} & {APPLICANT_B_NAME}",
    )

    # Reuses the exact same synthetic profiles as Scenario 1 (Applicant A)
    # and Scenario 2 (Applicant B), evaluated back-to-back immediately
    # after one another, in the same demo session and the same AuditLog.
    # Each evaluate_*_gate call builds its own fresh, single-use
    # PolicyEngine internally (see
    # governanceops_agent/ghana/ghana_lending_controls.py) precisely to
    # prevent one applicant's rule from shadowing another's under
    # first-match semantics -- this is the same guarantee already
    # covered in tests/test_ghana_lending_controls.py, made visible here
    # rather than just asserted in a test file.
    a_credit = evaluate_credit_report_gate(
        system_id=SYSTEM_ID, applicant_ref=APPLICANT_A_REF, policy_version=POLICY_VERSION,
        credit_report=_credit_report_retrieved(bureau_id="SYN-BUREAU-01"), audit_log=log,
    )
    run.steps.append(
        _run_gate_step(
            log=log, gate_label="Credit-report gate (Applicant A)", control_id=ControlId.CREDIT_REPORT_GATE,
            requested_action=CREDIT_REPORT_ACTION, decision_result=a_credit,
        )
    )

    a_disclosure = evaluate_disclosure_gate(
        system_id=SYSTEM_ID, applicant_ref=APPLICANT_A_REF, policy_version=POLICY_VERSION,
        disclosure=_disclosure_complete(), audit_log=log,
    )
    run.steps.append(
        _run_gate_step(
            log=log, gate_label="Disclosure gate (Applicant A)", control_id=ControlId.DISCLOSURE_GATE,
            requested_action=DISCLOSURE_ACTION, decision_result=a_disclosure,
        )
    )

    b_credit = evaluate_credit_report_gate(
        system_id=SYSTEM_ID, applicant_ref=APPLICANT_B_REF, policy_version=POLICY_VERSION,
        credit_report=_credit_report_missing(), audit_log=log,
    )
    run.steps.append(
        _run_gate_step(
            log=log, gate_label="Credit-report gate (Applicant B)", control_id=ControlId.CREDIT_REPORT_GATE,
            requested_action=CREDIT_REPORT_ACTION, decision_result=b_credit,
        )
    )

    assert a_credit.decision == Decision.ALLOW
    assert a_disclosure.decision == Decision.ALLOW
    assert b_credit.decision == Decision.BLOCK
    # Isolation, made explicit: B's BLOCK must come from B's own block
    # rule, not from any rule A's evaluation left behind, and A's ALLOW
    # must equally be unaffected by B's BLOCK that follows it.
    assert a_credit.matched_rule == f"{ControlId.CREDIT_REPORT_GATE.value}:allow"
    assert b_credit.matched_rule == f"{ControlId.CREDIT_REPORT_GATE.value}:block"

    run.summary = (
        "Applicant A's ALLOW and Applicant B's BLOCK sit adjacently in the same hash "
        "chain, each correctly attributed to its own applicant_ref, and neither result "
        "was altered by the other. This demonstrates SEQUENTIAL applicant isolation "
        "within this single-process, single-threaded demo run only -- it does NOT "
        "demonstrate concurrent execution safety, multi-tenant isolation under "
        "concurrent load, or production scalability. No such claim is made."
    )
    return run


# ---------------------------------------------------------------------------
# Presentation
# ---------------------------------------------------------------------------

_OUTCOME_WORD = {
    Decision.ALLOW: "PERMITTED",
    Decision.BLOCK: "BLOCKED",
    Decision.REQUIRE_APPROVAL: "ESCALATED (human approval required via the existing HITL checkpoint mechanism)",
}


def _rule(width: int = 78) -> None:
    print("=" * width)


def _print_scenario(run: ScenarioRun) -> None:
    _rule()
    print(f"SCENARIO {run.number} -- {run.name}")
    _rule()
    print(f"[SYNTHETIC INPUT] Applicant reference : {run.applicant_ref}")
    print(f"[SYNTHETIC INPUT] Applicant (fictional): {run.applicant_display_name}")
    print(f"[SYNTHETIC INPUT] Policy version        : {POLICY_VERSION}")
    print()

    for step in run.steps:
        print(f"--- {step.gate_label} ---")
        print(f"Control exercised : {step.control_id}")
        print(f"Requested action  : {step.requested_action}")
        print(f"[ACTUAL CONTROL DECISION] {_OUTCOME_WORD[step.decision]}  (matched_rule={step.matched_rule})")
        print(f"Reason            : {step.reason}")
        print("[ACTUAL AUDIT EVIDENCE] raw AuditEntry from the real hash-chained, HMAC-signed AuditLog:")
        print(json.dumps(step.audit_entry.to_dict(), indent=2, default=str))
        v = step.verification
        print(
            f"[AUDIT VERIFICATION] AuditLog.verify() -> is_valid={v.is_valid}, "
            f"entries_checked={v.entries_checked}"
            + ("" if v.is_valid else f", first_invalid_sequence={v.first_invalid_sequence}, reason={v.reason}")
        )
        print()

    for note in run.skipped_notes:
        print(f"[NOT EVALUATED] {note}")
        print()

    print(f"[HUMAN-READABLE SUMMARY] {run.summary}")
    print()


def main() -> None:
    print("GHANA PHASE I SYNTHETIC LENDING DEMONSTRATION")
    print("All applicant data below is SYNTHETIC and FICTIONAL. No real borrower")
    print("information is used anywhere in this script.")
    print()

    log = AuditLog(secret_key=DEMO_SECRET_KEY)

    runs = [
        run_scenario_1(log),
        run_scenario_2(log),
        run_scenario_3(log),
        run_scenario_4(log),
        run_scenario_5(log),
    ]
    for run in runs:
        _print_scenario(run)

    _rule()
    print("FINAL AUDIT VERIFICATION -- entire demo session's hash chain")
    _rule()
    final = log.verify()
    print(f"is_valid={final.is_valid}  entries_checked={final.entries_checked}")
    if not final.is_valid:
        print(
            f"first_invalid_sequence={final.first_invalid_sequence}  reason={final.reason}",
            file=sys.stderr,
        )
        sys.exit(1)
    print()

    print("What this demo does NOT claim:")
    print("  - Does not certify Ghanaian legal compliance for any real institution.")
    print("  - Does not evaluate the quality of any underlying AI lending recommendation.")
    print("  - Does not implement Candidate 3 (Act 843 S41, automated decision-taking) --")
    print("    that remains unimplemented pending legal review.")
    print("  - Scenario 5 does not demonstrate concurrent execution safety, multi-tenant")
    print("    isolation, or production scalability.")
    print("  - Does not constitute Bank of Ghana approval or institutional validation.")


if __name__ == "__main__":
    main()
