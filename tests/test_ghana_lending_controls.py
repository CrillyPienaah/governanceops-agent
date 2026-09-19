from governanceops_agent.audit_log import AuditLog
from governanceops_agent.autonomy import AutonomyLevel
from governanceops_agent.ghana.ghana_lending_controls import (
    CREDIT_REPORT_ACTION,
    DISCLOSURE_ACTION,
    ControlId,
    CreditReportStatus,
    DisclosureStatement,
    REQUIRED_DISCLOSURE_FIELDS,
    credit_report_gate_rules,
    disclosure_gate_rules,
    evaluate_credit_report_gate,
    evaluate_disclosure_gate,
)
from governanceops_agent.policy import Decision, PolicyEngine


def _complete_disclosure(**overrides) -> DisclosureStatement:
    fields = {f: "value" for f in REQUIRED_DISCLOSURE_FIELDS}
    return DisclosureStatement(delivered=True, fields=fields, **overrides)


# ---------------------------------------------------------------------------
# Candidate 1 -- Credit Report Gate
# ---------------------------------------------------------------------------


def test_credit_report_not_retrieved_blocks():
    log = AuditLog(secret_key="test-secret")
    result = evaluate_credit_report_gate(
        system_id="s",
        applicant_ref="a1",
        policy_version="v0.1.0",
        credit_report=CreditReportStatus(retrieved=False),
        audit_log=log,
    )
    assert result.decision == Decision.BLOCK
    assert result.matched_rule == f"{ControlId.CREDIT_REPORT_GATE.value}:block"


def test_credit_report_retrieved_allows():
    log = AuditLog(secret_key="test-secret")
    result = evaluate_credit_report_gate(
        system_id="s",
        applicant_ref="a1",
        policy_version="v0.1.0",
        credit_report=CreditReportStatus(retrieved=True, bureau_id="bureau-xyz"),
        audit_log=log,
    )
    assert result.decision == Decision.ALLOW
    assert result.matched_rule == f"{ControlId.CREDIT_REPORT_GATE.value}:allow"


def test_credit_report_gate_writes_a_verifiable_audit_entry():
    log = AuditLog(secret_key="test-secret")
    evaluate_credit_report_gate(
        system_id="s",
        applicant_ref="a1",
        policy_version="v0.1.0",
        credit_report=CreditReportStatus(retrieved=False),
        audit_log=log,
    )
    entries = log.export_entries()
    assert len(entries) == 1
    assert entries[0]["event_type"] == "policy_decision"
    assert entries[0]["payload"]["control_id"] == ControlId.CREDIT_REPORT_GATE.value
    assert entries[0]["payload"]["applicant_ref"] == "a1"
    assert log.verify().is_valid is True


# ---------------------------------------------------------------------------
# Candidate 2 -- Pre-Agreement Disclosure Gate
# ---------------------------------------------------------------------------


def test_disclosure_not_delivered_blocks():
    log = AuditLog(secret_key="test-secret")
    result = evaluate_disclosure_gate(
        system_id="s",
        applicant_ref="a1",
        policy_version="v0.1.0",
        disclosure=DisclosureStatement(delivered=False),
        audit_log=log,
    )
    assert result.decision == Decision.BLOCK
    assert "disclosure_not_delivered" in result.reason


def test_disclosure_delivered_but_missing_fields_blocks():
    log = AuditLog(secret_key="test-secret")
    incomplete = DisclosureStatement(
        delivered=True, fields={"principal_amount": 5000, "interest_rate": 0.18}
    )
    result = evaluate_disclosure_gate(
        system_id="s",
        applicant_ref="a1",
        policy_version="v0.1.0",
        disclosure=incomplete,
        audit_log=log,
    )
    assert result.decision == Decision.BLOCK
    assert "disclosure_missing_required_fields" in result.reason
    for missing in ("disbursement_schedule", "repayment_schedule", "insurance", "fees", "total_cost_of_credit"):
        assert missing in result.reason


def test_disclosure_complete_and_delivered_allows():
    log = AuditLog(secret_key="test-secret")
    result = evaluate_disclosure_gate(
        system_id="s",
        applicant_ref="a1",
        policy_version="v0.1.0",
        disclosure=_complete_disclosure(delivery_method="email"),
        audit_log=log,
    )
    assert result.decision == Decision.ALLOW


# ---------------------------------------------------------------------------
# First-match rule ordering
# ---------------------------------------------------------------------------


def test_credit_report_rules_are_returned_block_first():
    block, allow = credit_report_gate_rules(CreditReportStatus(retrieved=True))
    assert block.decision == Decision.BLOCK
    assert allow.decision == Decision.ALLOW


def test_disclosure_rules_are_returned_block_first():
    block, allow = disclosure_gate_rules(_complete_disclosure())
    assert block.decision == Decision.BLOCK
    assert allow.decision == Decision.ALLOW


def test_engine_built_block_then_allow_still_allows_when_compliant():
    # Guards against a future edit reversing the tuple order silently
    # shadowing the ALLOW rule -- see policy.py's own documented footgun
    # (test_ordering_matters_a_block_placed_after_a_permissive_rule_is_shadowed
    # in test_policy.py) for why order is checked explicitly here rather
    # than assumed safe just because the two conditions happen to be
    # mutually exclusive today.
    block, allow = credit_report_gate_rules(CreditReportStatus(retrieved=True))
    engine = PolicyEngine([block, allow])
    result = engine.evaluate(CREDIT_REPORT_ACTION, confidence=1.0, autonomy_level=AutonomyLevel.L0_NO_AUTONOMY)
    assert result.decision == Decision.ALLOW


# ---------------------------------------------------------------------------
# No cross-applicant rule leakage
# ---------------------------------------------------------------------------


def test_no_cross_applicant_leakage_across_sequential_evaluations():
    """
    Each evaluate_*_gate call builds its own short-lived PolicyEngine
    scoped to one applicant's state. This proves that two applicants
    with opposite credit-report/disclosure states, evaluated back to
    back against the *same* AuditLog, each get their own correct
    decision -- an earlier applicant's rules must not leak into or
    shadow a later applicant's evaluation for the same action name.
    """
    log = AuditLog(secret_key="test-secret")

    blocked = evaluate_credit_report_gate(
        system_id="s",
        applicant_ref="applicant-blocked",
        policy_version="v0.1.0",
        credit_report=CreditReportStatus(retrieved=False),
        audit_log=log,
    )
    allowed = evaluate_credit_report_gate(
        system_id="s",
        applicant_ref="applicant-allowed",
        policy_version="v0.1.0",
        credit_report=CreditReportStatus(retrieved=True, bureau_id="bureau-xyz"),
        audit_log=log,
    )

    assert blocked.decision == Decision.BLOCK
    assert allowed.decision == Decision.ALLOW

    entries = log.export_entries()
    assert len(entries) == 2
    assert entries[0]["payload"]["applicant_ref"] == "applicant-blocked"
    assert entries[0]["payload"]["decision"] == "block"
    assert entries[1]["payload"]["applicant_ref"] == "applicant-allowed"
    assert entries[1]["payload"]["decision"] == "allow"
    assert log.verify().is_valid is True


def test_no_cross_applicant_leakage_for_disclosure_gate():
    log = AuditLog(secret_key="test-secret")

    blocked = evaluate_disclosure_gate(
        system_id="s",
        applicant_ref="applicant-blocked",
        policy_version="v0.1.0",
        disclosure=DisclosureStatement(delivered=False),
        audit_log=log,
    )
    allowed = evaluate_disclosure_gate(
        system_id="s",
        applicant_ref="applicant-allowed",
        policy_version="v0.1.0",
        disclosure=_complete_disclosure(),
        audit_log=log,
    )

    assert blocked.decision == Decision.BLOCK
    assert allowed.decision == Decision.ALLOW
    assert log.verify().is_valid is True
