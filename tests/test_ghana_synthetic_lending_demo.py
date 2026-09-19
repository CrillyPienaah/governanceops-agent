"""
Automated coverage for examples/ghana_synthetic_lending_demo.py.

The demo script lives in examples/, not src/, so it isn't installed as
part of the governanceops_agent package -- it's loaded directly from
its file path here, the same script that `python
examples/ghana_synthetic_lending_demo.py` runs, not a reimplementation
of its logic.
"""

import importlib.util
import pathlib
import sys

import pytest

from governanceops_agent import AuditLog, Decision

_DEMO_PATH = pathlib.Path(__file__).resolve().parent.parent / "examples" / "ghana_synthetic_lending_demo.py"
_spec = importlib.util.spec_from_file_location("ghana_synthetic_lending_demo", _DEMO_PATH)
demo = importlib.util.module_from_spec(_spec)
# Dataclass processing (triggered by @dataclass in the demo module) looks
# the module up via sys.modules[cls.__module__] to resolve string
# annotations -- it must be registered there before exec_module runs, or
# that lookup returns None and dataclass() raises AttributeError.
sys.modules[_spec.name] = demo
_spec.loader.exec_module(demo)


@pytest.fixture
def log() -> AuditLog:
    return AuditLog(secret_key="test-secret")


def test_scenario_1_clean_pass_both_gates_allow(log):
    run = demo.run_scenario_1(log)
    assert [s.decision for s in run.steps] == [Decision.ALLOW, Decision.ALLOW]
    assert run.skipped_notes == []


def test_scenario_2_credit_report_block_skips_disclosure_gate(log):
    run = demo.run_scenario_2(log)
    assert [s.decision for s in run.steps] == [Decision.BLOCK]
    assert len(run.skipped_notes) == 1
    # Only one audit entry exists for this applicant -- the disclosure
    # gate was genuinely never called, not called-and-ignored.
    entries = [e for e in log.export_entries() if e["payload"]["applicant_ref"] == demo.APPLICANT_B_REF]
    assert len(entries) == 1


def test_scenario_3_disclosure_block_names_missing_fields(log):
    run = demo.run_scenario_3(log)
    assert [s.decision for s in run.steps] == [Decision.ALLOW, Decision.BLOCK]
    disclosure_step = run.steps[1]
    assert "insurance" in disclosure_step.reason
    assert "total_cost_of_credit" in disclosure_step.reason
    assert disclosure_step.audit_entry.payload["missing_fields"] == ["insurance", "total_cost_of_credit"]


def test_scenario_4_credit_report_block_skips_disclosure_gate_too(log):
    run = demo.run_scenario_4(log)
    assert [s.decision for s in run.steps] == [Decision.BLOCK]
    assert len(run.skipped_notes) == 1
    entries = [e for e in log.export_entries() if e["payload"]["applicant_ref"] == demo.APPLICANT_D_REF]
    assert len(entries) == 1


def test_scenario_5_sequential_applicant_isolation(log):
    demo.run_scenario_1(log)
    demo.run_scenario_2(log)
    run = demo.run_scenario_5(log)
    decisions = [s.decision for s in run.steps]
    assert decisions == [Decision.ALLOW, Decision.ALLOW, Decision.BLOCK]

    a_credit, a_disclosure, b_credit = run.steps
    assert a_credit.matched_rule == f"{demo.ControlId.CREDIT_REPORT_GATE.value}:allow"
    assert b_credit.matched_rule == f"{demo.ControlId.CREDIT_REPORT_GATE.value}:block"
    # Applicant A's ALLOW entry is untouched by Applicant B's BLOCK that
    # follows it in the same chain, and vice versa -- each entry still
    # carries its own applicant_ref and decision independently.
    assert a_credit.audit_entry.payload["applicant_ref"] == demo.APPLICANT_A_REF
    assert a_credit.audit_entry.payload["decision"] == "allow"
    assert b_credit.audit_entry.payload["applicant_ref"] == demo.APPLICANT_B_REF
    assert b_credit.audit_entry.payload["decision"] == "block"


def test_full_demo_session_audit_log_verifies_clean(log):
    for scenario_fn in (
        demo.run_scenario_1,
        demo.run_scenario_2,
        demo.run_scenario_3,
        demo.run_scenario_4,
        demo.run_scenario_5,
    ):
        scenario_fn(log)

    result = log.verify()
    assert result.is_valid is True
    assert result.entries_checked == 9


def test_main_runs_end_to_end_without_raising(capsys):
    demo.main()
    captured = capsys.readouterr()
    assert "is_valid=True" in captured.out
    assert "FINAL AUDIT VERIFICATION" in captured.out
