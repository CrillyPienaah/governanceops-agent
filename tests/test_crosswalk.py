from governanceops_agent.crosswalk import CROSSWALK, crosswalk_for_component, crosswalk_for_framework


def test_every_entry_is_well_formed():
    for entry in CROSSWALK:
        assert entry.citation and entry.note and entry.component and entry.framework


def test_component_lookup():
    audit_entries = crosswalk_for_component("audit_log.AuditLog")
    assert len(audit_entries) == 2
    assert {e.framework for e in audit_entries} == {"eu_ai_act", "owasp_agentic_top_10"}


def test_framework_lookup():
    eu_entries = crosswalk_for_framework("eu_ai_act")
    assert len(eu_entries) == 4  # audit_log, hitl, kill_switch, persistence


def test_all_four_named_frameworks_are_represented():
    frameworks_present = {e.framework for e in CROSSWALK}
    assert frameworks_present == {"osfi_agentic_bulletin", "nist_ai_rmf", "eu_ai_act", "owasp_agentic_top_10"}
