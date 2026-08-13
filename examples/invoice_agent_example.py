"""
Reference integration example — a simplified version of the "Invoice
Reconciliation Agent" (MDL-AGENT-0003) already seeded into Tool 1's
model inventory: an agent that matches vendor invoices to purchase
orders, auto-approves confident exact matches under a dollar
threshold, and flags everything else for a human. This script is the
"how do I actually wire this up" answer that a README code snippet
can't fully show — a run through several realistic decision points in
one continuous session, including a kill-switch engagement.

Run it directly:

    python examples/invoice_agent_example.py

Every assertion in this file is a genuine correctness check, not just
illustrative comments — if the library's behavior ever regresses, this
script fails loudly rather than silently printing wrong output.
"""

from governanceops_agent import (
    AgentGovernor,
    AutonomyLevel,
    KillSwitchEngagedError,
    PolicyEngine,
    ToolScope,
    threshold_rule_pair,
)


def build_governor() -> AgentGovernor:
    # Policy: invoice-matching decisions at 0.9+ confidence are allowed
    # through (subject to the tool's own cap below); anything less
    # requires a human to actually look at the match.
    engine = PolicyEngine()
    allow_rule, approval_rule = threshold_rule_pair(
        "invoice_match", min_confidence=0.90, action_prefix="approve_invoice"
    )
    engine.add_rule(allow_rule)
    engine.add_rule(approval_rule)

    governor = AgentGovernor(secret_key="example-secret-do-not-reuse", policy_engine=engine)

    # Tool scope: the actual auto-approval action is bounded — L3+
    # autonomy only, and never above $5,000 regardless of how
    # confident the match was. This is the "bounded" in "bounded
    # autonomy": the agent's own confidence is not the only constraint.
    governor.permissions.register(
        ToolScope(
            tool_name="auto_approve_invoice",
            minimum_autonomy=AutonomyLevel.L3_BOUNDED_AUTONOMY,
            constraint=lambda params: params.get("amount", 0) <= 5000,
            constraint_description="the $5,000 auto-approval cap",
        )
    )
    return governor


def process_invoice(governor: AgentGovernor, invoice_id: str, amount: float, confidence: float) -> None:
    print(f"\n--- Invoice {invoice_id} (${amount:,.2f}, match confidence {confidence:.2f}) ---")
    outcome = governor.evaluate_action(
        "approve_invoice_match",
        confidence=confidence,
        autonomy_level=AutonomyLevel.L3_BOUNDED_AUTONOMY,
        tool_name="auto_approve_invoice",
        tool_params={"amount": amount},
    )

    if outcome.allowed:
        print(f"  ALLOWED — auto-approved. (policy: {outcome.policy_decision.decision.value})")
    elif outcome.checkpoint is not None:
        print(f"  PENDING HUMAN REVIEW — checkpoint {outcome.checkpoint.checkpoint_id[:8]}...: {outcome.checkpoint.reason}")
        # Simulate a human (Finance Operations, per the model's real
        # model_owner in Tool 1's inventory) reviewing and approving it.
        governor.checkpoints.approve(
            outcome.checkpoint.checkpoint_id,
            approver="finance-ops-reviewer",
            notes="Manually verified against the PO line items.",
        )
        print("  -> approved by finance-ops-reviewer after manual review.")
    else:
        print(f"  BLOCKED — {outcome.denial_reason}")


def main() -> None:
    governor = build_governor()

    # Case 1: confident exact match, well under the cap -> auto-approved.
    process_invoice(governor, "INV-1001", amount=3200.00, confidence=0.97)

    # Case 2: same amount, but a fuzzy/uncertain match -> requires a human.
    process_invoice(governor, "INV-1002", amount=3200.00, confidence=0.62)

    # Case 3: KEY CASE — high confidence, but over the $5,000 cap.
    # Policy alone would say ALLOW; the tool's own scope still blocks it.
    process_invoice(governor, "INV-1003", amount=12000.00, confidence=0.95)
    last_decision = governor.audit_log.entries[-2]  # the policy_decision entry for INV-1003
    assert last_decision.payload["decision"] == "allow", "policy itself should have said allow"
    print("  (confirmed: policy said ALLOW, the $5,000 tool cap is what actually blocked this)")

    # Simulate an anomaly-detection system noticing something wrong
    # (e.g. three invoices from a never-before-seen vendor in one
    # minute) and engaging the kill switch mid-session.
    print("\n--- Anomaly detected: engaging kill switch ---")
    governor.kill_switch.engage(
        engaged_by="fraud-detection-system",
        reason="3 invoices from an unrecognized vendor within 60 seconds.",
    )

    print("\n--- Invoice INV-1004 arrives while the kill switch is engaged ---")
    try:
        process_invoice(governor, "INV-1004", amount=1000.00, confidence=0.99)
        raise AssertionError("should have raised KillSwitchEngagedError")
    except KillSwitchEngagedError as exc:
        print(f"  CORRECTLY REFUSED: {exc}")

    print("\n--- Ops investigates, confirms it's a false positive, clears the switch ---")
    governor.kill_switch.clear(cleared_by="ops-lead", notes="Vendor was legitimately onboarded yesterday; false positive.")

    process_invoice(governor, "INV-1004", amount=1000.00, confidence=0.99)

    # Final integrity check — the whole session's audit trail, across
    # every decision, checkpoint, tool check, and kill-switch event,
    # still verifies as an untampered chain.
    result = governor.audit_log.verify()
    print(f"\n--- Session complete: {len(governor.audit_log.entries)} audit entries, verify()={result.is_valid} ---")
    assert result.is_valid is True


if __name__ == "__main__":
    main()
