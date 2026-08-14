"""
The canonical enterprise demo — the full closed-loop assurance
lifecycle, live, against a real deployed GovernanceOps Inventory
instance:

    register -> approve policy -> deploy -> block action ->
    return evidence -> change policy -> rerun -> allow action

This is the single script meant to be shown to an actual audience
(model risk, responsible AI, internal audit, platform engineering) —
output is formatted for a human reading along, not a test log. Every
number and hash printed is real: fetched from a live Inventory
instance, not hardcoded or simulated.

Usage:

    python examples/full_lifecycle_demo.py \\
        --inventory-url https://your-instance.example.com/api/v1 \\
        --token <a valid CONTRIBUTOR-or-higher bearer token> \\
        [--cleanup]

Needs a real, running GovernanceOps Inventory instance reachable over
HTTPS, and a valid bearer token for a user with at least CONTRIBUTOR
role.
"""

import argparse
import json
import sys
import urllib.error
import urllib.request
from datetime import datetime

from governanceops_agent import AgentGovernor
from governanceops_agent.autonomy import AutonomyLevel
from governanceops_agent.inventory_client import InventoryClientError


def _api_call(method: str, url: str, token: str, body: dict = None):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Authorization", f"Bearer {token}")
    if data is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            raw = response.read().decode("utf-8")
            return json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8")
        raise RuntimeError(f"{method} {url} failed ({exc.code}): {detail}") from exc


def _header(title: str) -> None:
    print()
    print("=" * 74)
    print(title)
    print("=" * 74)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--inventory-url", required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--cleanup", action="store_true", help="Delete the demo model when finished.")
    args = parser.parse_args()

    base = args.inventory_url.rstrip("/")
    model_id = f"MDL-LIFECYCLE-DEMO-{int(datetime.now().timestamp())}"

    # ---- STEP 1: REGISTER ----
    _header("STEP 1: REGISTER — the AI system enters the inventory")
    created = _api_call("POST", f"{base}/models", args.token, {
        "model_id": model_id,
        "model_name": "Wire Transfer Agent (Lifecycle Demo)",
        "model_description": "Canonical end-to-end closed-loop assurance demonstration.",
        "model_risk_rating": "critical",
        "model_owner": "Demo",
        "model_developer": "Demo",
        "model_origin": "internally_developed",
        "model_version": "1.0",
    })
    record_id = created["record_id"]
    print(f"Registered: {created['model_name']}  ({model_id})")
    print(f"record_id:   {record_id}")
    print(f"risk_rating: {created['model_risk_rating']}")

    # ---- STEP 2: APPROVE POLICY ----
    _header("STEP 2: APPROVE POLICY — a risk officer sets the runtime boundary")
    _api_call("PATCH", f"{base}/models/{record_id}", args.token, {
        "autonomy_level": "l3_bounded_autonomy",
        "forbidden_tools": ["wire_transfer"],
        "confidence_threshold": 0.9,
    })
    policy = _api_call("GET", f"{base}/models/{record_id}/runtime-policy", args.token)
    print(f"autonomy_level:   {policy['autonomy_level']}")
    print(f"forbidden_tools:  {policy['forbidden_tools']}")
    print(f"policy_version:   {policy['policy_version']}")
    print(f"policy_hash:      {policy['policy_hash']}")

    # ---- STEP 3: DEPLOY ----
    _header("STEP 3: DEPLOY — an independent agent runtime fetches the approved policy")
    governor = AgentGovernor.from_governanceops(
        ai_system_record_id=record_id,
        inventory_base_url=args.inventory_url,
        secret_key="lifecycle-demo-ephemeral-secret-1",
        inventory_token=args.token,
    )
    print(f"Governor built from a real HTTPS fetch — no policy hand-entered on the agent side.")
    print(f"Enforcing policy_version={governor.policy_version}, policy_hash={governor.policy_hash}")

    # ---- STEP 4: BLOCK ACTION ----
    _header("STEP 4: the agent attempts the forbidden action")
    outcome = governor.evaluate_action(
        "wire_transfer_attempt_1", confidence=0.99, autonomy_level=AutonomyLevel.L3_BOUNDED_AUTONOMY,
        tool_name="wire_transfer", tool_params={},
    )
    print(f"Action: wire_transfer     Allowed: {outcome.allowed}")
    print(f"Reason: {outcome.denial_reason or outcome.policy_decision.reason}")
    if outcome.allowed is not False:
        print("\nUNEXPECTED: this action should have been blocked. Stopping.", file=sys.stderr)
        sys.exit(1)

    # ---- STEP 5: RETURN EVIDENCE ----
    _header("STEP 5: RETURN EVIDENCE — the denial is reported back to Inventory")
    entry = governor.audit_log.entries[-1]
    reported = governor.report_event(entry)
    print(f"Reported. event_id: {reported['event_id']}")
    events = _api_call("GET", f"{base}/models/{record_id}/runtime-events", args.token)
    print(f"Inventory now shows {len(events)} event(s) for this AI system:")
    for e in events:
        print(f"  - {e['event_type']}: decision={e['decision']}, policy_version={e['policy_version']}, occurred_at={e['occurred_at']}")

    # ---- STEP 6: CHANGE POLICY ----
    _header("STEP 6: CHANGE POLICY — the risk officer revises the runtime boundary")
    _api_call("PATCH", f"{base}/models/{record_id}", args.token, {
        "forbidden_tools": [],
        "permitted_tools": ["wire_transfer"],
    })
    new_policy = _api_call("GET", f"{base}/models/{record_id}/runtime-policy", args.token)
    print(f"permitted_tools:  {new_policy['permitted_tools']}")
    print(f"forbidden_tools:  {new_policy['forbidden_tools']}")
    print(f"policy_version:   {new_policy['policy_version']}  (was {policy['policy_version']})")
    print(f"policy_hash:      {new_policy['policy_hash']}")
    print(f"                  (was {policy['policy_hash']})")

    # ---- STEP 7: RERUN ----
    _header("STEP 7: RERUN — a fresh fetch picks up the revised policy")
    governor2 = AgentGovernor.from_governanceops(
        ai_system_record_id=record_id,
        inventory_base_url=args.inventory_url,
        secret_key="lifecycle-demo-ephemeral-secret-2",
        inventory_token=args.token,
    )
    print(f"New governor built. Enforcing policy_version={governor2.policy_version}, policy_hash={governor2.policy_hash}")

    # ---- STEP 8: ALLOW ACTION ----
    _header("STEP 8: the identical action is attempted again")
    outcome2 = governor2.evaluate_action(
        "wire_transfer_attempt_2", confidence=0.99, autonomy_level=AutonomyLevel.L3_BOUNDED_AUTONOMY,
        tool_name="wire_transfer", tool_params={},
    )
    print(f"Action: wire_transfer     Allowed: {outcome2.allowed}")
    print(f"Reason: {outcome2.policy_decision.reason}")
    if outcome2.allowed is not True:
        print("\nUNEXPECTED: this action should now be allowed. Stopping.", file=sys.stderr)
        sys.exit(1)

    entry2 = governor2.audit_log.entries[-1]
    governor2.report_event(entry2)
    final_events = _api_call("GET", f"{base}/models/{record_id}/runtime-events", args.token)

    # ---- SUMMARY ----
    _header("SUMMARY")
    print(f"AI System: {created['model_name']}  ({model_id})")
    print(f"Total evidenced events: {len(final_events)}\n")
    print("Full evidence chain, oldest first:")
    for e in sorted(final_events, key=lambda x: x["occurred_at"]):
        decision_display = e["decision"] or "—"
        print(f"  [{e['occurred_at']}]  {e['event_type']:<16}  decision={decision_display:<18}  policy_version={e['policy_version']}")
    print()
    print("The agent's behavior changed from BLOCKED to ALLOWED purely because")
    print("a risk officer changed a governance decision in Inventory — zero")
    print("changes to agent-side code. Every step of that transition is")
    print("evidenced, timestamped, tied to a specific policy version and hash,")
    print("and independently verifiable via GET /models/{id}/runtime-events.")

    if args.cleanup:
        _header("CLEANUP")
        _api_call("DELETE", f"{base}/models/{record_id}", args.token)
        print(f"Deleted demo model {model_id}.")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, InventoryClientError) as exc:
        print(f"\nDemo failed: {exc}", file=sys.stderr)
        sys.exit(1)
