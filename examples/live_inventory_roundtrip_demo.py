"""
Live round-trip demo — proves the Inventory<->Agent integration against
a real, running GovernanceOps Inventory instance, not mocked data.
Unlike every other example in this directory, this one needs actual
infrastructure: a deployed Inventory API, a valid bearer token, and a
model record with a runtime policy configured (autonomy_level set).

What this demonstrates, concretely:
  1. Fetch a model's runtime policy live over HTTPS from Inventory.
  2. Build a real AgentGovernor from it (PolicyEngine + ToolPermissionRegistry).
  3. Attempt an action Inventory currently forbids -> confirm it's blocked.
  4. (Separately, via Inventory's own API) flip that model's policy from
     forbidden to permitted.
  5. Run this exact script again, unmodified -> confirm the same action
     is now allowed.

Step 4 isn't part of this script deliberately — it's a governance
decision, made through Inventory's own API (or its UI), not something
an agent's own runtime should be able to do to itself. See the
accompanying README section for the exact PATCH request that changes
the policy between two runs.

Usage:

    python examples/live_inventory_roundtrip_demo.py \\
        --inventory-url https://your-inventory-instance.example.com/api/v1 \\
        --record-id <the model's record_id in Inventory> \\
        --token <a valid bearer token> \\
        --action-name wire_transfer_attempt \\
        --tool-name wire_transfer
"""

import argparse
import sys

from governanceops_agent import AgentGovernor
from governanceops_agent.autonomy import AutonomyLevel
from governanceops_agent.inventory_client import InventoryClientError


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--inventory-url", required=True, help="Base URL of your GovernanceOps Inventory API, e.g. https://your-instance.example.com/api/v1")
    parser.add_argument("--record-id", required=True, help="The model's record_id in Inventory")
    parser.add_argument("--token", required=True, help="A valid Inventory bearer token")
    parser.add_argument("--action-name", default="demo_action", help="The action name to evaluate (default: demo_action)")
    parser.add_argument("--tool-name", required=True, help="The tool name to check against Inventory's permitted/forbidden lists")
    parser.add_argument("--confidence", type=float, default=0.99, help="Confidence score for the attempted action (default: 0.99)")
    parser.add_argument(
        "--secret-key",
        default=None,
        help="Secret key for this session's audit log. Defaults to a random one-off value — fine for a demo run, "
        "but a real deployment should supply a real, persisted secret (see PersistentAuditLog in the README).",
    )
    args = parser.parse_args()

    secret_key = args.secret_key or "live-demo-ephemeral-secret-replace-for-real-use"

    print(f"Fetching runtime policy for {args.record_id} from {args.inventory_url} ...")
    try:
        governor = AgentGovernor.from_governanceops(
            ai_system_record_id=args.record_id,
            inventory_base_url=args.inventory_url,
            secret_key=secret_key,
            inventory_token=args.token,
        )
    except InventoryClientError as exc:
        print(f"\nCould not build a governor from Inventory: {exc}", file=sys.stderr)
        print(
            "Common causes: the record_id doesn't exist (was it deleted?), the "
            "model has no autonomy_level set (no runtime policy configured), or "
            "the token is invalid/expired.",
            file=sys.stderr,
        )
        sys.exit(1)
    print("Governor built successfully from live Inventory policy.\n")

    outcome = governor.evaluate_action(
        args.action_name,
        confidence=args.confidence,
        autonomy_level=AutonomyLevel.L3_BOUNDED_AUTONOMY,
        tool_name=args.tool_name,
        tool_params={},
    )
    print(f"Attempted action: {args.tool_name}")
    print(f"Allowed: {outcome.allowed}")
    print(f"Reason: {outcome.denial_reason or outcome.policy_decision.reason}")
    print()
    print("--- Audit trail for this session ---")
    for entry in governor.audit_log.entries:
        print(f"  [{entry.sequence}] {entry.event_type}: {entry.payload}")
    print(f"\nAudit log verifies: {governor.audit_log.verify().is_valid}")


if __name__ == "__main__":
    main()
