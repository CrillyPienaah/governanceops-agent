"""
Client for GovernanceOps Inventory's runtime policy bundle endpoint —
the concrete mechanism behind "Inventory becomes the source of truth
for runtime policy": a risk officer's approved autonomy tier, permitted
tools, forbidden tools, and confidence/transaction thresholds (set in
Tool 1) become a real, machine-enforced PolicyEngine + ToolScope
configuration here in Tool 2, via one HTTP call.

Uses `urllib.request` (stdlib), not `requests`/`httpx` — consistent
with this library's zero-runtime-dependency design; this one function
needing network access to fetch a bundle doesn't justify pulling in an
HTTP client dependency the rest of the library has no other use for.

Honest limitation: `fetch_policy_bundle` was written carefully against
GovernanceOps Inventory's actual documented response shape (see
app/models/schemas.py::RuntimePolicyBundle and
app/api/routes/models.py::get_runtime_policy in the governanceops-inventory
repo) but was developed in a sandbox with no network egress to test
against a live instance. The pure mapping function
(`_policy_bundle_to_engine`) has no such limitation and is fully
tested against hand-built JSON matching that documented shape — see
tests/test_inventory_client.py. Treat the network call's first real
run (e.g. against a live GovernanceOps Inventory deployment) as real
signal, the same way this project's other live-network integrations
were before their first run.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Optional

from governanceops_agent.autonomy import AutonomyLevel
from governanceops_agent.permissions import ToolScope
from governanceops_agent.policy import PolicyEngine, block_rule, threshold_rule_pair


class InventoryClientError(Exception):
    """Raised for any failure talking to GovernanceOps Inventory, or a
    response that doesn't match the documented runtime-policy shape."""


def _autonomy_from_inventory_value(value: str) -> AutonomyLevel:
    """
    Inventory's AutonomyLevel enum uses lowercase string values
    (e.g. "l3_bounded_autonomy") matching E-23-style naming; this
    library's AutonomyLevel is an IntEnum with the same member names.
    Mapping by uppercased name, not by value, since the two enums
    deliberately don't share a value representation (str vs int) even
    though they share the same 5-level scale and meaning.
    """
    name = value.upper()
    try:
        return AutonomyLevel[name]
    except KeyError as exc:
        valid = ", ".join(level.name for level in AutonomyLevel)
        raise InventoryClientError(
            f"Inventory returned autonomy_level {value!r}, which doesn't match any "
            f"known level. Expected one of (case-insensitive): {valid}"
        ) from exc


def fetch_policy_bundle(
    inventory_base_url: str, ai_system_record_id: str, token: Optional[str] = None
) -> Optional[dict]:
    """
    GET {inventory_base_url}/models/{ai_system_record_id}/runtime-policy.
    Returns None if the model exists but has no runtime policy
    configured (Inventory's documented behavior for a model with no
    autonomy_level set — not every model in an inventory is agentic).
    Raises InventoryClientError for any connection failure, non-2xx
    response, or invalid JSON.
    """
    url = f"{inventory_base_url.rstrip('/')}/models/{ai_system_record_id}/runtime-policy"
    request = urllib.request.Request(url)
    if token:
        request.add_header("Authorization", f"Bearer {token}")

    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            raw_body = response.read().decode("utf-8")
    except urllib.error.URLError as exc:
        raise InventoryClientError(f"Could not reach GovernanceOps Inventory at {url}: {exc}") from exc

    try:
        parsed = json.loads(raw_body) if raw_body else None
    except json.JSONDecodeError as exc:
        raise InventoryClientError(f"Response from {url} was not valid JSON: {exc}") from exc

    return parsed


def build_governance_from_bundle(bundle: dict) -> tuple[PolicyEngine, list, AutonomyLevel]:
    """
    Pure mapping — no network I/O, fully unit-testable. Turns a
    RuntimePolicyBundle-shaped dict into a real PolicyEngine (forbidden
    tools become unconditional block rules; permitted tools become
    confidence-threshold rules gated at the bundle's autonomy_level)
    plus a list of ToolScope objects (permitted tools, with
    transaction_limit compiled into a max_param constraint if set).

    Order matters here the same way it matters in a hand-written
    PolicyEngine: forbidden-tool block rules are added BEFORE the
    permitted-tools threshold rules, so an action that's both
    "forbidden" and would otherwise match a permissive rule is
    correctly blocked, not shadowed — see policy.py's own docstring on
    why rule ordering is the actual precedence mechanism.
    """
    autonomy_level = _autonomy_from_inventory_value(bundle["autonomy_level"])
    confidence_threshold = bundle.get("confidence_threshold")
    transaction_limit = bundle.get("transaction_limit")

    engine = PolicyEngine()

    for tool_name in bundle.get("forbidden_tools", []):
        engine.add_rule(
            block_rule(
                f"forbidden_{tool_name}",
                action_prefix=tool_name,
                reason=f"{tool_name} is forbidden for {bundle.get('ai_system_name', 'this AI system')} per its Inventory record.",
            )
        )

    tool_scopes = []
    for tool_name in bundle.get("permitted_tools", []):
        allow_rule, approval_rule = threshold_rule_pair(
            f"permitted_{tool_name}",
            min_confidence=confidence_threshold if confidence_threshold is not None else 0.0,
            minimum_autonomy=autonomy_level,
            action_prefix=tool_name,
        )
        engine.add_rule(allow_rule)
        engine.add_rule(approval_rule)

        constraint = None
        constraint_description = None
        if transaction_limit is not None:
            limit = transaction_limit
            constraint = lambda params, limit=limit: params.get("amount", 0) <= limit
            constraint_description = f"the ${limit:,.0f} transaction limit set in Inventory"

        tool_scopes.append(
            ToolScope(
                tool_name=tool_name,
                minimum_autonomy=autonomy_level,
                constraint=constraint,
                constraint_description=constraint_description,
            )
        )

    return engine, tool_scopes, autonomy_level
