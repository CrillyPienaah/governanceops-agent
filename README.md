# GovernanceOps Agent

Runtime governance controls for agentic AI systems — autonomy tiering,
policy/confidence gating, human-in-the-loop checkpoints, scoped tool
permissions, a tamper-evident audit log, and a kill switch. This is
**Tool 2** of the GovernanceOps stack; **Tool 1**
([governanceops-inventory](../governanceops-inventory)) handles the
model-inventory/risk-tiering side. Architecture:

```
Model Inventory (Tool 1) → GovernanceOps gate → Agent Library (Tool 2, this repo)
```

An agent that graduates from a scored/passive model into something
that acts autonomously carries its `AutonomyLevel` rating across both
tools — same 5-level scale, same names, same meaning.

## Positioning: part of an AI Assurance Control Plane

This library is the **runtime enforcement** layer of a broader thesis:
governance says what should happen; assurance proves it did, automatically,
with evidence. See
[`AI_Assurance_Control_Plane_Strategy.docx`](../AI_Assurance_Control_Plane_Strategy.docx)
for the full positioning.

**AI Deployment Gates** — a CI/CD-style check that runs an AI system's
governance configuration (policy rules + tool scopes) against a set of
declared scenarios and blocks deployment if any scenario's actual
outcome doesn't match what its owner expected. Same mental model as a
test suite gating a merge, applied to governance configuration instead
of application code — a scenario declaring `expect: blocked` for a
prohibited tool call is a real regression test: if that tool call
actually goes through, the gate catches the gap before it reaches
production, not after.

```bash
pip install governanceops-agent
governanceops-gate run ai_system.json
```

```json
{
  "ai_system_id": "AI-CA-EX-000001",
  "ai_system_name": "Invoice Reconciliation Agent v1.4.0",
  "policy_rules": [
    {"type": "threshold", "name": "invoice_match", "min_confidence": 0.90,
     "minimum_autonomy": "L3_BOUNDED_AUTONOMY", "action_prefix": "approve_invoice_match"}
  ],
  "tool_scopes": [
    {"tool_name": "auto_approve_invoice", "minimum_autonomy": "L3_BOUNDED_AUTONOMY",
     "constraint": {"kind": "max_param", "param": "amount", "max": 5000}}
  ],
  "scenarios": [
    {"name": "Confident match under the cap is allowed", "action": "approve_invoice_match",
     "confidence": 0.97, "autonomy_level": "L3_BOUNDED_AUTONOMY", "tool_name": "auto_approve_invoice",
     "tool_params": {"amount": 3200}, "expect": "allowed"}
  ]
}
```

Exit code is the actual CI contract: `0` = every scenario passed
(deployment approved), `1` = at least one scenario failed (a real
governance gap — deployment blocked), `2` = the config itself is
malformed (a different failure mode a pipeline should treat
differently, e.g. failing the build with a clearer message rather than
reporting a false "governance gap"). See
[`examples/invoice_agent_gate_config.json`](examples/invoice_agent_gate_config.json)
for a complete example (including a deliberately-broken variant worth
reading to see what a caught gap actually looks like), and
[`.github/workflows/example-deployment-gate.yml`](.github/workflows/example-deployment-gate.yml)
for how another repo would wire this into CI.

A second, richer example —
[`examples/mortgage_underwriting_gate.json`](examples/mortgage_underwriting_gate.json)
— reproduces the exact "Mortgage Underwriting Agent v4.3" AI system
from the accompanying strategy document (same ID, same four tools, same
OSFI E-23 framing), 6/6 scenarios passing. Two companion misconfigured
variants demonstrate a genuinely useful distinction: removing the
account-closure block rule entirely
([`_MISCONFIGURED`](examples/mortgage_underwriting_gate_MISCONFIGURED.json))
degrades safely to `requires_approval` — the "no rule matched \u2192
default to requiring a human, never silently allow" design decision
earning its keep — while a more realistic mistake, an overly-broad
permissive rule whose prefix accidentally also matches the prohibited
action
([`_SEVERELY_MISCONFIGURED`](examples/mortgage_underwriting_gate_SEVERELY_MISCONFIGURED.json)),
genuinely allows it through. That second case is the literal
"Agent Authorization: FAIL \u2014 agent attempted a prohibited tool call"
scenario from the strategy document, reproduced and caught for real,
not just described.

**Scope, stated plainly**: this checks one specific thing — does the
declared policy/permission configuration produce the outcomes its
owner expects, for the scenarios they thought to write down. It does
not run unit tests, security scanners, or anything else a normal CI
pipeline already does; those checks belong alongside this one, not
inside it. Config format is plain JSON (not YAML) and constraints are a
small fixed set of declarative kinds (`max_param`/`min_param`/`equals_param`),
deliberately not `eval()` of an arbitrary expression from a file an
attacker could modify — see `gate.py`'s docstring for why.

## Install

```bash
pip install -e ".[dev]"   # editable install + pytest for the test suite
```

Zero runtime dependencies beyond the Python standard library —
deliberately. This library is meant to sit *underneath* whatever agent
framework a team already uses; it should never be the reason a
dependency resolution breaks.

## The six primitives

| Module | What it does | Framework mapping |
|---|---|---|
| `autonomy.py` | L0 (no autonomy) → L4 (full autonomy) tiering, mirrors Tool 1's `AutonomyLevel` | OSFI agentic bulletin, NIST AI RMF (MAP) |
| `audit_log.py` | Hash-chained, HMAC-signed audit log — tamper-evident by construction | EU AI Act Art. 12, OWASP Agentic Top 10 |
| `policy.py` | Confidence/autonomy-based gating: ALLOW / REQUIRE_APPROVAL / BLOCK | NIST AI RMF (MANAGE), OSFI agentic bulletin |
| `hitl.py` | Human-in-the-loop checkpoints with safe (blocked, not approved) expiry | EU AI Act Art. 14, OSFI agentic bulletin |
| `permissions.py` | Deny-by-default scoped tool permissions with per-call constraints | OWASP Agentic Top 10 (excessive agency), OSFI agentic bulletin |
| `kill_switch.py` | Thread-safe emergency halt with an audit trail, requires explicit human clear | EU AI Act Art. 14, OSFI agentic bulletin |
| `persistence.py` | JSONL file adapter for `AuditLog` — durable, tamper-detectable across process restarts | EU AI Act Art. 12 (retention) |
| `gate.py` / `cli.py` | AI Deployment Gates — CI/CD check gating deployment on declared scenario outcomes | OSFI agentic bulletin, OWASP Agentic Top 10 |
| `inventory_client.py` | Consumes GovernanceOps Inventory's runtime policy bundle — a risk officer's Inventory decision becomes a real, enforced `PolicyEngine`/`ToolScope` configuration here | OSFI agentic bulletin |

`governor.py`'s `AgentGovernor` wires all six together behind one
`evaluate_action()` call — the common-case front door. Every module is
also fully usable on its own if you want a different composition.
`crosswalk.py` documents which component maps to which specific
citation in the four target frameworks (see `crosswalk_for_component`
/ `crosswalk_for_framework`). `persistence.py` adds one concrete,
optional durable-storage choice — a JSONL file — for `AuditLog`, which
is otherwise deliberately storage-agnostic.

## Reference example

`examples/invoice_agent_example.py` — a simplified version of the
"Invoice Reconciliation Agent" already seeded into Tool 1's model
inventory (MDL-AGENT-0003): auto-approves confident exact-match
invoices under a dollar threshold, routes uncertain matches to a human
checkpoint, shows a tool-level cap overriding a policy ALLOW, and walks
through a full kill-switch engage/clear cycle mid-session. Every
assertion in it is a real correctness check, not just illustrative
comments — run it directly:

```bash
python examples/invoice_agent_example.py
```

## Quickstart

```python
from governanceops_agent import AgentGovernor, AutonomyLevel, PolicyEngine, threshold_rule_pair

engine = PolicyEngine()
allow_rule, approval_rule = threshold_rule_pair(
    "wire_transfer", min_confidence=0.85, action_prefix="wire_transfer"
)
engine.add_rule(allow_rule)
engine.add_rule(approval_rule)

governor = AgentGovernor(secret_key="a-real-secret-not-this-one", policy_engine=engine)

outcome = governor.evaluate_action(
    "wire_transfer_client_x",
    confidence=0.6,
    autonomy_level=AutonomyLevel.L3_BOUNDED_AUTONOMY,
)

if not outcome.allowed:
    if outcome.checkpoint:
        print(f"Waiting on human approval: {outcome.checkpoint.checkpoint_id}")
        # later, once a human decides:
        # governor.checkpoints.approve(outcome.checkpoint.checkpoint_id, approver="jane.doe")
    else:
        print(f"Blocked: {outcome.denial_reason}")
```

Scoped tool permissions layer on top of policy decisions — a policy
ALLOW doesn't override a tool's own constraint:

```python
from governanceops_agent import ToolScope

governor.permissions.register(
    ToolScope(
        tool_name="transfer_funds_tool",
        constraint=lambda params: params.get("amount", 0) <= 1000,
        constraint_description="the $1,000 transfer cap",
    )
)

outcome = governor.evaluate_action(
    "transfer_funds_big", confidence=0.9, autonomy_level=AutonomyLevel.L3_BOUNDED_AUTONOMY,
    tool_name="transfer_funds_tool", tool_params={"amount": 5000},
)
# outcome.allowed is False even though policy itself said ALLOW —
# the tool's own $1,000 cap still has the final say.
```

Emergency stop:

```python
governor.kill_switch.engage(engaged_by="ops-oncall", reason="Agent made repeated unauthorized transfers.")
# every subsequent evaluate_action() now raises KillSwitchEngagedError
# until a human explicitly clears it:
governor.kill_switch.clear(cleared_by="ops-lead", notes="Root cause fixed.")
```

Durable audit logging — inject a `PersistentAuditLog` instead of
letting `AgentGovernor` build its own in-memory `AuditLog`:

```python
from governanceops_agent import PersistentAuditLog, load_persistent_audit_log

# First run:
audit_log = PersistentAuditLog(secret_key="a-real-secret", path="audit.jsonl")
governor = AgentGovernor(audit_log=audit_log, policy_engine=engine)
# ... every evaluate_action() call now also durably writes to audit.jsonl ...

# After a process restart, re-attach to the same log:
audit_log = load_persistent_audit_log(secret_key="a-real-secret", path="audit.jsonl")
audit_log.verify()  # confirms nothing in the file was tampered with while this process was down
governor = AgentGovernor(audit_log=audit_log, policy_engine=engine)
```

Building a governor from a GovernanceOps Inventory record (Tool 1) —
the concrete mechanism behind "Inventory becomes the source of truth
for runtime policy":

```python
governor = AgentGovernor.from_governanceops(
    ai_system_record_id="<the model's record_id in Inventory>",
    inventory_base_url="https://your-inventory-instance.example.com/api/v1",
    secret_key="a-real-secret",
    inventory_token="...",  # Inventory requires auth on every route
)
# governor's PolicyEngine (forbidden tools -> block rules, permitted
# tools -> confidence-threshold rules) and ToolPermissionRegistry
# (transaction_limit -> a max_param constraint) are now built directly
# from that model's Inventory record — a risk officer's decision,
# enforced here at runtime, not just recorded there.
```

Raises `InventoryClientError` if the model has no runtime policy
configured in Inventory (`autonomy_level` unset — true for most models
in a typical inventory, which are scored/passive, not agentic) or if
Inventory can't be reached. Uses `urllib` (stdlib) for the fetch, not
`requests`/`httpx` — consistent with this library's zero-dependency
design.

**Live-verified, not just unit-tested**: `fetch_policy_bundle` was
originally written against Inventory's documented response shape in a
sandbox with no network egress, so only the pure mapping logic could
be tested at the time. It has since been verified against a real,
separately-deployed Inventory instance —
[`examples/live_inventory_roundtrip_demo.py`](examples/live_inventory_roundtrip_demo.py)
is the actual script used for that verification, not an illustrative
mockup. The real run: created a test model in a live Inventory
deployment with `forbidden_tools: ["wire_transfer"]`, confirmed the
action was blocked (with a real audit trail), then PATCHed Inventory's
`forbidden_tools`/`permitted_tools` and re-ran the *same unmodified
script* — the action was now allowed, entirely from the policy change,
with zero code touched on the agent side. That's the concrete proof
behind "Inventory becomes the source of truth for runtime policy": a
governance decision changing an agent's actual behavior over a real
network call, not a shared naming convention between two codebases.

```bash
python examples/live_inventory_roundtrip_demo.py \
    --inventory-url https://your-inventory-instance.example.com/api/v1 \
    --record-id <the model's record_id in Inventory> \
    --token <a valid bearer token> \
    --tool-name wire_transfer
```

## Design decisions worth knowing about

- **First-match rule ordering in `PolicyEngine`, not most-restrictive-wins.**
  Ordering is the visible mechanism for expressing precedence (e.g. an
  unconditional `block_rule` for wire transfers has to be added
  *before* a permissive threshold rule for the same action prefix, or
  the block gets silently shadowed). `tests/test_policy.py` includes a
  test that deliberately gets this wrong to prove the footgun is real,
  not just a documented possibility.
- **No rule matched → `REQUIRE_APPROVAL`, never `ALLOW`.** An
  unrecognized action is exactly the situation a governance layer
  exists to catch — silently allowing it through would make this
  library's presence-with-a-gap indistinguishable from its absence.
- **HITL checkpoint expiry defaults to `EXPIRED`, never `APPROVED`.**
  An unattended approval request timing out is not the same thing as
  someone approving it. This is what actually makes EU AI Act Article
  14's "technically enforced" oversight technically enforced, rather
  than a suggestion an agent could route around by nobody responding.
- **The audit log is hash-chained *and* HMAC-signed, not just
  hash-chained.** A hash chain alone only proves internal consistency;
  SHA-256 needs no secret to recompute, so anyone rewriting a whole
  log file could also just recompute every subsequent hash to match.
  The HMAC signature is what actually requires the secret key an
  attacker doesn't have. `tests/test_audit_log.py` has a test that
  specifically tampers with an entry *and* correctly recomputes its
  hash, confirming verification still fails on the signature check.
- **Deny-by-default tool permissions.** A tool with no registered
  `ToolScope` is refused, not allowed — the opposite of the more
  common software-permissions default, and deliberately so: an agent
  framework adding a new tool should require someone to decide it's in
  scope, not silently make it reachable.
- **`AgentGovernor.evaluate_action` lets `KillSwitchEngagedError`
  propagate rather than returning it as a normal "not allowed"
  outcome.** A kill switch being engaged is categorically different
  from an ordinary policy denial; a caller that only checks
  `outcome.allowed` should not be able to miss that the whole system
  is supposed to be halted.

## Test suite

```bash
pytest -v
```

85 test cases across 12 files, covering all six primitives, the
`AgentGovernor` integration, the JSONL persistence adapter, the AI
Deployment Gate (including real subprocess invocations of the actual
installed CLI, not just in-process function calls), the crosswalk
mapping, and the GovernanceOps Inventory policy-bundle integration
(`test_inventory_client.py`). Every one of these was verified by hand in the
sandbox this library was built in — this is a **zero-runtime-dependency,
pure-stdlib** library, so unlike Tool 1 (which needed careful
module-stubbing to work around missing `pydantic`/`fastapi`/etc.),
every single test here was executed for real against the actual
shipped code before delivery, including the persistence tests' real
file I/O (temp directories, a simulated process restart, tampering a
file on disk directly) and a minimal `pytest.raises`/`pytest.fixture`
shim built specifically to run the real pytest-formatted test files
(not just equivalent scratch scripts) since `pytest` itself wasn't
installed in that sandbox. The reference example
(`examples/invoice_agent_example.py`) was also actually run, twice
(before and after the persistence-related `AgentGovernor` signature
change), confirming no regression. Install `pytest` for real
(`pip install -e ".[dev]"`) to run these through the actual test
runner rather than the shim — and if you do, it's worth knowing this
library's very first run through a real `pytest` (on the machine
this was actually delivered to) also passed 49/49 clean on the first
try, before this second round of additions.

## What's NOT here

- **No integration with a specific agent framework** (LangChain,
  AutoGen, a custom loop, etc.) — this library provides the governance
  primitives; wiring `evaluate_action()` into wherever your agent
  decides its next tool call is deployment-specific and left to you.
- **No persistence layer beyond the one JSONL adapter.**
  `CheckpointStore` and `ToolPermissionRegistry` are still in-memory
  only — `persistence.py` covers `AuditLog`, since that's the one
  component where losing state on a restart is a compliance problem
  (Article 12 retention), not just an inconvenience. A real deployment
  wanting durable checkpoints/permissions would need its own adapter,
  following the same override-and-delegate shape `PersistentAuditLog`
  uses.
- **No confidence-scoring mechanism.** `PolicyEngine.evaluate()` takes
  a `confidence` float as an input — where that number comes from
  (a model's own logprobs, a separate classifier, a human's estimate)
  is entirely up to the caller.
- **This crosswalk is a mapping the library's author is asserting, not
  a compliance certification.** Using this library correctly still
  requires a human to configure policy rules, tool scopes, and
  autonomy tiers that actually match a real deployment's risk profile
  — the library provides the mechanism, not the judgment. Same
  disclaimer Tool 1's crosswalk carries, for the same reason.
