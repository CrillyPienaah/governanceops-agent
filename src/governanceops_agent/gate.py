"""
AI Deployment Gates — the CI/CD-style check proposed in the AI Assurance
Control Plane strategy: run a declared AI system's policy and tool-scope
configuration against a set of representative scenarios, and report
pass/fail per scenario plus an aggregate score.

Scope, stated plainly: this answers "does this AI system's governance
configuration actually behave the way its owner believes it does" — the
same question a unit test answers about a function. It does NOT run
unit tests, security scanners, or anything else a normal CI pipeline
already does; those checks belong alongside this one, not inside it.
Conflating "our governance check passed" with "the whole system is
safe to ship" would be a real overclaim — this checks one specific
thing: does the declared policy/permission setup produce the outcomes
its owner expects, for the scenarios they thought to write down.

Config format is plain JSON, not YAML — consistent with this library's
zero-runtime-dependency design; adding a YAML parser just for this one
CLI would be an inconsistent exception to that rule.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional, Union

from governanceops_agent.autonomy import AutonomyLevel
from governanceops_agent.governor import AgentGovernor
from governanceops_agent.permissions import ToolScope
from governanceops_agent.policy import PolicyEngine, block_rule, threshold_rule_pair


class GateConfigError(Exception):
    """Raised for any malformed or invalid gate configuration — an
    unknown autonomy level name, an unrecognized rule/constraint kind,
    a missing required field, or a config file that isn't valid JSON."""


def _autonomy_from_name(name: str) -> AutonomyLevel:
    try:
        return AutonomyLevel[name]
    except KeyError as exc:
        valid = ", ".join(level.name for level in AutonomyLevel)
        raise GateConfigError(f"Unknown autonomy level {name!r}. Valid values: {valid}") from exc


def _compile_constraint(spec: dict) -> tuple[Callable[[dict], bool], str]:
    """
    Compiles a declarative constraint spec into a real predicate.
    Deliberately NOT eval()/exec() of an arbitrary expression from the
    config file — this is a governance/security tool; running arbitrary
    code sourced from a JSON file an attacker could modify would defeat
    the entire point of having a gate at all. Only a small, fixed set
    of constraint kinds is supported; add more kinds here as real needs
    come up, never a general expression evaluator.
    """
    kind = spec.get("kind")
    param = spec.get("param")
    if kind == "max_param":
        limit = spec["max"]
        return (lambda params: params.get(param, 0) <= limit), f"{param} <= {limit}"
    if kind == "min_param":
        limit = spec["min"]
        return (lambda params: params.get(param, 0) >= limit), f"{param} >= {limit}"
    if kind == "equals_param":
        expected = spec["value"]
        return (lambda params: params.get(param) == expected), f"{param} == {expected!r}"
    raise GateConfigError(f"Unknown constraint kind {kind!r}. Supported: max_param, min_param, equals_param.")


@dataclass(frozen=True)
class ScenarioResult:
    name: str
    expected: str
    actual: str
    passed: bool
    detail: str


@dataclass(frozen=True)
class GateReport:
    ai_system_id: str
    ai_system_name: str
    results: list

    @property
    def passed_count(self) -> int:
        return sum(1 for r in self.results if r.passed)

    @property
    def total_count(self) -> int:
        return len(self.results)

    @property
    def score(self) -> float:
        if self.total_count == 0:
            return 100.0
        return round(100 * self.passed_count / self.total_count, 1)

    @property
    def all_passed(self) -> bool:
        return self.total_count > 0 and self.passed_count == self.total_count

    def render(self) -> str:
        lines = [f"AI System: {self.ai_system_name} ({self.ai_system_id})", ""]
        name_width = max((len(r.name) for r in self.results), default=10)
        for r in self.results:
            status = "PASS" if r.passed else "FAIL"
            lines.append(f"{r.name.ljust(name_width)}  {status}")
            if not r.passed:
                lines.append(f"  expected: {r.expected}  actual: {r.actual}")
                lines.append(f"  {r.detail}")
        lines.append("")
        lines.append("-" * (name_width + 8))
        verdict = "DEPLOYMENT APPROVED" if self.all_passed else "DEPLOYMENT BLOCKED"
        lines.append(f"AI ASSURANCE SCORE: {self.passed_count}/{self.total_count} ({self.score}%) \u2014 {verdict}")
        return "\n".join(lines)


def _build_policy_engine(rules_spec: list) -> PolicyEngine:
    engine = PolicyEngine()
    for spec in rules_spec:
        rule_type = spec.get("type")
        if rule_type == "block":
            engine.add_rule(block_rule(spec["name"], action_prefix=spec["action_prefix"], reason=spec["reason"]))
        elif rule_type == "threshold":
            minimum_autonomy = _autonomy_from_name(spec.get("minimum_autonomy", "L0_NO_AUTONOMY"))
            allow_rule, approval_rule = threshold_rule_pair(
                spec["name"],
                min_confidence=spec["min_confidence"],
                minimum_autonomy=minimum_autonomy,
                action_prefix=spec.get("action_prefix"),
            )
            engine.add_rule(allow_rule)
            engine.add_rule(approval_rule)
        else:
            raise GateConfigError(f"Unknown policy rule type {rule_type!r}. Supported: block, threshold.")
    return engine


def _build_tool_scopes(scopes_spec: list) -> list:
    scopes = []
    for spec in scopes_spec:
        constraint = None
        constraint_description = None
        if "constraint" in spec:
            constraint, constraint_description = _compile_constraint(spec["constraint"])
        scopes.append(
            ToolScope(
                tool_name=spec["tool_name"],
                minimum_autonomy=_autonomy_from_name(spec.get("minimum_autonomy", "L0_NO_AUTONOMY")),
                max_calls_per_session=spec.get("max_calls_per_session"),
                constraint=constraint,
                constraint_description=constraint_description,
            )
        )
    return scopes


def load_gate_config(path: Union[str, Path]) -> dict:
    path = Path(path)
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError as exc:
        raise GateConfigError(f"Gate config file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise GateConfigError(f"Gate config file is not valid JSON: {path} ({exc})") from exc


def run_gate(config: dict) -> GateReport:
    """
    Runs every declared scenario against a freshly-built AgentGovernor
    and reports pass/fail per scenario. A scenario PASSES if the real
    evaluate_action() outcome matches its declared `expect` (allowed /
    requires_approval / blocked), and FAILS otherwise — e.g. a scenario
    declaring `expect: blocked` for a prohibited tool call FAILS if that
    tool call actually got through, which is exactly the signal a
    deployment gate needs to catch a governance-configuration gap
    before it reaches production.
    """
    ai_system_id = config.get("ai_system_id", "UNKNOWN")
    ai_system_name = config.get("ai_system_name", "Unnamed AI System")

    policy_engine = _build_policy_engine(config.get("policy_rules", []))
    tool_scopes = _build_tool_scopes(config.get("tool_scopes", []))

    # A fresh, ephemeral secret key per gate run — this audit trail is
    # diagnostic CI output, not a durable compliance record. A real
    # runtime deployment should inject a real secret via CI/CD secrets
    # and use PersistentAuditLog if the trail itself needs to be kept —
    # see the README for that distinction.
    governor = AgentGovernor(secret_key="deployment-gate-ephemeral-key", policy_engine=policy_engine)
    for scope in tool_scopes:
        governor.permissions.register(scope)

    results = []
    for scenario in config.get("scenarios", []):
        name = scenario["name"]
        expected = scenario["expect"]
        if expected not in ("allowed", "requires_approval", "blocked"):
            raise GateConfigError(
                f"Scenario {name!r} has invalid expect={expected!r}. "
                "Must be one of: allowed, requires_approval, blocked."
            )

        autonomy_level = _autonomy_from_name(scenario.get("autonomy_level", "L0_NO_AUTONOMY"))
        outcome = governor.evaluate_action(
            action=scenario["action"],
            confidence=scenario.get("confidence", 1.0),
            autonomy_level=autonomy_level,
            tool_name=scenario.get("tool_name"),
            tool_params=scenario.get("tool_params"),
        )

        if outcome.allowed:
            actual = "allowed"
        elif outcome.checkpoint is not None:
            actual = "requires_approval"
        else:
            actual = "blocked"

        passed = actual == expected
        detail = outcome.denial_reason or outcome.policy_decision.reason
        results.append(ScenarioResult(name=name, expected=expected, actual=actual, passed=passed, detail=detail))

    return GateReport(ai_system_id=ai_system_id, ai_system_name=ai_system_name, results=results)
