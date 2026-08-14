"""
CLI entry point for AI Deployment Gates.

    governanceops-gate run path/to/ai_system.json

Exits 0 if every scenario passed (deployment approved), 1 otherwise
(deployment blocked) — the exit code is what a CI pipeline actually
acts on; the printed report is for the human reading the CI log.
"""

from __future__ import annotations

import argparse
import sys

from governanceops_agent.gate import GateConfigError, load_gate_config, run_gate


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="governanceops-gate",
        description="Run an AI system's governance configuration against declared scenarios and gate deployment on the result.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="Run a gate config and report pass/fail.")
    run_parser.add_argument("config_path", help="Path to the AI system's gate config JSON file.")
    run_parser.add_argument(
        "--quiet", action="store_true", help="Only print the final score line, not the per-scenario report."
    )

    args = parser.parse_args(argv)

    if args.command == "run":
        try:
            config = load_gate_config(args.config_path)
            report = run_gate(config)
        except GateConfigError as exc:
            print(f"Gate configuration error: {exc}", file=sys.stderr)
            return 2

        if args.quiet:
            verdict = "DEPLOYMENT APPROVED" if report.all_passed else "DEPLOYMENT BLOCKED"
            print(f"AI ASSURANCE SCORE: {report.passed_count}/{report.total_count} ({report.score}%) \u2014 {verdict}")
        else:
            print(report.render())

        return 0 if report.all_passed else 1

    return 2


if __name__ == "__main__":
    sys.exit(main())
