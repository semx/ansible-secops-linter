"""Command line interface for ansible-secops-linter."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from ansible_secops_linter import __version__
from ansible_secops_linter.linter import scan_paths
from ansible_secops_linter.models import Finding, Severity
from ansible_secops_linter.sarif import to_sarif

_SEVERITY_RANK = {Severity.NOTE: 1, Severity.WARNING: 2, Severity.ERROR: 3}
_FAIL_ON_RANK = {"note": 1, "warning": 2, "error": 3, "never": 4}


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser for the ``ansible-secops-linter`` command."""
    parser = argparse.ArgumentParser(
        prog="ansible-secops-linter",
        description="Security-focused static analysis for Ansible playbooks and roles.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    subparsers = parser.add_subparsers(dest="command")

    lint = subparsers.add_parser("lint", help="Scan paths for insecure Ansible patterns.")
    lint.add_argument(
        "paths",
        nargs="*",
        default=["."],
        help="Files or directories to scan (defaults to the current directory).",
    )
    lint.add_argument(
        "--format",
        choices=("text", "sarif"),
        default="text",
        help="Output format (default: text).",
    )
    lint.add_argument(
        "--fail-on",
        choices=("error", "warning", "note", "never"),
        default="error",
        help="Minimum severity that makes the command exit non-zero (default: error).",
    )
    return parser


def _exit_code(findings: Sequence[Finding], fail_on: str) -> int:
    threshold = _FAIL_ON_RANK[fail_on]
    if threshold > _SEVERITY_RANK[Severity.ERROR]:
        return 0
    if any(_SEVERITY_RANK[finding.severity] >= threshold for finding in findings):
        return 1
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command line interface and return a process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command != "lint":
        parser.print_help()
        return 0

    findings = scan_paths(args.paths)

    if args.format == "sarif":
        print(to_sarif(findings))
    else:
        for finding in findings:
            print(finding.format_text())
        summary = f"{len(findings)} issue(s) found."
        print(summary, file=sys.stderr)

    return _exit_code(findings, args.fail_on)


if __name__ == "__main__":
    raise SystemExit(main())
