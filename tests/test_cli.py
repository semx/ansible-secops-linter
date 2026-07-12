"""Tests for the ansible-secops-linter command line interface."""

from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from ansible_secops_linter import __version__
from ansible_secops_linter.cli import build_parser, main

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
INSECURE = str(EXAMPLES / "insecure-playbook.yml")
SECURE = str(EXAMPLES / "secure-playbook.yml")


class TestCli(unittest.TestCase):
    def test_version_is_set(self) -> None:
        self.assertTrue(__version__)

    def test_parser_parses_lint_paths(self) -> None:
        args = build_parser().parse_args(["lint", "roles", "playbooks"])
        self.assertEqual(args.command, "lint")
        self.assertEqual(args.paths, ["roles", "playbooks"])

    def test_lint_insecure_exits_nonzero(self) -> None:
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(["lint", INSECURE])
        self.assertEqual(code, 1)
        self.assertIn("SEC001", out.getvalue())

    def test_lint_secure_exits_zero(self) -> None:
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            code = main(["lint", SECURE])
        self.assertEqual(code, 0)

    def test_sarif_output_is_valid_json(self) -> None:
        out = io.StringIO()
        with redirect_stdout(out), redirect_stderr(io.StringIO()):
            main(["lint", INSECURE, "--format", "sarif"])
        document = json.loads(out.getvalue())
        self.assertEqual(document["version"], "2.1.0")

    def test_fail_on_never_exits_zero(self) -> None:
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            code = main(["lint", INSECURE, "--fail-on", "never"])
        self.assertEqual(code, 0)

    def test_no_command_returns_zero(self) -> None:
        with redirect_stdout(io.StringIO()):
            code = main([])
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
