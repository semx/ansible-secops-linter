"""Integration tests that run the linter against the bundled example playbooks."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ansible_secops_linter.linter import scan_file, scan_paths

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


class TestLinterOnExamples(unittest.TestCase):
    def test_insecure_playbook_triggers_every_rule(self) -> None:
        findings = scan_file(EXAMPLES / "insecure-playbook.yml")
        rule_ids = {finding.rule_id for finding in findings}
        self.assertEqual(
            rule_ids,
            {"SEC001", "SEC002", "SEC003", "SEC004", "SEC005", "SEC006", "SEC007"},
        )

    def test_secure_playbook_is_clean(self) -> None:
        self.assertEqual(scan_file(EXAMPLES / "secure-playbook.yml"), [])

    def test_scan_directory_collects_findings(self) -> None:
        findings = scan_paths([str(EXAMPLES)])
        self.assertTrue(findings)
        self.assertTrue(all(f.line >= 1 for f in findings))

    def test_github_workflows_are_excluded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workflows = Path(directory) / ".github" / "workflows"
            workflows.mkdir(parents=True)
            (workflows / "ci.yml").write_text(
                "jobs:\n  build:\n    env:\n      api_token: hunter2\n",
                encoding="utf-8",
            )
            self.assertEqual(scan_paths([str(directory)]), [])

    def test_non_ansible_yaml_is_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            compose = Path(directory) / "docker-compose.yml"
            compose.write_text(
                "services:\n  db:\n    environment:\n      db_password: hunter2\n",
                encoding="utf-8",
            )
            self.assertEqual(scan_file(compose), [])


if __name__ == "__main__":
    unittest.main()
