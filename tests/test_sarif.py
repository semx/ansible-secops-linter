"""Tests for the SARIF serializer."""

from __future__ import annotations

import json
import unittest

from ansible_secops_linter.models import Finding, Severity
from ansible_secops_linter.sarif import to_sarif


class TestSarif(unittest.TestCase):
    def test_document_structure(self) -> None:
        findings = [Finding("SEC001", "TLS off", Severity.ERROR, "play.yml", 3)]
        document = json.loads(to_sarif(findings))

        self.assertEqual(document["version"], "2.1.0")
        run = document["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "ansible-secops-linter")

        result = run["results"][0]
        self.assertEqual(result["ruleId"], "SEC001")
        self.assertEqual(result["level"], "error")
        location = result["locations"][0]["physicalLocation"]
        self.assertEqual(location["artifactLocation"]["uri"], "play.yml")
        self.assertEqual(location["region"]["startLine"], 3)

    def test_empty_findings(self) -> None:
        document = json.loads(to_sarif([]))
        self.assertEqual(document["runs"][0]["results"], [])


if __name__ == "__main__":
    unittest.main()
