"""SARIF 2.1.0 serialization of findings, for GitHub code scanning."""

from __future__ import annotations

import json
from collections.abc import Sequence

from ansible_secops_linter import __version__
from ansible_secops_linter.models import RULES, Finding

_INFORMATION_URI = "https://github.com/semx/ansible-secops-linter"


def to_sarif(findings: Sequence[Finding]) -> str:
    """Serialize findings as a SARIF 2.1.0 document."""
    rules: dict[str, dict[str, object]] = {}
    results: list[dict[str, object]] = []

    for finding in findings:
        rules.setdefault(
            finding.rule_id,
            {
                "id": finding.rule_id,
                "name": finding.rule_id,
                "shortDescription": {"text": RULES.get(finding.rule_id, finding.message)},
                "defaultConfiguration": {"level": finding.severity.value},
            },
        )
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": finding.severity.value,
                "message": {"text": finding.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.path},
                            "region": {"startLine": max(finding.line, 1)},
                        }
                    }
                ],
            }
        )

    document: dict[str, object] = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ansible-secops-linter",
                        "informationUri": _INFORMATION_URI,
                        "version": __version__,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(document, indent=2)
