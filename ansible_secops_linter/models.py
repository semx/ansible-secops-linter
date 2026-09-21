"""Core data types shared across the linter."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

RULES: dict[str, str] = {
    "SEC001": "TLS certificate verification disabled",
    "SEC002": "SSH host key verification disabled",
    "SEC003": "Hardcoded credential",
    "SEC004": "Remote script piped into a shell",
    "SEC005": "World-writable file mode",
    "SEC006": "Package signature verification disabled",
    "SEC007": "Secret module argument without no_log",
    "SEC008": "Secret printed by debug",
    "SEC009": "Loop over a secret prints every item",
    "SEC010": "Secret on a command line",
    "SEC011": "Secret embedded in a URL",
    "SEC012": "Secret copied into a fact",
}
"""One-line names of every rule, keyed by id; the SARIF rule catalogue."""


class Severity(StrEnum):
    """Severity of a finding, aligned with SARIF result levels."""

    ERROR = "error"
    WARNING = "warning"
    NOTE = "note"


@dataclass(frozen=True)
class Finding:
    """A single security issue detected in an Ansible file."""

    rule_id: str
    message: str
    severity: Severity
    path: str
    line: int

    def format_text(self) -> str:
        """Render the finding as a single ``path:line: LEVEL [RULE] message`` line."""
        return (
            f"{self.path}:{self.line}: {self.severity.value} "
            f"[{self.rule_id}] {self.message}"
        )
