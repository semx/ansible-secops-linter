"""Core data types shared across the linter."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


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
