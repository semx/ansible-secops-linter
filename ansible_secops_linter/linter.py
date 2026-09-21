"""Discovery and scanning of Ansible files."""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from pathlib import Path

from ansible_secops_linter.flow import check_secret_flow, role_variables
from ansible_secops_linter.models import Finding
from ansible_secops_linter.rules import check_lines, check_no_log

_YAML_SUFFIXES = frozenset({".yml", ".yaml"})
# Directories that never contain Ansible content but do contain YAML that would
# otherwise produce noise (CI definitions, virtualenvs, vendored code).
_EXCLUDED_DIRS = frozenset({".git", ".github", ".venv", "venv", "node_modules", ".tox"})
_NON_ANSIBLE_MARKERS = (
    re.compile(r"^jobs:\s*$", re.MULTILINE),  # GitHub Actions workflow
    re.compile(r"^services:\s*$", re.MULTILINE),  # docker-compose
)


def iter_yaml_files(paths: Iterable[str]) -> Iterator[Path]:
    """Yield every YAML file under the given files or directories, in order."""
    seen: set[Path] = set()
    for raw in paths:
        path = Path(raw)
        candidates: list[Path]
        if path.is_dir():
            candidates = sorted(
                p
                for p in path.rglob("*")
                if p.is_file()
                and p.suffix in _YAML_SUFFIXES
                and _EXCLUDED_DIRS.isdisjoint(p.parts)
            )
        elif path.is_file() and path.suffix in _YAML_SUFFIXES:
            candidates = [path]
        else:
            candidates = []
        for candidate in candidates:
            if candidate not in seen:
                seen.add(candidate)
                yield candidate


def _looks_non_ansible(text: str) -> bool:
    return any(marker.search(text) for marker in _NON_ANSIBLE_MARKERS)


def scan_file(path: Path) -> list[Finding]:
    """Return all findings for a single file."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    if _looks_non_ansible(text):
        return []
    lines = text.splitlines()
    name = path.as_posix()
    findings = list(check_lines(name, lines))
    findings.extend(check_no_log(name, text))
    findings.extend(check_secret_flow(name, text, role_variables(path)))
    findings.sort(key=lambda finding: (finding.line, finding.rule_id))
    return findings


def scan_paths(paths: Iterable[str]) -> list[Finding]:
    """Return all findings for every YAML file under the given paths."""
    findings: list[Finding] = []
    for file in iter_yaml_files(paths):
        findings.extend(scan_file(file))
    return findings
