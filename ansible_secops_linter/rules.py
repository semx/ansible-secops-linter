"""Security rules applied to Ansible files.

Most rules operate line by line, which keeps accurate line numbers and is robust
against Ansible's YAML extensions (``!vault`` tags, Jinja expressions). The
``no_log`` rule additionally inspects the parsed document structure.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass

import yaml

from ansible_secops_linter.models import Finding, Severity

# A value that references a variable, a vault secret, or a lookup is treated as
# safe for the "hardcoded secret" rule.
_SAFE_VALUE = re.compile(r"^(\"?\{\{|!vault|.*\|\s*password_hash|.*lookup\()", re.IGNORECASE)
_SECRET_KEY = re.compile(
    r"^[a-z0-9_]*(password|passwd|secret|token|api[_-]?key|access[_-]?key|"
    r"private[_-]?key|auth[_-]?token)[a-z0-9_]*$",
    re.IGNORECASE,
)
# Keys that match the secret pattern but do not hold secret values.
_SECRET_KEY_ALLOWLIST = frozenset(
    {"update_password", "password_hash", "password_lock", "no_log", "token_type"}
)
# Values that are Ansible keywords rather than secrets.
_VALUE_ALLOWLIST = frozenset(
    {"always", "on_create", "true", "false", "yes", "no", "present", "absent", "omit", ""}
)
_TRUE_SCALARS = frozenset({"true", "yes", "on"})


@dataclass(frozen=True)
class Rule:
    """A line-oriented rule: a compiled pattern plus metadata."""

    rule_id: str
    severity: Severity
    message: str
    pattern: re.Pattern[str]
    predicate: Callable[[re.Match[str]], bool] | None = None


def _mode_is_world_writable(match: re.Match[str]) -> bool:
    try:
        value = int(match.group("mode"), 8)
    except ValueError:
        return False
    return bool(value & 0o002) or value == 0o777


def _is_hardcoded_secret(match: re.Match[str]) -> bool:
    key = match.group("key").lower()
    raw_value = match.group("value").strip()
    value = raw_value.strip("\"'").strip()
    if key in _SECRET_KEY_ALLOWLIST or not _SECRET_KEY.match(key):
        return False
    if value.lower() in _VALUE_ALLOWLIST:
        return False
    return not _SAFE_VALUE.match(raw_value)


LINE_RULES: tuple[Rule, ...] = (
    Rule(
        "SEC001",
        Severity.ERROR,
        "TLS certificate verification is disabled (validate_certs).",
        re.compile(r"^\s*validate_certs\s*:\s*(false|no|off)\b", re.IGNORECASE),
    ),
    Rule(
        "SEC002",
        Severity.ERROR,
        "SSH host key verification is disabled.",
        re.compile(
            r"(StrictHostKeyChecking[ =]+no\b|host_key_checking\s*:\s*(false|no|off)\b)",
            re.IGNORECASE,
        ),
    ),
    Rule(
        "SEC003",
        Severity.ERROR,
        "Possible hardcoded credential; use a vault-encrypted variable instead.",
        re.compile(r"^\s*(?P<key>[A-Za-z0-9_]+)\s*:\s*(?P<value>\S.*?)\s*$"),
        _is_hardcoded_secret,
    ),
    Rule(
        "SEC004",
        Severity.ERROR,
        "Remote script piped straight into a shell (remote code execution risk).",
        re.compile(r"(curl|wget)\b.*\|\s*(sudo\s+)?(bash|sh|zsh)\b", re.IGNORECASE),
    ),
    Rule(
        "SEC005",
        Severity.WARNING,
        "World-writable file mode.",
        re.compile(r"^\s*mode\s*:\s*['\"]?0?o?(?P<mode>[0-7]{3,4})['\"]?\s*$"),
        _mode_is_world_writable,
    ),
    Rule(
        "SEC006",
        Severity.WARNING,
        "Package signature verification is disabled.",
        re.compile(
            r"(disable_gpg_check\s*:\s*(true|yes|on)\b|gpgcheck\s*:\s*(no|false|0)\b)",
            re.IGNORECASE,
        ),
    ),
)


def check_lines(path: str, lines: Sequence[str]) -> Iterator[Finding]:
    """Yield findings from every line-oriented rule."""
    for number, line in enumerate(lines, start=1):
        if line.lstrip().startswith("#"):
            continue
        for rule in LINE_RULES:
            match = rule.pattern.search(line)
            if match is None:
                continue
            if rule.predicate is not None and not rule.predicate(match):
                continue
            yield Finding(rule.rule_id, rule.message, rule.severity, path, number)


def _iter_mapping_nodes(node: yaml.Node) -> Iterator[yaml.MappingNode]:
    if isinstance(node, yaml.MappingNode):
        yield node
        for _, value_node in node.value:
            yield from _iter_mapping_nodes(value_node)
    elif isinstance(node, yaml.SequenceNode):
        for item in node.value:
            yield from _iter_mapping_nodes(item)


def _mapping_keys(node: yaml.MappingNode) -> dict[str, yaml.Node]:
    keys: dict[str, yaml.Node] = {}
    for key_node, value_node in node.value:
        if isinstance(key_node, yaml.ScalarNode):
            keys[str(key_node.value)] = value_node
    return keys


def _is_secret_key(key: str) -> bool:
    return bool(_SECRET_KEY.match(key)) and key.lower() not in _SECRET_KEY_ALLOWLIST


def _mapping_has_secret_key(node: yaml.Node) -> bool:
    if not isinstance(node, yaml.MappingNode):
        return False
    return any(
        isinstance(key_node, yaml.ScalarNode) and _is_secret_key(str(key_node.value))
        for key_node, _ in node.value
    )


def _has_sensitive_arg(keys: dict[str, yaml.Node]) -> bool:
    # Only consider secrets nested under a module key (module arguments). A task's
    # own ``name``/``no_log`` live one level up, so this avoids mistaking the
    # module-argument mapping itself for a separate task.
    return any(_mapping_has_secret_key(value_node) for value_node in keys.values())


def check_no_log(path: str, text: str) -> Iterator[Finding]:
    """Flag named tasks that handle secrets without ``no_log: true``."""
    try:
        documents = list(yaml.compose_all(text, Loader=yaml.SafeLoader))
    except yaml.YAMLError:
        return
    for document in documents:
        if document is None:
            continue
        for mapping in _iter_mapping_nodes(document):
            keys = _mapping_keys(mapping)
            if "name" not in keys or not _has_sensitive_arg(keys):
                continue
            no_log = keys.get("no_log")
            if isinstance(no_log, yaml.ScalarNode) and str(no_log.value).lower() in _TRUE_SCALARS:
                continue
            name_node = mapping.value[0][0]
            line = name_node.start_mark.line + 1
            yield Finding(
                "SEC007",
                "Task handles a secret but does not set no_log: true.",
                Severity.WARNING,
                path,
                line,
            )
