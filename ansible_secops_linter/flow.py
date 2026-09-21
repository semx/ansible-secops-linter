"""Secret flow analysis: follow secret-bearing variables to the tasks that print them.

The line rules catch a secret where it is written down. This module catches the
other half of the problem: a secret that is defined safely (vault, lookup, a
variable file) and then handed to a task that prints it. Which tasks print what
was measured against ansible-core rather than guessed; see the rule messages and
``tests/test_ansible_verify.py``.

Variables are followed in file order. A variable is a *value* secret when its
name says so, when it is assigned a ``!vault`` value, when it is built from a
secret with ``set_fact``, or when it is the ``register`` result of a task whose
result carries one. It is a *container* when it holds secrets inside a structure
(a list of users with passwords): ``item.name`` is then harmless, ``item.password``
and ``{{ item }}`` are not.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from ansible_secops_linter.models import Finding, Severity
from ansible_secops_linter.rules import (
    is_secret_name,
    iter_mapping_nodes,
    mapping_has_secret_key,
    mapping_keys,
)

_JINJA_BLOCK = re.compile(r"\{[{%](.*?)[}%]\}", re.DOTALL)
# A block that hashes its input does not carry the secret out.
_HASHED = re.compile(r"\|\s*(password_hash|hash|checksum|md5|sha1|sha256)\b")
# A variable reference with its attribute chain: ``item.password`` -> ("item", ".password").
_REFERENCE = re.compile(r"(?<!\w)([A-Za-z_][A-Za-z0-9_]*)((?:\.[A-Za-z_][A-Za-z0-9_]*)*)")
_STRING_LITERAL = re.compile(r"'[^']*'|\"[^\"]*\"")
_TRUE_SCALARS = frozenset({"true", "yes", "on"})
_VAULT_TAG = "!vault"

# Task keywords that are not module names. Anything else at task level is the
# module being invoked.
_TASK_KEYWORDS = frozenset(
    {
        "action",
        "always",
        "any_errors_fatal",
        "args",
        "async",
        "become",
        "become_exe",
        "become_flags",
        "become_method",
        "become_user",
        "block",
        "changed_when",
        "check_mode",
        "collections",
        "connection",
        "debugger",
        "delay",
        "delegate_facts",
        "delegate_to",
        "diff",
        "environment",
        "failed_when",
        "ignore_errors",
        "ignore_unreachable",
        "listen",
        "local_action",
        "loop",
        "loop_control",
        "module_defaults",
        "name",
        "no_log",
        "notify",
        "poll",
        "port",
        "register",
        "remote_user",
        "rescue",
        "retries",
        "run_once",
        "tags",
        "throttle",
        "timeout",
        "until",
        "vars",
        "when",
    }
)
_LOOP_KEYWORDS = frozenset({"loop", "with_items", "with_list", "with_flattened", "with_dict"})
_TASK_LIST_KEYS = ("pre_tasks", "tasks", "post_tasks", "handlers")
_BLOCK_KEYS = ("block", "rescue", "always")

_DEBUG_MODULES = frozenset({"debug"})
_COMMAND_MODULES = frozenset({"command", "shell", "raw", "script", "win_command", "win_shell"})
_URL_MODULES = frozenset({"uri", "get_url", "win_uri", "win_get_url"})
_SET_FACT_MODULES = frozenset({"set_fact"})


_VALUE = "value"  # the variable is the secret
_CONTAINER = "container"  # a structure with secrets inside
_STRUCTURAL = {"!vault": "a !vault value", "secret key": "a value with a secret key"}


@dataclass
class _Scope:
    """Secret names by kind, the effective ``no_log`` of the scope, role variables."""

    tainted: dict[str, str] = field(default_factory=dict)
    no_log: bool = False
    variables: dict[str, str] = field(default_factory=dict)


def _short_module(name: str) -> str:
    return name.rsplit(".", 1)[-1]


def _scalar(node: yaml.Node | None) -> str | None:
    if isinstance(node, yaml.ScalarNode):
        return str(node.value)
    return None


def _is_true(node: yaml.Node | None) -> bool:
    value = _scalar(node)
    return value is not None and value.lower() in _TRUE_SCALARS


_NO_LOG_TEMPLATE = re.compile(
    r"^\{\{\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s*\|\s*(?:d|default)\(\s*(?P<fallback>[A-Za-z]+)\s*\))?\s*\}\}$"
)


def _no_log_state(node: yaml.Node | None, variables: dict[str, str]) -> tuple[bool, str]:
    """Return (no_log is on, caveat) for a ``no_log`` value.

    A literal is read as is. ``{{ var }}`` and ``{{ var | d(True) }}`` are resolved
    through ``variables`` (the role's defaults and vars); when the variable is
    unknown the fallback decides, and without one the finding stands with a
    caveat, since role defaults for such switches are commonly false.
    """
    value = _scalar(node)
    if value is None:
        return False, ""
    if value.lower() in _TRUE_SCALARS:
        return True, ""
    match = _NO_LOG_TEMPLATE.match(value.strip())
    if match is None:
        if "{{" in value:
            return False, f" no_log is {value}, so this applies when that is false."
        return False, ""
    name = match.group("name")
    if name in variables:
        return variables[name].lower() in _TRUE_SCALARS, (
            ""
            if variables[name].lower() in _TRUE_SCALARS
            else f" no_log is {value} and the role sets it to {variables[name]}."
        )
    fallback = match.group("fallback")
    if fallback is not None:
        return fallback.lower() in _TRUE_SCALARS, ""
    return False, f" no_log is {value}, so this applies when that is false."


def role_variables(path: Path) -> dict[str, str]:
    """Return the scalar defaults/vars of the role a task file belongs to, if any."""
    variables: dict[str, str] = {}
    parts = path.resolve().parts
    if "tasks" not in parts:
        return variables
    role = Path(*parts[: len(parts) - 1 - parts[::-1].index("tasks")])
    for directory in ("defaults", "vars"):
        for candidate in (role / directory / "main.yml", role / directory / "main.yaml"):
            try:
                document = yaml.compose(
                    candidate.read_text(encoding="utf-8"), Loader=yaml.SafeLoader
                )
            except (OSError, UnicodeDecodeError, yaml.YAMLError):
                continue
            if isinstance(document, yaml.MappingNode):
                for key_node, value_node in document.value:
                    key, value = _scalar(key_node), _scalar(value_node)
                    if key is not None and value is not None:
                        variables[key] = value
    return variables


def _line(node: yaml.Node) -> int:
    return node.start_mark.line + 1


def _iter_scalars(node: yaml.Node | None) -> Iterator[yaml.ScalarNode]:
    if isinstance(node, yaml.ScalarNode):
        yield node
    elif isinstance(node, yaml.MappingNode):
        for _, value in node.value:
            yield from _iter_scalars(value)
    elif isinstance(node, yaml.SequenceNode):
        for item in node.value:
            yield from _iter_scalars(item)


def _has_vault(node: yaml.Node | None) -> bool:
    return any(scalar.tag == _VAULT_TAG for scalar in _iter_scalars(node))


def _sources(text: str, bare: bool) -> list[str]:
    """Return the expression sources in ``text``: its Jinja blocks, or all of it when ``bare``.

    String literals are blanked so a path like ``"/credentials/"`` is not read as a
    name, and a block that hashes its input is dropped: no secret comes out of it.
    """
    blocks = [text] if bare else _JINJA_BLOCK.findall(text)
    return [_STRING_LITERAL.sub(" ", b) for b in blocks if not _HASHED.search(b)]


def _references(
    node: yaml.Node | None, tainted: dict[str, str], bare: bool = False
) -> dict[str, str]:
    """Return the secrets referenced under ``node``, as reason -> kind.

    A name counts when it was tainted earlier in the file or when the name itself
    says secret (``vault_db_password``, ``api_token``) — that needs no definition,
    which is how vault and group_vars secrets are used. For a container only a
    whole reference or a secret-named attribute counts (``item.password``).
    """
    found: dict[str, str] = {}
    for scalar in _iter_scalars(node):
        for source in _sources(str(scalar.value), bare):
            for name, chain in _REFERENCE.findall(source):
                attributes = chain.split(".")[1:]
                kind = tainted.get(name)
                if kind == _VALUE or (kind is None and is_secret_name(name)):
                    found[name] = _VALUE
                elif kind == _CONTAINER and not attributes:
                    found[name] = _CONTAINER
                for attribute in attributes:
                    if is_secret_name(attribute):
                        found[f"{name}.{attribute}"] = _VALUE
    return found


def _holds_secret(node: yaml.Node | None, tainted: dict[str, str]) -> dict[str, str]:
    """Return why ``node`` carries a secret: references, a ``!vault`` value, secret keys."""
    reasons = _references(node, tainted)
    if _has_vault(node):
        reasons["!vault"] = _VALUE
    if isinstance(node, yaml.MappingNode | yaml.SequenceNode):
        for mapping in iter_mapping_nodes(node):
            if mapping_has_secret_key(mapping):
                reasons["secret key"] = _CONTAINER
                break
    return reasons


def _kind(reasons: dict[str, str]) -> str:
    return _VALUE if _VALUE in reasons.values() else _CONTAINER


def _taint_vars(vars_node: yaml.Node | None, scope: _Scope) -> None:
    """Taint ``vars``/``set_fact`` entries that are or contain secrets."""
    if not isinstance(vars_node, yaml.MappingNode):
        return
    for key_node, value_node in vars_node.value:
        key = _scalar(key_node)
        if key is None:
            continue
        if is_secret_name(key):
            scope.tainted[key] = _VALUE
            continue
        reasons = _holds_secret(value_node, scope.tainted)
        if reasons:
            scope.tainted[key] = _kind(reasons)


def _module_of(keys: dict[str, yaml.Node]) -> tuple[str, yaml.Node] | None:
    for key, node in keys.items():
        if key not in _TASK_KEYWORDS and not key.startswith("with_"):
            return key, node
    return None


def _module_args(keys: dict[str, yaml.Node], module_node: yaml.Node) -> dict[str, yaml.Node]:
    args: dict[str, yaml.Node] = {}
    if isinstance(module_node, yaml.MappingNode):
        args.update(mapping_keys(module_node))
    extra = keys.get("args")
    if isinstance(extra, yaml.MappingNode):
        args.update(mapping_keys(extra))
    return args


def _loop_value(keys: dict[str, yaml.Node]) -> yaml.Node | None:
    for key, node in keys.items():
        if key in _LOOP_KEYWORDS or key.startswith("with_"):
            return node
    return None


def _loop_var(keys: dict[str, yaml.Node]) -> str:
    control = keys.get("loop_control")
    if isinstance(control, yaml.MappingNode):
        name = _scalar(mapping_keys(control).get("loop_var"))
        if name is not None:
            return name
    return "item"


def _has_loop_label(keys: dict[str, yaml.Node]) -> bool:
    control = keys.get("loop_control")
    return isinstance(control, yaml.MappingNode) and "label" in mapping_keys(control)


def _names(reasons: dict[str, str]) -> str:
    """Describe why something is a secret: variable names, or the shape of the value."""
    names = sorted(r for r in reasons if r not in _STRUCTURAL)
    shapes = sorted(_STRUCTURAL[r] for r in reasons if r in _STRUCTURAL)
    parts = [", ".join(f"'{n}'" for n in names)] if names else []
    parts.extend(shapes)
    return " and ".join(parts)


def _check_task(path: str, task: yaml.MappingNode, scope: _Scope) -> Iterator[Finding]:
    keys = mapping_keys(task)
    module = _module_of(keys)
    if module is None:
        return
    module_name, module_node = module
    short = _short_module(module_name)
    args = _module_args(keys, module_node)
    line = _line(task)
    task_no_log, caveat = _no_log_state(keys.get("no_log"), scope.variables)
    no_log = scope.no_log or task_no_log

    # Task-level vars and the loop variable are visible to this task only.
    local = _Scope(dict(scope.tainted), no_log, scope.variables)
    _taint_vars(keys.get("vars"), local)
    loop_node = _loop_value(keys)
    loop_reasons: dict[str, str] = {}
    if loop_node is not None:
        loop_reasons = _holds_secret(loop_node, local.tainted)
        loop_var = _loop_var(keys)
        # The loop variable is a secret when the list is one (a list of tokens);
        # otherwise it is a container, and ``item.password`` in the task says what
        # the items hold even when the list itself is unknown.
        loop_kind = _kind(loop_reasons) if loop_reasons else _CONTAINER
        prefix = loop_var + "."
        loop_reasons.update(
            (reason, kind)
            for reason, kind in _references(module_node, local.tainted).items()
            if reason.startswith(prefix)
        )
        if loop_reasons:
            local.tainted[loop_var] = loop_kind

    # What ends up in the registered result: the command line of a command
    # module (result.cmd), the url of a url module (result.url) and, for a loop,
    # every item (results[*].item). Other module arguments are not returned.
    in_result: dict[str, str] = dict(loop_reasons)
    if short in _COMMAND_MODULES:
        if isinstance(module_node, yaml.ScalarNode):
            in_result |= _references(module_node, local.tainted)
        for key in ("cmd", "argv", "_raw_params"):
            in_result |= _references(args.get(key), local.tainted)
    elif short in _URL_MODULES:
        in_result |= _references(args.get("url"), local.tainted)

    if not no_log:
        if loop_reasons and _has_loop_label(keys):
            yield Finding(
                "SEC009",
                f"Loop over {_names(loop_reasons)}; loop_control.label hides each "
                "item at default verbosity but -v prints it in full. Only no_log keeps "
                "it out of the output." + caveat,
                Severity.NOTE,
                path,
                line,
            )
        elif loop_reasons:
            yield Finding(
                "SEC009",
                f"Loop over {_names(loop_reasons)} without loop_control.label; "
                "every item is printed in the task output." + caveat,
                Severity.ERROR,
                path,
                line,
            )
        if short in _DEBUG_MODULES:
            shown = _references(args.get("var"), local.tainted, bare=True)
            shown |= _references(args.get("msg"), local.tainted)
            if shown:
                yield Finding(
                    "SEC008",
                    f"Secret {_names(shown)} is printed by {module_name}; "
                    "debug output is shown at every verbosity." + caveat,
                    Severity.ERROR,
                    path,
                    line,
                )
        elif short in _COMMAND_MODULES:
            on_cmdline: dict[str, str] = {}
            if isinstance(module_node, yaml.ScalarNode):
                on_cmdline = _references(module_node, local.tainted)
            for key in ("cmd", "argv", "_raw_params"):
                on_cmdline |= _references(args.get(key), local.tainted)
            if on_cmdline:
                yield Finding(
                    "SEC010",
                    f"Secret {_names(on_cmdline)} is on the {module_name} command line; "
                    "it is printed when the task fails or runs with -v (ansible masks only "
                    "the value of a --password-style flag) and is visible in the process "
                    "list on the target either way. Pass it through environment: instead." + caveat,
                    Severity.WARNING,
                    path,
                    line,
                )
        elif short in _URL_MODULES:
            in_url = _references(args.get("url"), local.tainted)
            if in_url:
                yield Finding(
                    "SEC011",
                    f"Secret {_names(in_url)} is embedded in the {module_name} url; "
                    "the URL is printed when the request fails. Send it as a header "
                    "or body instead." + caveat,
                    Severity.WARNING,
                    path,
                    line,
                )
        elif short in _SET_FACT_MODULES and isinstance(module_node, yaml.MappingNode):
            for key_node, value_node in module_node.value:
                fact = _scalar(key_node)
                reasons = _references(value_node, local.tainted)
                if fact is not None and reasons:
                    yield Finding(
                        "SEC012",
                        f"Secret {_names(reasons)} flows into fact '{fact}'; "
                        "set_fact results are printed with -v." + caveat,
                        Severity.NOTE,
                        path,
                        line,
                    )

    # Propagation outlives the task: registered results and new facts.
    if short in _SET_FACT_MODULES:
        _taint_vars(module_node, scope)
    registered = _scalar(keys.get("register"))
    if registered is not None and in_result:
        scope.tainted[registered] = _VALUE


def _check_tasks(path: str, node: yaml.Node | None, scope: _Scope) -> Iterator[Finding]:
    if not isinstance(node, yaml.SequenceNode):
        return
    for item in node.value:
        if not isinstance(item, yaml.MappingNode):
            continue
        keys = mapping_keys(item)
        if any(key in keys for key in _BLOCK_KEYS):
            block_no_log, _ = _no_log_state(keys.get("no_log"), scope.variables)
            inner = _Scope(scope.tainted, scope.no_log or block_no_log, scope.variables)
            _taint_vars(keys.get("vars"), inner)
            for key in _BLOCK_KEYS:
                yield from _check_tasks(path, keys.get(key), inner)
            continue
        yield from _check_task(path, item, scope)


def check_secret_flow(
    path: str, text: str, variables: dict[str, str] | None = None
) -> Iterator[Finding]:
    """Yield findings for secrets that reach a task that prints them.

    ``variables`` are the role's defaults and vars (see ``role_variables``), used
    to resolve a templated ``no_log``.
    """
    variables = variables or {}
    try:
        documents = list(yaml.compose_all(text, Loader=yaml.SafeLoader))
    except yaml.YAMLError:
        return
    for document in documents:
        if not isinstance(document, yaml.SequenceNode):
            continue
        plays = [
            item
            for item in document.value
            if isinstance(item, yaml.MappingNode) and "hosts" in mapping_keys(item)
        ]
        if not plays:
            # A task file (role tasks/, handlers/, an included file).
            yield from _check_tasks(path, document, _Scope(variables=variables))
            continue
        for play in plays:
            keys = mapping_keys(play)
            play_no_log, _ = _no_log_state(keys.get("no_log"), variables)
            scope = _Scope(no_log=play_no_log, variables=variables)
            _taint_vars(keys.get("vars"), scope)
            for key in _TASK_LIST_KEYS:
                yield from _check_tasks(path, keys.get(key), scope)
