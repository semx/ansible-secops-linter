"""Check the secret flow rules against what ansible-core actually prints.

``tests/fixtures/secret-flow.yml`` names every task after the behaviour it has
in ansible-core: ``(leaks)`` when the secret shows up at default verbosity,
``(leaks -v)`` when it takes ``-v``, ``(masked)`` when ansible blanks it in the
output although it is still handed to the target, ``(clean)`` when it never
shows. The play is run twice with the secret passed as an extra variable, its
output is split per task, and the two sides are compared: the linter must flag
exactly the tasks that are not clean, and every leaking task must really print
the secret.

Skipped when ``ansible-playbook`` is not installed.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import unittest
from pathlib import Path

import yaml

from ansible_secops_linter.flow import check_secret_flow

FIXTURE = Path(__file__).parent / "fixtures" / "secret-flow.yml"
SECRET = "Hunter2-4f9d2c-not-for-logs"
_TASK_HEADER = re.compile(r"^TASK \[(?P<name>.*?)\] \**$", re.MULTILINE)


def _run_play(verbosity: int) -> dict[str, str]:
    """Run the fixture and return each task's output keyed by task name."""
    env = {
        **os.environ,
        "ANSIBLE_NOCOLOR": "1",
        "ANSIBLE_STDOUT_CALLBACK": "default",
        "ANSIBLE_LOCALHOST_WARNING": "false",
        "ANSIBLE_HOST_KEY_CHECKING": "false",
    }
    command = [
        "ansible-playbook",
        "-i",
        "localhost,",
        "-e",
        f"secret={SECRET}",
        str(FIXTURE),
    ]
    if verbosity:
        command.append("-" + "v" * verbosity)
    completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
        command, capture_output=True, text=True, env=env, check=False, timeout=300
    )
    output = completed.stdout + completed.stderr
    sections: dict[str, str] = {}
    matches = list(_TASK_HEADER.finditer(output))
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(output)
        sections[match.group("name")] = output[match.end() : end]
    return sections


def _expectation(name: str) -> str:
    """Return the behaviour a fixture task name declares: leaks, leaks -v, masked, clean."""
    return name[name.rindex("(") + 1 : -1]


def _task_names_by_line() -> dict[int, str]:
    """Map the line of every task in the fixture to its name."""
    document = yaml.compose(FIXTURE.read_text(encoding="utf-8"), Loader=yaml.SafeLoader)
    names: dict[int, str] = {}
    for play in document.value:
        for key_node, value_node in play.value:
            if key_node.value != "tasks":
                continue
            for task in value_node.value:
                for task_key, task_value in task.value:
                    if task_key.value == "name":
                        names[task.start_mark.line + 1] = str(task_value.value)
    return names


@unittest.skipUnless(shutil.which("ansible-playbook"), "ansible-playbook is not installed")
class TestAgainstAnsibleCore(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.names = _task_names_by_line()
        cls.default = _run_play(0)
        cls.verbose = _run_play(1)
        if set(cls.default) != set(cls.names.values()):
            raise AssertionError(f"not every fixture task ran: {sorted(cls.default)}")

    def test_linter_flags_exactly_the_unsafe_tasks(self) -> None:
        flagged = {
            self.names[finding.line]
            for finding in check_secret_flow(str(FIXTURE), FIXTURE.read_text(encoding="utf-8"))
        }
        expected = {name for name in self.names.values() if _expectation(name) != "clean"}
        self.assertEqual(flagged, expected)

    def test_default_verbosity_prints_exactly_the_leaking_tasks(self) -> None:
        for name, output in self.default.items():
            with self.subTest(task=name):
                self.assertEqual(SECRET in output, _expectation(name) == "leaks")

    def test_dash_v_prints_the_leaks_v_tasks_too(self) -> None:
        for name, output in self.verbose.items():
            with self.subTest(task=name):
                self.assertEqual(SECRET in output, _expectation(name) in {"leaks", "leaks -v"})


if __name__ == "__main__":
    unittest.main()
