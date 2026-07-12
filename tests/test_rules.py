"""Tests for the individual security rules."""

from __future__ import annotations

import textwrap
import unittest

from ansible_secops_linter.rules import check_lines, check_no_log


def rule_ids(path: str, lines: list[str]) -> list[str]:
    return [finding.rule_id for finding in check_lines(path, lines)]


class TestLineRules(unittest.TestCase):
    def test_validate_certs_false_flagged(self) -> None:
        self.assertEqual(rule_ids("p", ["    validate_certs: false"]), ["SEC001"])

    def test_validate_certs_true_clean(self) -> None:
        self.assertEqual(rule_ids("p", ["    validate_certs: true"]), [])

    def test_host_key_checking_flagged(self) -> None:
        self.assertIn("SEC002", rule_ids("p", ['  args: "-o StrictHostKeyChecking=no"']))

    def test_curl_pipe_bash_flagged(self) -> None:
        self.assertIn("SEC004", rule_ids("p", ["    shell: curl -sSL https://x/i.sh | bash"]))

    def test_hardcoded_secret_flagged(self) -> None:
        self.assertEqual(rule_ids("p", ['    db_password: "s3cr3t"']), ["SEC003"])

    def test_vault_variable_is_clean(self) -> None:
        self.assertEqual(rule_ids("p", ['    password: "{{ vault_pw }}"']), [])

    def test_update_password_is_not_a_secret(self) -> None:
        self.assertEqual(rule_ids("p", ["    update_password: always"]), [])

    def test_world_writable_mode_flagged(self) -> None:
        self.assertIn("SEC005", rule_ids("p", ['    mode: "0777"']))

    def test_safe_mode_is_clean(self) -> None:
        self.assertEqual(rule_ids("p", ['    mode: "0640"']), [])

    def test_gpg_check_disabled_flagged(self) -> None:
        self.assertIn("SEC006", rule_ids("p", ["    disable_gpg_check: true"]))

    def test_comment_lines_ignored(self) -> None:
        self.assertEqual(rule_ids("p", ["  # validate_certs: false"]), [])


class TestNoLogRule(unittest.TestCase):
    def test_secret_without_no_log_flagged(self) -> None:
        text = textwrap.dedent(
            """\
            ---
            - name: play
              hosts: all
              tasks:
                - name: create user
                  ansible.builtin.user:
                    name: app
                    password: "{{ vault_pw }}"
            """
        )
        self.assertEqual([f.rule_id for f in check_no_log("p", text)], ["SEC007"])

    def test_secret_with_no_log_is_clean(self) -> None:
        text = textwrap.dedent(
            """\
            ---
            - name: play
              hosts: all
              tasks:
                - name: create user
                  ansible.builtin.user:
                    name: app
                    password: "{{ vault_pw }}"
                  no_log: true
            """
        )
        self.assertEqual(list(check_no_log("p", text)), [])

    def test_vault_tagged_values_do_not_crash(self) -> None:
        text = textwrap.dedent(
            """\
            ---
            - name: play
              hosts: all
              vars:
                pw: !vault |
                  $ANSIBLE_VAULT;1.1;AES256
                  6638
              tasks:
                - name: create user
                  ansible.builtin.user:
                    name: app
                    password: "{{ pw }}"
                  no_log: true
            """
        )
        self.assertEqual(list(check_no_log("p", text)), [])


if __name__ == "__main__":
    unittest.main()
