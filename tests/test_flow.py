"""Tests for the secret flow rules (SEC008-SEC012)."""

from __future__ import annotations

import textwrap
import unittest

from ansible_secops_linter.flow import check_secret_flow


def flow(text: str) -> list[tuple[str, int]]:
    return [(f.rule_id, f.line) for f in check_secret_flow("p", textwrap.dedent(text))]


PLAY = """\
---
- name: play
  hosts: all
  vars:
    db_password: "{{ vault_db_password }}"
    users:
      - name: alice
        password: "{{ vault_alice }}"
  tasks:
"""


class TestDebugSink(unittest.TestCase):
    def test_debug_var_flagged(self) -> None:
        text = PLAY + """\
            - name: show it
              ansible.builtin.debug:
                var: db_password
        """
        self.assertEqual(flow(text), [("SEC008", 10)])

    def test_debug_msg_flagged(self) -> None:
        text = PLAY + """\
            - name: show it
              debug:
                msg: "pw is {{ db_password }}"
        """
        self.assertEqual(flow(text), [("SEC008", 10)])

    def test_debug_of_plain_variable_is_clean(self) -> None:
        text = PLAY + """\
            - name: show it
              ansible.builtin.debug:
                var: ansible_hostname
        """
        self.assertEqual(flow(text), [])

    def test_no_log_suppresses(self) -> None:
        text = PLAY + """\
            - name: show it
              ansible.builtin.debug:
                var: db_password
              no_log: true
        """
        self.assertEqual(flow(text), [])

    def test_secret_named_variable_needs_no_definition(self) -> None:
        text = """\
            ---
            - name: dump
              ansible.builtin.debug:
                var: vault_app_password
        """
        self.assertEqual(flow(text), [("SEC008", 2)])


class TestLoopSink(unittest.TestCase):
    def test_loop_over_secret_structure_flagged(self) -> None:
        text = PLAY + """\
            - name: create users
              ansible.builtin.user:
                name: "{{ item.name }}"
                password: "{{ item.password }}"
              loop: "{{ users }}"
        """
        self.assertEqual(flow(text), [("SEC009", 10)])

    def test_loop_label_downgrades_to_note(self) -> None:
        text = PLAY + """\
            - name: create users
              ansible.builtin.user:
                name: "{{ item.name }}"
                password: "{{ item.password }}"
              loop: "{{ users }}"
              loop_control:
                label: "{{ item.name }}"
        """
        findings = list(check_secret_flow("p", textwrap.dedent(text)))
        self.assertEqual([(f.rule_id, f.severity.value) for f in findings], [("SEC009", "note")])

    def test_loop_no_log_suppresses(self) -> None:
        text = PLAY + """\
            - name: create users
              ansible.builtin.user:
                name: "{{ item.name }}"
                password: "{{ item.password }}"
              loop: "{{ users }}"
              no_log: true
        """
        self.assertEqual(flow(text), [])

    def test_with_items_flagged(self) -> None:
        text = PLAY + """\
            - name: create users
              ansible.builtin.user:
                name: "{{ item.name }}"
              with_items: "{{ users }}"
        """
        self.assertEqual(flow(text), [("SEC009", 10)])

    def test_loop_var_is_tainted_inside_the_task(self) -> None:
        text = PLAY + """\
            - name: dump
              ansible.builtin.debug:
                msg: "{{ account.password }}"
              loop: "{{ users }}"
              loop_control:
                loop_var: account
                label: "{{ account.name }}"
        """
        self.assertEqual(flow(text), [("SEC009", 10), ("SEC008", 10)])

    def test_loop_items_revealed_by_attribute(self) -> None:
        text = """\
            ---
            - name: create users
              ansible.builtin.user:
                name: "{{ item.name }}"
                password: "{{ item.password }}"
              loop: "{{ accounts }}"
        """
        self.assertEqual(flow(text), [("SEC009", 2)])

    def test_container_item_attributes_are_told_apart(self) -> None:
        # users is a container: item.name may go anywhere, item.password may not.
        text = PLAY + """\
            - name: greet
              ansible.builtin.command: greet {{ item.name }}
              loop: "{{ users }}"
              no_log: true
            - name: leak
              ansible.builtin.command: greet {{ item.password }}
              loop: "{{ users }}"
              no_log: true
        """
        self.assertEqual(flow(text), [])
        text = PLAY + """\
            - name: leak
              ansible.builtin.command: greet {{ item.password }}
              loop: "{{ users }}"
              loop_control:
                label: "{{ item.name }}"
              no_log: false
        """
        self.assertEqual(flow(text), [("SEC009", 10), ("SEC010", 10)])

    def test_loop_over_plain_list_is_clean(self) -> None:
        text = PLAY + """\
            - name: install
              ansible.builtin.package:
                name: "{{ item }}"
              loop: [git, curl]
        """
        self.assertEqual(flow(text), [])


class TestCommandSink(unittest.TestCase):
    def test_free_form_command_flagged(self) -> None:
        text = PLAY + """\
            - name: connect
              ansible.builtin.command: mysql -p{{ db_password }}
        """
        self.assertEqual(flow(text), [("SEC010", 10)])

    def test_shell_cmd_argument_flagged(self) -> None:
        text = PLAY + """\
            - name: connect
              ansible.builtin.shell:
                cmd: mysql -p{{ db_password }}
        """
        self.assertEqual(flow(text), [("SEC010", 10)])

    def test_secret_via_environment_is_clean(self) -> None:
        text = PLAY + """\
            - name: connect
              ansible.builtin.command: mysql
              environment:
                MYSQL_PWD: "{{ db_password }}"
        """
        self.assertEqual(flow(text), [])


class TestUrlSink(unittest.TestCase):
    def test_token_in_url_flagged(self) -> None:
        text = PLAY + """\
            - name: call api
              ansible.builtin.uri:
                url: "https://api.example.com/?token={{ db_password }}"
        """
        self.assertEqual(flow(text), [("SEC011", 10)])

    def test_token_in_header_is_clean(self) -> None:
        text = PLAY + """\
            - name: call api
              ansible.builtin.uri:
                url: https://api.example.com/
                headers:
                  Authorization: "Bearer {{ db_password }}"
        """
        self.assertEqual(flow(text), [])


class TestPropagation(unittest.TestCase):
    def test_set_fact_noted_and_propagates(self) -> None:
        text = PLAY + """\
            - name: build dsn
              ansible.builtin.set_fact:
                dsn: "postgres://app:{{ db_password }}@db/app"
            - name: use dsn
              ansible.builtin.command: psql "{{ dsn }}"
        """
        self.assertEqual(flow(text), [("SEC012", 10), ("SEC010", 13)])

    def test_registered_result_is_tainted_even_with_no_log(self) -> None:
        text = PLAY + """\
            - name: login
              ansible.builtin.command: get-token --password {{ db_password }}
              register: login
              no_log: true
            - name: show token
              ansible.builtin.debug:
                var: login.stdout
        """
        self.assertEqual(flow(text), [("SEC008", 14)])

    def test_register_of_secret_argument_is_not_tainted(self) -> None:
        # Module arguments are not part of the result, so the registered value is clean.
        text = PLAY + """\
            - name: create token
              ansible.builtin.uri:
                url: https://api.example.com/token
                body:
                  password: "{{ db_password }}"
              register: response
              no_log: true
            - name: show response
              ansible.builtin.debug:
                var: response.status
        """
        self.assertEqual(flow(text), [])

    def test_register_of_a_loop_carries_the_items(self) -> None:
        text = PLAY + """\
            - name: create users
              ansible.builtin.user:
                name: "{{ item.name }}"
                password: "{{ item.password }}"
              loop: "{{ users }}"
              register: created
              no_log: true
            - name: report
              ansible.builtin.debug:
                var: created.results
        """
        self.assertEqual(flow(text), [("SEC008", 17)])

    def test_hashed_value_is_not_a_secret(self) -> None:
        text = PLAY + """\
            - name: set hash
              ansible.builtin.command: htpasswd -b users {{ db_password | password_hash('sha512') }}
        """
        self.assertEqual(flow(text), [])

    def test_vault_value_taints_any_name(self) -> None:
        text = """\
            ---
            - name: play
              hosts: all
              vars:
                greeting: !vault |
                  $ANSIBLE_VAULT;1.1;AES256
                  6638
              tasks:
                - name: dump
                  ansible.builtin.debug:
                    var: greeting
        """
        self.assertEqual(flow(text), [("SEC008", 9)])


class TestScopes(unittest.TestCase):
    def test_block_no_log_covers_its_tasks(self) -> None:
        text = PLAY + """\
            - name: secrets
              no_log: true
              block:
                - name: dump
                  ansible.builtin.debug:
                    var: db_password
        """
        self.assertEqual(flow(text), [])

    def test_block_tasks_are_checked(self) -> None:
        text = PLAY + """\
            - block:
                - name: dump
                  ansible.builtin.debug:
                    var: db_password
              rescue:
                - name: dump again
                  ansible.builtin.debug:
                    var: db_password
        """
        self.assertEqual(flow(text), [("SEC008", 11), ("SEC008", 15)])

    def test_task_file_without_play(self) -> None:
        text = """\
            ---
            - name: dump
              ansible.builtin.debug:
                var: db_password
              vars:
                db_password: "{{ lookup('env', 'DB_PASSWORD') }}"
        """
        self.assertEqual(flow(text), [("SEC008", 2)])

    def test_play_level_no_log(self) -> None:
        text = """\
            ---
            - name: play
              hosts: all
              no_log: true
              tasks:
                - name: dump
                  ansible.builtin.debug:
                    var: db_password
        """
        self.assertEqual(flow(text), [])

    def test_templated_no_log_resolved_through_role_defaults(self) -> None:
        text = PLAY + """\
            - name: dump
              ansible.builtin.debug:
                var: db_password
              no_log: "{{ hide_passwords }}"
        """
        on = list(check_secret_flow("p", textwrap.dedent(text), {"hide_passwords": "true"}))
        off = list(check_secret_flow("p", textwrap.dedent(text), {"hide_passwords": "false"}))
        unknown = list(check_secret_flow("p", textwrap.dedent(text)))
        self.assertEqual(on, [])
        self.assertEqual([f.rule_id for f in off], ["SEC008"])
        self.assertIn("the role sets it to false", off[0].message)
        self.assertIn("applies when that is false", unknown[0].message)

    def test_templated_no_log_with_default_true(self) -> None:
        text = PLAY + """\
            - name: dump
              ansible.builtin.debug:
                var: db_password
              no_log: "{{ ops__no_log | d(True) }}"
        """
        self.assertEqual(flow(text), [])

    def test_invalid_yaml_is_ignored(self) -> None:
        self.assertEqual(flow("- name: [unclosed\n"), [])


if __name__ == "__main__":
    unittest.main()
