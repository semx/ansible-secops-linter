# Ansible SecOps Linter

[![tests](https://github.com/semx/ansible-secops-linter/actions/workflows/tests.yml/badge.svg)](https://github.com/semx/ansible-secops-linter/actions/workflows/tests.yml)
[![codeql](https://github.com/semx/ansible-secops-linter/actions/workflows/codeql.yml/badge.svg)](https://github.com/semx/ansible-secops-linter/actions/workflows/codeql.yml)
[![gitleaks](https://github.com/semx/ansible-secops-linter/actions/workflows/gitleaks.yml/badge.svg)](https://github.com/semx/ansible-secops-linter/actions/workflows/gitleaks.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/semx/ansible-secops-linter/badge)](https://scorecard.dev/viewer/?uri=github.com/semx/ansible-secops-linter)

Security-focused static analysis for Ansible playbooks and roles.

Where a formatting linter cares about style, `ansible-secops-linter` cares about
**operational and security risk**: task patterns that leak secrets into logs,
disable TLS or host-key verification, run with unnecessary privilege, or
introduce non-idempotent, drift-prone behaviour on production hosts.

Beyond the line-level checks it follows secret variables through a play: a
password that is stored in vault and then handed to `debug`, looped over,
put on a command line or into a URL is reported at the task that prints it.
Which tasks print what was measured against ansible-core, not guessed — see
[Secret flow](#secret-flow).

It is dependency-light (only PyYAML), reports accurate line numbers, tolerates
Ansible YAML extensions such as `!vault` tags and Jinja expressions, and can
emit SARIF for GitHub code scanning.

## Checks

| ID | Severity | Detects |
| --- | --- | --- |
| `SEC001` | error | TLS certificate verification disabled (`validate_certs: false`) |
| `SEC002` | error | SSH host key verification disabled |
| `SEC003` | error | Hardcoded credential in a variable or task argument |
| `SEC004` | error | Remote script piped straight into a shell (`curl … \| bash`) |
| `SEC005` | warning | World-writable file mode |
| `SEC006` | warning | Package signature verification disabled |
| `SEC007` | warning | Module argument holds a secret without `no_log: true` |
| `SEC008` | error | Secret variable printed by `debug` |
| `SEC009` | error / note | Loop over a secret prints every item (note when `loop_control.label` is set) |
| `SEC010` | warning | Secret variable on a `command`/`shell` command line |
| `SEC011` | warning | Secret variable embedded in a `uri`/`get_url` URL |
| `SEC012` | note | Secret variable copied into a fact with `set_fact` |

Values that reference a variable, a `!vault` secret, or a `lookup()` are treated
as safe, so vault-managed secrets do not trip the hardcoded-credential rule.
Directories such as `.github/` and non-Ansible YAML (GitHub Actions workflows,
`docker-compose` files) are skipped.

## Secret flow

`SEC008`–`SEC012` answer a different question from `SEC003`: not "is a secret
written down here" but "does a secret end up in the play output". A variable
is followed as a secret when

- its name ends in `password`, `secret`, `token`, `api_key`, `secret_key`,
  `secret_access_key`, `auth_token` or `credentials` (`db_password`,
  `vault_api_token`, `aws_secret_access_key`), whether or not it is defined in
  the file — that is how vault and `group_vars` secrets are used. `passwd`,
  `private_key` and `access_key` are left out on purpose: they name `/etc/passwd`
  data, key file paths and key ids far more often than secret material, and
  names that talk about a secret rather than hold one (`users_wo_passwords`,
  `hide_passwords`, `update_password`) are excluded;
- it is assigned a `!vault` value, or a structure that contains a secret key
  (a list of users with passwords). Such a *container* is followed by attribute:
  `item.name` may go anywhere, `item.password` and `{{ item }}` may not, and
  `item.password` in a task marks the loop as secret even when the list itself
  is unknown;
- it is built from a secret with `set_fact`, or is the `register` result of a
  task whose result carries one: the command line of a command module, the URL
  of a `uri`/`get_url`, or the items of a loop. `no_log` on that task hides its
  output but not the registered value. Other module arguments are not part of
  the result, so registering a `user:` task with a password does not taint it;
- a value piped through `password_hash`, `hash`, `checksum`, `md5`, `sha1` or
  `sha256` is not a secret any more.

The sinks are the places ansible-core actually prints, measured on 2.21 and
pinned by `tests/test_ansible_verify.py`, which runs
`tests/fixtures/secret-flow.yml` against the real `ansible-playbook` and checks
every task's output for the secret:

| Where the secret goes | Printed at default verbosity | With `-v` |
| --- | --- | --- |
| `debug` `var:`/`msg:` | yes | yes |
| Loop item, no `loop_control.label` | yes, as `(item=…)` | yes |
| Loop item with `loop_control.label` | no | yes, the full item is in the result |
| `command`/`shell` argument | on failure | yes, and in the process list on the target |
| … after a `--password`-style flag | ansible blanks it | blanked, still in the process list |
| `uri`/`get_url` `url:` | on failure | on failure |
| `set_fact` value | no | yes |
| `environment:` value | no | no (`-vvv` shows it) |
| Anything under `no_log: true` | no | no |

`no_log: true` on the task (or its block or play) silences every sink;
`environment:` is the way to hand a secret to a command. A templated
`no_log: "{{ hide_passwords }}"` is resolved through the role's `defaults/` and
`vars/` (`roles/x/tasks/*.yml` → `roles/x/defaults/main.yml`); `{{ x | d(True) }}`
counts as on when `x` is unknown, and an unresolvable switch keeps the finding
with a note saying so, because role defaults for such switches are commonly
`false`.

## Install

```bash
pip install git+https://github.com/semx/ansible-secops-linter.git
```

## Usage

```bash
# Human-readable output
ansible-secops-linter lint path/to/playbooks

# SARIF for code scanning; do not fail the run on findings
ansible-secops-linter lint . --format sarif --fail-on never > results.sarif
```

`--fail-on` (`error` by default) sets the minimum severity that makes the
command exit non-zero: `error`, `warning`, `note`, or `never`.

Example on an intentionally insecure playbook:

```text
site.yml:14: error [SEC004] Remote script piped straight into a shell (remote code execution risk).
site.yml:20: error [SEC001] TLS certificate verification is disabled (validate_certs).
site.yml:25: error [SEC003] Possible hardcoded credential; use a vault-encrypted variable instead.
site.yml:36: warning [SEC005] World-writable file mode.
site.yml:44: error [SEC009] Loop over secret service_accounts without loop_control.label; every item is printed in the task output.
site.yml:50: error [SEC008] Secret vault_db_password is printed by ansible.builtin.debug; debug output is shown at every verbosity.
site.yml:57: warning [SEC011] Secret vault_inventory_token is embedded in the ansible.builtin.uri url; the URL is printed when the request fails. Send it as a header or body instead.
```

## Use as a GitHub Action

```yaml
- uses: semx/ansible-secops-linter@v0.2.0
  with:
    paths: playbooks roles
    fail-on: error
```

Upload findings to GitHub code scanning:

```yaml
- uses: semx/ansible-secops-linter@v0.2.0
  with:
    paths: .
    format: sarif
    fail-on: never
    output-file: ansible-secops.sarif
- uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: ansible-secops.sarif
```

| Input | Default | Description |
| --- | --- | --- |
| `paths` | `.` | Space-separated files or directories to scan. |
| `format` | `text` | `text` or `sarif`. |
| `fail-on` | `error` | Minimum severity that fails the action, or `never`. |
| `output-file` | `""` | Optional path to also write the output to. |

## Security & supply chain

This project runs a DevSecOps baseline in CI:

- **SAST** — CodeQL (`security-extended` query suite).
- **Secret scanning** — Gitleaks over full history, plus GitHub secret scanning.
- **Supply-chain posture** — OpenSSF Scorecard, GitHub Actions pinned to commit SHAs,
  hardened runners (`step-security/harden-runner`), least-privilege workflow tokens.
- **Dependency updates** — Dependabot.

See [SECURITY.md](SECURITY.md) for how to report a vulnerability.

## License

[MIT](LICENSE) © Sergey Sannikov
