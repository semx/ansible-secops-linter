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
| `SEC007` | warning | Task handles a secret without `no_log: true` |

Values that reference a variable, a `!vault` secret, or a `lookup()` are treated
as safe, so vault-managed secrets do not trip the hardcoded-credential rule.
Directories such as `.github/` and non-Ansible YAML (GitHub Actions workflows,
`docker-compose` files) are skipped.

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
site.yml:11: error [SEC004] Remote script piped straight into a shell (remote code execution risk).
site.yml:17: error [SEC001] TLS certificate verification is disabled (validate_certs).
site.yml:22: error [SEC003] Possible hardcoded credential; use a vault-encrypted variable instead.
site.yml:33: warning [SEC005] World-writable file mode.
```

## Use as a GitHub Action

```yaml
- uses: semx/ansible-secops-linter@v0.1.0
  with:
    paths: playbooks roles
    fail-on: error
```

Upload findings to GitHub code scanning:

```yaml
- uses: semx/ansible-secops-linter@v0.1.0
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
