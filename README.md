# Ansible SecOps Linter

[![tests](https://github.com/semx/ansible-secops-linter/actions/workflows/tests.yml/badge.svg)](https://github.com/semx/ansible-secops-linter/actions/workflows/tests.yml)
[![codeql](https://github.com/semx/ansible-secops-linter/actions/workflows/codeql.yml/badge.svg)](https://github.com/semx/ansible-secops-linter/actions/workflows/codeql.yml)
[![gitleaks](https://github.com/semx/ansible-secops-linter/actions/workflows/gitleaks.yml/badge.svg)](https://github.com/semx/ansible-secops-linter/actions/workflows/gitleaks.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/semx/ansible-secops-linter/badge)](https://scorecard.dev/viewer/?uri=github.com/semx/ansible-secops-linter)

Security-focused static analysis for Ansible playbooks and roles.

Where a formatting linter cares about style, `ansible-secops-linter` cares about
**operational and security risk**: task patterns that leak secrets into logs,
disable TLS verification, run with unnecessary privilege, or introduce
non-idempotent, drift-prone behaviour on production hosts.

> **Status: early scaffold.** The packaging, CLI, and full DevSecOps CI/security
> pipeline are in place; the rule engine is being built out. The `lint` command
> is wired up but does not yet emit findings — see the roadmap below.

## Install

```bash
pip install git+https://github.com/semx/ansible-secops-linter.git
```

## Usage

```bash
ansible-secops-linter lint path/to/playbooks
```

## Planned checks

Each rule mirrors an upstream `ansible-lint` check or an Ansible core behaviour,
with a security lens:

- Secrets echoed to logs (missing `no_log: true` on sensitive tasks).
- Disabled TLS/host-key verification (`validate_certs: false`, `StrictHostKeyChecking=no`).
- Shell/command tasks that bypass idempotent modules.
- Over-broad `become` / privilege escalation.
- World-readable file modes on sensitive paths.
- Hardcoded credentials and tokens in vars and tasks.

## Security & supply chain

This project is developed with a DevSecOps baseline that is enforced in CI:

- **SAST** — CodeQL (`security-extended` query suite).
- **Secret scanning** — Gitleaks over full history, plus GitHub secret scanning.
- **Supply-chain posture** — OpenSSF Scorecard, GitHub Actions pinned to commit SHAs,
  hardened runners (`step-security/harden-runner`), least-privilege workflow tokens.
- **Dependency updates** — Dependabot.

See [SECURITY.md](SECURITY.md) for how to report a vulnerability.

## License

[MIT](LICENSE) © Sergey Sannikov
