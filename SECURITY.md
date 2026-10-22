# Security Policy

Cerberus is a security product, so we hold it — and its supply chain — to a high bar.
This document explains which versions are supported and how to report a vulnerability
responsibly.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| 0.5.x   | :x: (upgrade to 1.0.x) |
| < 0.5   | :x:                |

Only the latest 1.0.x release receives security fixes. Pre-1.0 releases are
unsupported; please upgrade.

## Reporting a Vulnerability

**Please do not open a public issue for security problems.**

Report privately using one of:

1. **GitHub Private Vulnerability Reporting** — open the repository's
   **Security → Report a vulnerability** tab (preferred).
2. **Email** — `guptaaikagra365@gmail.com` with the subject `[SECURITY] Cerberus`.

Include as much of the following as you can:

- Affected version(s) and component (API, detection engine, agent pipeline, frontend).
- A clear description and, ideally, a minimal proof of concept.
- Reproduction steps and any relevant logs (redact secrets).
- Impact assessment (what an attacker could achieve).
- Any suggested remediation.

### What to expect

| Stage | Target |
| --- | --- |
| Acknowledgement of report | within 3 business days |
| Initial triage / severity assessment | within 7 business days |
| Fix or mitigation plan | within 30 days (severity-dependent) |
| Public disclosure | coordinated with you after a fix ships |

We will credit reporters in the release notes unless you prefer to stay anonymous.

## Scope

**In scope**

- The FastAPI backend (`api.py`) and `src/` package.
- The multi-agent pipeline and guardrail logic.
- Authentication, session, and RBAC handling.
- The SQLite persistence layer and query construction.
- Firewall/IPS command execution paths.
- The container images and CI/CD workflows.

**Out of scope**

- The CIC-IDS2017 dataset, which ships only for training and is not part of the runtime.
- Denial of service via resource exhaustion on a single local deployment.
- Issues requiring a pre-compromised host or elevated local access.
- Third-party services (NVIDIA NIM, hosting providers).

## Security Design Notes

Cerberus is built defensively. Notable controls:

- **Fail-closed startup** — the API refuses to start unless `ADMIN_USERNAME` and
  `ADMIN_PASSWORD` are set; no default credentials are ever created (see
  [ADR 0003](docs/adr/0003-single-admin-authentication.md)).
- **No `shell=True`** — firewall/IPs operations use argument lists; attacker-supplied
  IPs are validated against a strict IPv4 regex before use.
- **Parameterized SQL** — all database access uses bound parameters; SQLite runs in WAL mode.
- **RBAC** — mutating endpoints require the `ADMIN` role; read endpoints require an
  authenticated session.
- **Session tokens & rate limiting** — bearer sessions with expiry, and login throttling
  (5 attempts / 5 minutes) to blunt brute force.
- **Non-root container** — the backend image runs as UID `10001` with no shell access.
- **Supply chain** — `bandit`, `pip-audit`, `safety`, and Dependabot run continuously;
  CI builds images and health-checks the container before deploy.

## Hardening Checklist for Operators

- [ ] Set a strong `ADMIN_PASSWORD`; never reuse it elsewhere.
- [ ] Terminate TLS at a reverse proxy (see [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)).
- [ ] Keep the container image pinned to a released tag; do not use `latest` in production.
- [ ] Restrict network exposure of port 8000 to the proxy/host that needs it.
- [ ] Rotate LLM provider API keys and store them in a secret manager, not in `.env` in VCS.
- [ ] Monitor `/metrics` and alert on auth failures and IPS block events.
