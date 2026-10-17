# Changelog

All notable changes to Cerberus will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-10-17

First stable release. Cerberus graduates from beta to a production-ready 1.0.0 with a
documented API-stability contract, a security policy, deployment guidance, release
automation, and a substantially expanded test suite.

### Added
- Architecture, deployment, API, and API-stability documentation (`docs/`)
- `SECURITY.md` with supported versions, private disclosure process, and operator hardening checklist
- `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1) — previously referenced but missing
- GitHub issue templates, a pull-request template, and Dependabot configuration
- Release workflow (`.github/workflows/release.yml`): tags matching `v*` build and publish
  backend/frontend images to GHCR and create a GitHub Release
- [ADR 0004](docs/adr/0004-api-versioning-and-stability.md) (API versioning and stability
  contract) and an [ADR index](docs/adr/README.md)
- Container healthchecks for backend (`/health`) and frontend, with startup ordering
  (`frontend` waits for `backend: service_healthy`)
- Expanded test suite: API endpoints and WebSocket auth, detection service (sync + async),
  alert store (sync + async reputation/IPS/session lifecycle), and the real-log parser
  (34 → 100 tests; coverage 61% → 87%)

### Changed
- Version bumped to **1.0.0** in `pyproject.toml`, `api.py`, and `frontend/package.json`
- Development status promoted to **Production/Stable**
- Packaging metadata migrated to PEP 639 (`license = "MIT"`, `license-files`)
- Unified test-coverage gate at **70%** across CI, `Makefile`, and `CONTRIBUTING.md`
- Rewrote `README.md` for 1.0.0 (architecture, API, deployment, security, stability)
- CI runs now cancel superseded runs on the same ref

### Fixed
- Coverage-threshold inconsistency (CI 55% / Makefile 45% / CONTRIBUTING 70%) unified at 70%
- `CONTRIBUTING.md` release steps now include `pyproject.toml`
- Removed the obsolete `version` attribute from `docker-compose.yml`
- `.dockerignore` now excludes CIC-IDS2017 training CSVs (Docker build context ~912 MB → ~70 MB)

### Security
- Documented security policy and coordinated-disclosure process (`SECURITY.md`)
- Health-gated container startup reduces the window where the frontend proxies to an unready backend

## [0.5.0] - 2026-10-17

### Added
- Structured JSON logging with structlog
- Prometheus metrics endpoint (`/metrics`)
- Kubernetes readiness (`/ready`) and liveness (`/live`) probes
- Async database operations with aiosqlite
- GitHub Actions CI/CD pipeline
- Pre-commit hooks (ruff, mypy, bandit, pip-audit)
- Dependency locking with pip-tools
- Nginx-based frontend container
- Contributing guidelines and Code of Conduct
- Configuration via meta tags for frontend API URL
- Architecture Decision Records (ADRs) documenting key design choices (`docs/adr/`)
- `.env.example` environment configuration template
- End-to-end attack simulation test suite (`attack_simulation_test.py`)

### Changed
- Replaced `print()` statements with structured logging
- Updated dependencies to latest compatible versions (Python 3.12+)
- Removed hardcoded production URL from frontend
- Added async versions of all database operations (backward compatible)

### Security
- Enforced `ADMIN_USERNAME` and `ADMIN_PASSWORD` environment variables (fail-closed: no default credentials)
- Added input validation for all API endpoints
- Removed shell=True from subprocess calls

### Fixed
- Added missing `LICENSE` file (MIT)
- Corrected README quick-start entry point to `python -m uvicorn api:app`

## [0.4.0] - 2026-01-15

### Added
- Multi-agent DevSecOps pipeline (Triage → Research → Remediation → Guardrail)
- MITRE ATT&CK RAG engine (709 techniques, TF-IDF retrieval)
- NVIDIA NIM integration (DeepSeek V4 Pro, Nemotron-70B)
- Active IPS gatekeeper with auto-blocking at reputation ≥100
- OS-level firewall deployment (iptables/PowerShell)
- 3D WebGL frontend with Three.js
- RBAC with Admin/Analyst roles
- 7 AI brains trained on CIC-IDS2017 datasets
- Signature-based detection (30+ rules)

### Changed
- Migrated from CSV to SQLite with WAL mode
- Unified 20-feature vector across all models

### Fixed
- Command injection prevention in firewall deployment
- Session token expiration handling
- Rate limiting on login attempts

## [0.3.0] - 2025-11-01

### Added
- Random Forest classifiers for 7 attack types
- Feature extractor for CIC-IDS2017 flow data
- WebSocket live alerts stream
- Model analytics dashboard
- Batch log ingestion endpoint

### Changed
- Refactored detection pipeline (Signature → AI → IPS)

## [0.2.0] - 2025-09-15

### Added
- Basic FastAPI backend
- SQLite alert storage
- JWT-like session authentication
- Signature-based detection engine

## [0.1.0] - 2025-08-01

### Added
- Initial proof of concept
- Log monitoring daemon
- File integrity monitoring (FIM)
- Basic web dashboard

---

## Release Checklist

### 1.0.0
- [x] Version bumped to `1.0.0` in `pyproject.toml`, `api.py`, and `frontend/package.json`
- [x] CHANGELOG.md updated
- [x] All tests passing (100/100) with coverage above the 70% gate (87%)
- [x] Lint, type, and security checks clean (ruff, mypy, bandit: 0 high/medium findings)
- [x] Test-coverage gate unified at 70% across CI, `Makefile`, and `CONTRIBUTING.md`
- [x] Docker images built and tested (backend + frontend; full stack verified via `docker compose up`)
- [x] Documentation complete (architecture, deployment, API, stability, security policy, ADRs)
- [x] Release automation in place (`.github/workflows/release.yml`, Dependabot, templates)
- [x] Release notes drafted (see `[1.0.0]` above)