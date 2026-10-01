# Changelog

All notable changes to Cerberus will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

### Changed
- Replaced `print()` statements with structured logging
- Updated dependencies to latest compatible versions (Python 3.12+)
- Removed hardcoded production URL from frontend
- Added async versions of all database operations (backward compatible)

### Security
- Enforced ADMIN_PASSWORD environment variable (no default fallback)
- Added input validation for all API endpoints
- Removed shell=True from subprocess calls

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

- [ ] Version bumped in `api.py` and `frontend/package.json`
- [ ] CHANGELOG.md updated
- [ ] All tests passing
- [ ] Security scan clean
- [ ] Docker images built and tested
- [ ] Release notes drafted