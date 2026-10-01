# 3. Single-Admin Authentication & Credential Hardening

Date: 2026-09-25

## Status
Accepted

## Context
Earlier prototypes contained pre-seeded demo credentials (such as `analyst/analyst123` and default `admin/admin123`) in source code. This represented a major security vulnerability (credential stuffing, unauthorized administrative access).

## Decision
1. Purge all default and demo user accounts on initialization.
2. Require environment variables `ADMIN_USERNAME` and `ADMIN_PASSWORD` on initial deployment.
3. Hash passwords using PBKDF2-HMAC-SHA256 with 600,000 iterations (aligned with OWASP guidelines) and unique cryptographic salts.
4. Issue random 256-bit cryptographically secure session tokens stored in the database.
5. Provide backward compatibility for reboots when users are already populated in persistent storage.

## Consequences
- **Positive:** Eliminates hardcoded credentials and enforces zero-trust deployment best practices.
- **Negative:** Requires explicit environment configuration in all deployment environments (Docker, Render, GitHub Actions).
