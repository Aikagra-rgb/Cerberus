# 1. Use SQLite with Write-Ahead Logging (WAL) Mode

Date: 2026-05-23

## Status
Accepted

## Context
Cerberus operates as an intrusion prevention system (IPS) and Security Operations Center (SOC) backend. It needs persistent storage for security alerts, IP blocklists, reputation caching, and user sessions. Initially, the project used flat CSV files (`hids_alerts.csv`), which led to concurrency locks, corruption risks, and lack of relational query capabilities.

## Decision
We adopted SQLite as the default relational storage engine configured with:
1. `PRAGMA journal_mode=WAL` (Write-Ahead Logging) to allow concurrent readers while a write is occurring.
2. Synchronous fallback for legacy operations and `aiosqlite` for asynchronous FastAPI endpoints.
3. Automated database indexing on high-frequency query fields (`timestamp`, `threat_type`, `source_ip`, `token`).

## Consequences
- **Positive:** Zero infrastructure overhead, self-contained single-file deployment, embedded in Docker container without requiring external database provisioning.
- **Negative:** Horizontal scaling across multiple replica instances is limited by SQLite's single-writer model. If multi-instance active-active clustering is required in the future, a migration to PostgreSQL will be required.
