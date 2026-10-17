# Architecture Decision Records (ADRs)

This index lists the architecture decisions that shape Cerberus. Each ADR captures
the context, the decision, and its consequences.

| # | Title | Status |
| --- | --- | --- |
| [0001](0001-sqlite-wal-mode.md) | Use SQLite in WAL mode for alert storage | Accepted |
| [0002](0002-multi-agent-triage-architecture.md) | Multi-agent triage architecture | Accepted |
| [0003](0003-single-admin-authentication.md) | Single-admin authentication with fail-closed startup | Accepted |
| [0004](0004-api-versioning-and-stability.md) | API versioning and 1.0.0 stability contract | Accepted |

## Adding a new ADR

1. Copy an existing record as a template.
2. Name it `NNNN-short-title.md` (zero-padded, sequential).
3. Set a status (`Proposed`, `Accepted`, `Deprecated`, `Superseded by NNNN`).
4. Add a row to the table above.
5. Reference it from the code and/or `CHANGELOG.md` where relevant.
