# 0004. API Versioning and 1.0.0 Stability Contract

- **Status:** Accepted
- **Date:** 2026-10-17
- **Deciders:** Cerberus maintainers

## Context

Cerberus reaches 1.0.0, which is the point at which downstream users expect a
compatibility promise. The REST API is currently exposed under the `/api/` prefix
(for example `/api/alerts`, `/api/logs`). There is no external consumer yet, and
the frontend calls `/api/...` directly.

We needed to decide whether to version the URL path (e.g. `/api/v1/...`) and how
to define stability going forward.

## Decision

1. **Keep the unversioned `/api/` prefix** for the 1.0.0 line rather than
   relocating to `/api/v1/`.
2. **Publish an explicit compatibility contract** in
   [`docs/API_STABILITY.md`](../API_STABILITY.md) that describes what may and may
   not change within a major version.
3. **Adopt a deprecation policy** (announce → warn via headers → remove only in the
   next major version).
4. **If a future breaking change is required**, introduce `/api/v2/` and retain
   `/api/` per the deprecation policy, rather than mutating `/api/` in place.

## Consequences

### Positive

- No churn or breakage for the existing frontend and any local integrations.
- The stability promise lives in documentation that clients can rely on, which is
  the actual substance of a 1.0.0 — not a cosmetic URL segment.
- A clear, low-cost path to parallel versioning exists if and when a break is needed.

### Negative / trade-offs

- Some reviewers expect a version segment in the URL; we document and justify the
  choice here.
- Responsibility shifts to discipline: contributors must respect the contract and
  the deprecation window, backed by code review and the CHANGELOG.
