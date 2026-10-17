# API Stability & Versioning Policy

Cerberus follows [Semantic Versioning](https://semver.org/) (`MAJOR.MINOR.PATCH`).
Starting with **1.0.0**, the following contract applies.

## What "stable" means at 1.0.0

| Surface | Stability guarantee |
| --- | --- |
| HTTP REST endpoints under `/api/` | **Stable.** Path, method, request/response shape, and status codes will not break within a major version. |
| Health/probe endpoints (`/health`, `/ready`, `/live`) | **Stable.** Field additions are non-breaking. |
| Prometheus metric names (`/metrics`) | **Stable** names; new labels may be added. |
| WebSocket `/api/live-alerts` | **Stable** message envelope; new optional fields may be added. |
| Python API (`src.*`) | **Internal.** May change in a minor release; not covered by the public contract. |
| CLI scripts (`trainer.py`, `serve_frontend.py`) | **Stable** flags; new flags may be added. |

## Backward compatibility

Within a major version (e.g. all `1.x`), we will not:

- Remove or rename an endpoint.
- Change an endpoint's HTTP method.
- Remove a response field or change its type.
- Make a previously optional request field required.
- Change authentication/authorization requirements of an existing endpoint.

We **may** (non-breaking):

- Add new endpoints.
- Add new **optional** request fields.
- Add new response fields.
- Add new enum values where clients are expected to tolerate unknown values.

## Deprecation policy

1. A deprecated endpoint/field is announced in `CHANGELOG.md` and in the API docs.
2. Deprecated surfaces return a `Deprecation` response header with the version and,
   where possible, a `Sunset` date.
3. Deprecated surfaces remain functional for **at least one MINOR release or 90 days**,
   whichever is longer.
4. Removal only happens in the next **MAJOR** release.

## Versioning approach

Cerberus exposes the API under the stable `/api/` prefix without a path segment
(e.g. `/api/alerts`), rather than `/api/v1/...`. Rationale:

- There are no external consumers yet; a path version would add churn without benefit.
- The major version of the software *is* the API version, and the compatibility
  contract above makes that explicit.

If a future breaking change requires parallel versions, we will introduce
`/api/v2/` and keep `/api/` (then aliased to v1) alive per the deprecation policy.
The decision is recorded in
[ADR 0004](adr/0004-api-versioning-and-stability.md).

## Reporting a break

If you believe a release broke the compatibility contract, open an issue using the
bug template and tag it `compatibility`.
