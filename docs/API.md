# API Reference

Base URL: `http://<host>:8000` (local) or through the frontend proxy at `http://<host>/`.
The API is considered **stable** as of 1.0.0 — see
[API_STABILITY.md](API_STABILITY.md) for the compatibility contract.

- Interactive docs: `/docs` (Swagger UI) and `/redoc` (ReDoc).
- Interactive OpenAPI schema: `/openapi.json`.

## Authentication

Cerberus uses opaque **bearer session tokens** (not JWT). Log in to obtain a token,
then send it as `Authorization: Bearer <token>` on subsequent requests.

```bash
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"change-me"}' | jq -r .token)
```

Two roles exist: `ADMIN` (full access, including mutating endpoints) and `ANALYST`
(read-only). Mutating endpoints require `ADMIN`.

Login is rate-limited to **5 attempts per 5 minutes** per username (HTTP 429).

## Endpoints

### System

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| GET | `/health` | — | Liveness + brains loaded + signature count |
| GET | `/ready` | — | Readiness (DB + AI engine); 503 if not ready |
| GET | `/live` | — | Process liveness |
| GET | `/metrics` | — | Prometheus metrics |

`GET /health` → `200`

```json
{ "status": "ok", "ai_ready": true,
  "active_brains": ["web","auth","dos","recon","ddos","botnet","infiltration"],
  "signature_count": 30 }
```

### Authentication

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| POST | `/api/auth/login` | — | Exchange credentials for a session token |
| POST | `/api/auth/logout` | Bearer | Revoke the current session |
| GET | `/api/auth/me` | Bearer | Current session details |

`POST /api/auth/login`

```json
// request
{ "username": "admin", "password": "change-me" }
// 200 response
{ "token": "…", "username": "admin", "role": "ADMIN" }
```

Errors: `401` invalid credentials, `429` too many attempts.

### Log Ingestion

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| POST | `/api/logs` | ADMIN | Ingest one log line; returns generated alerts |
| POST | `/api/logs/batch` | ADMIN | Ingest many lines |

`POST /api/logs`

```json
// request
{ "line": "...", "source": "api" }
// 200 response
{ "source": "api", "alert_count": 1, "alerts": [ { "Type": "SQL Injection", "...": "..." } ] }
```

### Alerts & Threat Intel

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| GET | `/api/alerts` | Bearer | List alerts (`limit`, `newest_first`, `threat_type`, `source_ip`) |
| GET | `/api/threat-intel` | Bearer | Cumulative IP reputation scores |
| GET | `/api/threat-intel/mitre` | Bearer | Semantic search over MITRE ATT&CK (`q`, `top_k`) |
| GET | `/api/model-analytics` | Bearer | Per-model metrics + feature importances |

`GET /api/alerts?limit=100&threat_type=PortScan` → `200`

```json
{ "count": 1, "alerts": [ { "Type": "PortScan", "Source IP": "10.0.0.5" } ] }
```

`GET /api/threat-intel/mitre?q=credential%20dumping&top_k=3`

```json
{ "query": "credential dumping", "total_techniques": 709, "results": [ { "...": "..." } ] }
```

Returns `503` if the RAG engine is not ready.

### Active IPS

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| GET | `/api/blocked-ips` | Bearer | List blocklisted IPs |
| POST | `/api/ips/unblock` | ADMIN | Remove an IP from the blocklist |
| POST | `/api/ips/deploy-firewall` | ADMIN | Apply a host firewall drop rule |

`POST /api/ips/deploy-firewall` accepts `{ "ip": "203.0.113.7" }`. The IP is validated
against a strict IPv4 regex; invalid input returns `400`. The command is executed with
an argument list (no shell), so injection is not possible.

```json
{ "success": true, "message": "Firewall rule deployed to block 203.0.113.7", "command": "sudo iptables -A INPUT -s 203.0.113.7 -j DROP" }
```

### Multi-Agent Triage

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| POST | `/api/triage/multi-agent` | Bearer | Run the 4-agent DevSecOps pipeline |

```json
// request
{ "threat_type": "SQL Injection", "source_ip": "10.0.0.5",
  "details": "UNION SELECT in query param", "log_line": "..." }
// 200 response (shape)
{ "approved": true, "final_verdict": "…", "steps": [ { "agent": "Triage", "status": "ok", "latency_ms": 812 } ] }
```

Returns `500` if the pipeline fails.

### WebSocket

| Path | Auth | Description |
| --- | --- | --- |
| WS `/api/live-alerts` | Bearer header or `?token=` | Stream real-time detection |

Send a raw log line as a text frame; the server replies with generated alerts. Only
`ADMIN` sessions may ingest. Unauthenticated or expired sessions are closed with
policy-violation code `1008`.

## Error Format

FastAPI's standard shape:

```json
{ "detail": "Human-readable message" }
```

| Status | Meaning |
| --- | --- |
| 400 | Invalid input (e.g. malformed IPv4) |
| 401 | Missing/invalid/expired session token |
| 403 | Authenticated but lacking `ADMIN` role |
| 429 | Login rate limit exceeded |
| 500 | Unexpected server error |
| 503 | Dependency not ready (RAG engine, readiness probe) |
