# Deployment Guide

Cerberus runs as two containers — a FastAPI backend and an nginx-served 3D console —
or as two local processes for development.

## Prerequisites

- Docker Engine 24+ with Compose v2 (`docker compose`), **or**
- Python 3.11–3.13 for a local (non-container) run.
- Outbound HTTPS access to NVIDIA NIM if you use the multi-agent pipeline.
- ~2 GB RAM (the backend loads ten ML pipelines at startup).

## Configuration

All configuration is read from environment variables (and `.env`). Copy the template
and fill it in:

```bash
cp .env.example .env
```

| Variable | Required | Default | Purpose |
| --- | --- | --- | --- |
| `ADMIN_USERNAME` | **yes** | — | Admin account created on first startup |
| `ADMIN_PASSWORD` | **yes** | — | Admin password (no default; API refuses to start without it) |
| `NVIDIA_BASE_URL` | no | `https://integrate.api.nvidia.com/v1` | LLM provider base URL |
| `NEMOTRON_API_KEY` | for agents | — | Key for the Remediation agent |
| `DEEPSEEK_API_KEY` | for agents | — | Key for Triage/Research/Guardrail agents |
| `NEMOTRON_MODEL` | no | `nvidia/llama-3.1-nemotron-70b-instruct` | Model id |
| `DEEPSEEK_MODEL` | no | `deepseek-ai/deepseek-v4-0324` | Model id |
| `AGENT_TIMEOUT_SECONDS` | no | `30` | Per-agent timeout (1–180) |
| `MITRE_DATA_PATH` | no | `data/mitre_attack.json` | RAG knowledge base |
| `RAG_TOP_K` | no | `5` | Techniques retrieved per query (1–20) |
| `LOG_LEVEL` | no | `INFO` | Logging level |
| `LOG_JSON` | no | `0` | Emit JSON logs |
| `LOG_FILE` | no | — | Optional rotating log file |
| `ALLOWED_ORIGINS` | no | — | Extra comma-separated CORS origins |
| `VERCEL_DOMAINS` | no | — | Extra allowed frontend domains |

> **Never commit `.env`.** It is git-ignored. In production, inject secrets from a
> secret manager rather than a file.

## Option A — Docker Compose (recommended)

```bash
cp .env.example .env      # then set ADMIN_USERNAME / ADMIN_PASSWORD (and API keys)
docker compose up -d --build
```

Services:

| Service | Container | Port | Notes |
| --- | --- | --- | --- |
| `backend` | `logsentry_backend` | 8000 | FastAPI; `NET_ADMIN` cap for iptables |
| `frontend` | `logsentry_frontend` | 80 | nginx, proxies `/api` to `backend` |

Verify:

```bash
curl -f http://localhost/health
# {"status":"ok","ai_ready":true,"active_brains":[...],"signature_count":30}
```

Open `http://localhost` for the console and log in with your admin credentials.

Stop / tear down:

```bash
docker compose down          # stop
docker compose down -v       # stop and drop volumes
```

Individual images:

```bash
docker build -t cerberus-backend:latest .
docker build -t cerberus-frontend:latest ./frontend
```

## Option B — Local Processes

```bash
pip install -r requirements.txt
cp .env.example .env      # set ADMIN_USERNAME / ADMIN_PASSWORD

# Terminal 1 — API
python -m uvicorn api:app --host 0.0.0.0 --port 8000

# Terminal 2 — console
python serve_frontend.py  # or: cd frontend && node server.mjs
```

## TLS / Reverse Proxy

Terminate TLS in front of the frontend container. Minimal nginx example:

```nginx
server {
    listen 443 ssl;
    server_name cerberus.example.com;

    ssl_certificate     /etc/nginx/certs/fullchain.pem;
    ssl_certificate_key /etc/nginx/certs/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:80;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /api/live-alerts {
        proxy_pass http://127.0.0.1:80;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 86400;
    }
}
```

## Health Probes & Orchestration

| Endpoint | Use |
| --- | --- |
| `/live` | liveness — process is up |
| `/ready` | readiness — DB + AI engine are ready |
| `/health` | general health / load-balancer check |

`docker-compose.yml` wires a healthcheck on `/health` for the backend and gates the
frontend on `service_healthy`. For Kubernetes, map `/live` to `livenessProbe` and
`/ready` to `readinessProbe`.

## Observability

- Scrape `http://<host>:8000/metrics` with Prometheus.
- Correlate logs using the `X-Request-ID` response header (mirrored in JSON logs).
- Alert on `cerberus_http_requests_total{status=~"4..|5.."}` and login-failure events.

## Scaling & Operations

- **Vertical first.** Cerberus is designed as a single-host sensor; the ML pipelines
  and DB are local, so scale the host rather than the replica count.
- **Multiple replicas** would each keep their own SQLite store; if you need horizontal
  scale, front them with a shared database and sticky WebSocket sessions (out of scope
  for 1.0.0).
- **Backups:** back up `sentinel.db` (and `-wal`/`-shm`) plus `.env` and `data/`.
- **Upgrades:** `docker compose pull && docker compose up -d` for tagged releases;
  migrations run automatically on startup.

## Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| Backend container restarts in a loop | `ADMIN_USERNAME`/`ADMIN_PASSWORD` not set in `.env` |
| `502 Bad Gateway` from the frontend | Backend not healthy yet; check `docker logs logsentry_backend` |
| `curl` to port 8000 fails | Publish/inspect ports; the container listens on 8000 |
| `ai_ready:false` in `/health` | Model files missing under `models/`; retrain with `python trainer.py --type all` |
| Firewall deploy returns `Access is denied` | Run the backend elevated (Administrator) to modify host firewall rules |
