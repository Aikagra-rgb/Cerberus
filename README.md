# Cerberus Hybrid Detection & Prevention Platform

**Cerberus** (**C**ognitive **E**ngine for **R**eal-time **B**ehavioral **E**valuation, **R**esponse & **U**nified **S**ecurity) is an active hybrid intrusion detection and prevention platform that integrates:

- A signature-based detection engine (30+ rules covering SQLi, XSS, RFI, Path Traversal, and common exploits)
- Multi-brain Random Forest classifiers trained on CIC-IDS2017 flow data
- A file integrity monitor (FIM)
- An active IPS Gatekeeper with real-time OS-level firewall blocking (`iptables` / PowerShell Defender rules)
- A gorgeous, centralized modern browser analyst console and Legacy Streamlit dashboard

The current prototype tails demo logs from `data/`, writes alerts to SQLite, and loads trained models from `models/`.

---

## 1. Project Layout

- `sentinel_engine.py` - runtime engine for signatures, AI checks, auth/web log monitoring, and FIM.
- `api.py` - FastAPI backend for log ingestion, active IPS gatekeeping, alert querying, and live WebSocket checks.
- `trainer.py` - trains Random Forest classifier pipelines for each configured CIC-IDS2017 attack family.
- `src/config.py` - central paths, feature names, model configs, and simulation key mapping.
- `src/feature_extractor.py` - parses injected query-string metrics or Apache/Nginx combined logs into the unified 20-feature vector.
- `frontend/` - modern browser analyst console that connects to the FastAPI backend.
- `dashboard.py` - Streamlit dashboard that reads SQLite alerts and visualizes incidents.
- `src/alert_store.py` - SQLite persistence layer for alert writes, reads, active IPS IP reputation, and session management.
- `data/` - CIC CSVs, demo logs, signatures, and legacy CSV alert output.
- `models/` - trained model artifacts.
- `sentinel.db` - SQLite alert database, created automatically at runtime.

---

## 2. Environment And Installation

From the project root:

```powershell
cd "C:\Users\HP\Desktop\logsentry"
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

If `python` is not available in PowerShell, install Python 3.11+ and make sure
it is added to PATH.

---

## 3. Datasets

The trainer expects CIC-IDS2017 CSV files in `data/` using the filenames listed
in `src/config.py`, including:

- `cic_thursday.csv`
- `cic_tuesday.csv`
- `cic_wednesday.csv`
- `cic_friday_portscan.csv`
- `cic_friday_ddos.csv`
- `cic_friday_morning.csv`
- `cic_thursday_infiltration.csv`

All classifiers use the same 20 CIC feature columns from `UNIFIED_FEATURES`.

---

## 4. Training Models

Train all configured classifiers:

```powershell
python trainer.py --type all
```

Train one classifier:

```powershell
python trainer.py --type web
python trainer.py --type auth
python trainer.py --type dos
python trainer.py --type recon
python trainer.py --type ddos
python trainer.py --type botnet
python trainer.py --type infiltration
```

For a quick smoke test on a large CSV:

```powershell
python trainer.py --type web --max-rows 50000
```

Saved classifiers are written to `models/<type>_classifier.pkl`.

---

## 5. Running The Detection Engine

```powershell
python sentinel_engine.py
```

The engine will:

- Tail `data/demo_access.log`
- Tail `data/demo_auth.log`
- Run signature checks on web and auth log lines
- Run AI checks when a line contains query-string simulation metrics
- Monitor `critical_config.conf` and `server_bin.exe`
- Append alerts to `sentinel.db`

Example AI simulation line:

```text
192.168.1.5 - GET /traffic?dport=80&dur=1200&fpkts=8&bpkts=5&byte_rate=500.0 HTTP/1.1 200
```

---

## 6. Running The SOC Dashboard

Run the modern analyst console:

```powershell
python -m uvicorn api:app --host 127.0.0.1 --port 8000
python frontend/server.py
# (Or if Node.js is installed: node frontend/server.mjs)
```

Open:

```text
http://127.0.0.1:5173
```

The frontend reads API health, lists active AI brains, queries alerts from
SQLite, filters the live alert feed, and can submit individual log lines to
`POST /api/logs`.

The legacy Streamlit dashboard is still available:

```powershell
streamlit run dashboard.py
```

Both dashboards read alerts from `sentinel.db`. If `data/hids_alerts.csv`
exists from older runs, alerts are imported into SQLite once.

---

## 7. Running The FastAPI Backend

```powershell
python -m uvicorn api:app --reload
```

Useful endpoints:

- `GET /health` - service status, loaded AI brains, and signature count.
- `POST /api/logs` - ingest one log line and return generated alerts.
- `POST /api/logs/batch` - ingest multiple log lines.
- `GET /api/alerts` - read recent alerts from SQLite.
- `WS /api/live-alerts` - send log lines over WebSocket and receive alert results.

---

## 8. Helper Workflow

The PowerShell helper supports:

```powershell
.\run_workflow.ps1 -Task train
.\run_workflow.ps1 -Task train-all
.\run_workflow.ps1 -Task test
.\run_workflow.ps1 -Task api
.\run_workflow.ps1 -Task frontend
.\run_workflow.ps1 -Task engine
.\run_workflow.ps1 -Task dashboard
.\run_workflow.ps1 -Task all
```

`-Task all` runs tests, starts the engine and API in separate processes, and
launches the modern frontend.

---

## 9. Current Productization Roadmap

1. Split the runtime into agent and manager processes.
2. Swap SQLite for PostgreSQL when the product needs multi-user SaaS hosting.
