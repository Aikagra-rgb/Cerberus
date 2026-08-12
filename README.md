# 🛡️ Cerberus — Multi-Agent DevSecOps & AI-Powered SIEM/IPS Platform

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11+-blue.svg" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/FastAPI-0.110+-009688.svg" alt="FastAPI">
  <img src="https://img.shields.io/badge/LLM-NVIDIA_NIM-76B900.svg" alt="NVIDIA NIM">
  <img src="https://img.shields.io/badge/DeepSeek-V4_Pro-00F0FF.svg" alt="DeepSeek">
  <img src="https://img.shields.io/badge/Nemotron-70B-BF5AF2.svg" alt="Nemotron">
  <img src="https://img.shields.io/badge/3D_UI-Three.js-FF2D55.svg" alt="Three.js">
  <img src="https://img.shields.io/badge/MITRE-ATT%26CK_RAG-orange.svg" alt="MITRE ATT&CK RAG">
</p>

**Cerberus** (**C**ognitive **E**ngine for **R**eal-time **B**ehavioral **E**valuation, **R**esponse & **U**nified **S**ecurity) is an enterprise-grade, agentic Security Operations (SOC) platform. It merges multi-model machine learning, continuous signature inspection, kernel-level active IPS gatekeeping, and an autonomous **4-Agent DevSecOps pipeline** powered by **NVIDIA NIM** (DeepSeek V4 Pro + Nemotron-70B) into an immersive **3D WebGL command console**.

---

## 🌟 Key Capabilities

### ⚡ 1. Autonomous Multi-Agent DevSecOps Pipeline
Instead of relying on single LLM prompts, Cerberus uses a 4-agent state-graph orchestrator:
* 🎯 **Triage Agent (DeepSeek V4 Pro)**: Classifies attack vector, blast radius, severity (CRITICAL/HIGH/MEDIUM/LOW), and confidence score.
* 🔬 **Research Agent (DeepSeek V4 Pro + MITRE ATT&CK RAG)**: Performs TF-IDF semantic retrieval over a bundled knowledge base of **709 MITRE ATT&CK Enterprise techniques**, mapping technique IDs, threat actor campaigns, and Indicators of Compromise (IoCs).
* 🔧 **Remediation Agent (NVIDIA Nemotron-70B)**: Generates syntactically validated, production-ready remediation playbooks:
  * OS Firewall commands (`iptables` & PowerShell `New-NetFirewallRule`)
  * Ansible Remediation Playbooks (YAML)
  * Sigma Detection Rules (YAML)
  * Step-by-step SOC incident response checklist
* 🛡️ **Guardrail Verification Agent (DeepSeek V4 Pro)**: Runs static regex danger scanning (`rm -rf`, raw disc write interception) + LLM sanity verification before outputs reach the analyst console.

### 🌌 2. Ultra-Futuristic 3D WebGL SOC Console
* **Three.js Engine (`bg3d.js`)**: Infinite perspective wireframe grid floor scrolling smoothly into the horizon.
* **Neural Threat Map**: 280 floating neon cyan/purple/pink particles with live edge network connections.
* **Attack Nodes**: 9 rotating holographic hexagonal nodes floating in 3D space with volumetric light shafts and CRT scanline overlay.
* **Interactive Parallax**: Camera orientation dynamically tracks cursor coordinates.
* **Glassmorphism Drawer**: Multi-agent thought stream console with tabbed playbook viewers (Firewall / Ansible / Sigma / Checklist).

### 🤖 3. Multi-Brain ML Threat Classifier
* Trained on 20 unified network flow metrics from the **CIC-IDS2017** benchmark dataset.
* Specialized classifier brains for **Web Attacks, Auth Brute Force, DoS, DDoS, Recon/PortScan, Botnet, and Infiltration**.
* Live evaluation metrics tracked per brain: **Accuracy, Precision, Recall, and F1-Score**.

### 🔥 4. Active IPS Gatekeeper & Kernel Firewall
* Continuous IP threat score accumulation based on violation severity.
* One-click kernel-level IP blocking via Linux `iptables` or Windows Defender PowerShell commands.

### 🔍 5. Signatures & File Integrity Monitoring (FIM)
* 30+ regex detection rules covering SQLi, XSS, Path Traversal, Log4Shell, and RFI.
* Cryptographic hash monitoring for critical system files (`critical_config.conf`, `server_bin.exe`).

---

## 🏗️ Multi-Agent Architecture

```
                  ┌───────────────────────────────┐
                  │    Security Alert Ingested    │
                  └──────────────┬────────────────┘
                                 │
                                 ▼
                     [ 🎯 1. Triage Agent ]
                   (Model: DeepSeek V4 Pro)
               Classifies attack, severity & scope
                                 │
                                 ▼
                    [ 🔬 2. Research Agent ]
               (Model: DeepSeek V4 + MITRE RAG)
             Searches 709 ATT&CK technique matrix
                                 │
                                 ▼
                   [ 🔧 3. Remediation Agent ]
                  (Model: NVIDIA Nemotron-70B)
             Generates firewall, Ansible & Sigma
                                 │
                                 ▼
                    [ 🛡️ 4. Guardrail Agent ]
                   (Model: DeepSeek V4 Pro)
             Static regex scan + Safety audit
                                 │
                                 ▼
               ┌──────────────────────────────────┐
               │ Verified Output -> SOC Dashboard │
               └──────────────────────────────────┘
```

---

## 🚀 Quick Start Guide

### Prerequisites
* **Python 3.11+**
* (Optional) **NVIDIA API Key** for DeepSeek & Nemotron NIM agents (fallback modes included).

### 1. Installation & Environment Setup
Clone the repository and install Python dependencies:

```powershell
# Navigate to project root
cd Cerberus

# Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1   # On Windows
# source .venv/bin/activate    # On Linux/macOS

# Install requirements
pip install -r requirements.txt
```

### 2. Configure NVIDIA NIM API Keys (Optional for Multi-Agent LLMs)
Create a `.env` file in the project root:

```env
NVIDIA_BASE_URL=https://integrate.api.nvidia.com/v1
NEMOTRON_API_KEY=your_nvidia_nemotron_key_here
DEEPSEEK_API_KEY=your_nvidia_deepseek_key_here
```

### 3. Launch Cerberus Platform

#### Terminal 1 — Start FastAPI Backend API
```powershell
python -m uvicorn api:app --port 8000 --reload
```

#### Terminal 2 — Start 3D Analyst Console
```powershell
python serve_frontend.py
```

Open your browser at **`http://localhost:3000`**

#### Demo Login Credentials
* **Analyst**: `analyst` / `analyst123`
* **Admin**: `admin` / `admin123`

---

## 📊 Training & Evaluating Machine Learning Models

Train all 7 Random Forest classifier brains on CIC-IDS2017 flow data and generate metric reports (`Accuracy`, `Precision`, `Recall`, `F1`):

```powershell
# Train all models
python trainer.py --type all --max-rows 100000

# Train individual model types (web, auth, dos, recon, ddos, botnet, infiltration)
python trainer.py --type web
```

Metric outputs are automatically saved to `models/<type>_metrics.json` and served live on the **Model Analytics** tab.

---

## 📡 API Reference

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/auth/login` | Authenticates user and returns JWT bearer token |
| `POST` | `/api/triage/multi-agent` | Triggers the 4-Agent DevSecOps orchestration pipeline |
| `GET` | `/api/threat-intel/mitre?q=...` | Performs RAG semantic search over 709 MITRE techniques |
| `GET` | `/api/analytics` | Returns accuracy, precision, recall & F1 metrics for all models |
| `GET` | `/api/alerts` | Queries persistent incident log records from SQLite |
| `POST` | `/api/logs` | Ingests raw log lines for real-time AI & signature triage |
| `POST` | `/api/ips/deploy-firewall` | Deploys active OS-level block rule for malicious IP |
| `WS` | `/api/live-alerts` | Real-time WebSocket streaming feed |

---

## 📂 Project Structure

```
Cerberus/
├── api.py                   # FastAPI backend server & API routing
├── sentinel_engine.py       # Signature engine, log tailer, FIM & AI dispatcher
├── trainer.py               # ML training pipeline for CIC-IDS2017 datasets
├── serve_frontend.py        # Python static HTTP server for frontend dashboard
├── requirements.txt         # Project dependencies
├── .env                     # Private environment variables (gitignored)
├── src/
│   ├── alert_store.py       # SQLite persistence, PBKDF2 auth & IPS reputation
│   ├── config.py            # System configuration & feature schemas
│   ├── feature_extractor.py # 20-feature CIC flow vector parsing
│   └── agents/              # Autonomous DevSecOps Multi-Agent Package
│       ├── llm_provider.py  # NVIDIA NIM DeepSeek & Nemotron client
│       ├── rag_engine.py    # TF-IDF MITRE ATT&CK technique retriever
│       ├── triage_agent.py  # DeepSeek V4 Pro triage classifier
│       ├── research_agent.py# DeepSeek + MITRE RAG threat intel agent
│       ├── remediation_agent.py # Nemotron-70B playbook generator
│       ├── guardrail_agent.py # Safety & regex interception guardrail
│       └── orchestrator.py  # State-graph pipeline controller
├── frontend/                # 3D WebGL Modern SOC Dashboard
│   ├── index.html           # Dashboard layout & slide-out console
│   ├── styles.css           # Glassmorphism cyber styles & neon accents
│   ├── app.js               # Event handlers & API client logic
│   └── bg3d.js              # Three.js 3D background animation engine
├── data/                    # Datasets, MITRE ATT&CK JSON & detection rules
└── models/                  # Trained .pkl models & .json metrics reports
```

---

## 📜 License & Acknowledgments

* **Datasets**: CIC-IDS2017 Dataset (Canadian Institute for Cybersecurity).
* **Threat Intel**: MITRE ATT&CK Enterprise Matrix.
* **LLM Engine**: NVIDIA NIM (DeepSeek V4 Pro & Nemotron-70B).
