# Cerberus — Multi-Agent DevSecOps & Security Intelligence Platform

[![Python](https://img.shields.io/badge/Python-3.11+-blue?style=flat-square&logo=python)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110-009688?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com)
[![Three.js](https://img.shields.io/badge/3D_UI-Three.js-FF2D55?style=flat-square)](https://threejs.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

> **Cerberus** (**C**ognitive **E**ngine for **R**eal-time **B**ehavioral **E**valuation, **R**esponse & **U**nified **S**ecurity) is an agentic Security Operations (SOC) platform merging multi-model machine learning, MITRE ATT&CK RAG retrieval, active IPS gatekeeping, and an interactive 3D WebGL command console.

---

## Key Features

- **Multi-Agent DevSecOps Pipeline:** Autonomous AI agents performing threat analysis, vulnerability triage, and incident response checklists.
- **MITRE ATT&CK Knowledge Base:** RAG retrieval engine over 700+ MITRE ATT&CK techniques for immediate threat mapping and IoC analysis.
- **Real-Time IPS Gatekeeper:** Active kernel/network level response mechanisms for blocking malicious traffic patterns.
- **3D WebGL Security Console:** Three.js visualization dashboard displaying network topology and live threat indicators.

---

## Tech Stack

- **Backend:** FastAPI, SQLite, Python 3.11+
- **AI & NLP:** NVIDIA NIM / DeepSeek & Nemotron agents, MITRE ATT&CK RAG
- **Frontend:** HTML5, CSS3, Three.js 3D WebGL

---

## Quick Start

`ash
git clone https://github.com/Aikagra-rgb/Cerberus.git
cd Cerberus

# Install dependencies
pip install -r requirements.txt

# Start Cerberus engine
python main.py
`

---

## License

Distributed under the MIT License.
