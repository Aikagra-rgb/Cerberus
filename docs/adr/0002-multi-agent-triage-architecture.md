# 2. Multi-Agent Security Triage Architecture

Date: 2026-08-11

## Status
Accepted

## Context
When security alerts trigger (via heuristic signature or Random Forest classification), automated incident analysis requires multiple steps:
1. Threat classification and severity assessment.
2. Threat intelligence gathering and MITRE ATT&CK correlation.
3. Automated containment recommendation (e.g. firewall blocking).
4. Guardrails to ensure safety and prevent unauthorized destructive actions.

## Decision
We implemented a multi-agent orchestrator using specialized LLM agents powered by NVIDIA NIM (Nemotron-70B) and DeepSeek models:
- **TriageAgent:** Assesses event context, assigns severity, and calculates initial confidence.
- **ResearchAgent:** Queries local RAG engine populated with MITRE ATT&CK matrix data.
- **RemediationAgent:** Generates defensive actions (iptables rules, incident response plans).
- **GuardrailAgent:** Validates proposals against safety rules before execution.

## Consequences
- **Positive:** Modular separation of duties, explainable multi-step reasoning, and fail-safe guardrail checks before applying firewall changes.
- **Negative:** Dependent on external LLM inference endpoints; fallback mechanisms and timeouts are required to prevent latency spikes during high log ingest rates.
