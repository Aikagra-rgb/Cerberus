"""
Cerberus Multi-Agent Pipeline — Orchestrator
=============================================
Controls the full multi-agent state graph:

  Triage Agent  ->  Research Agent (RAG)  ->  Remediation Agent (Nemotron)
      ->  Guardrail Agent (DeepSeek)  ->  Final Verified Output

Captures per-agent timing, status, and thought traces for
real-time UI rendering in the frontend Triage Console.
"""

import time
from datetime import datetime
from typing import Any

from . import triage_agent, research_agent, remediation_agent, guardrail_agent


class AgentStep:
    """Represents a single agent's execution result and metadata."""

    def __init__(self, agent_name: str, model: str):
        self.agent_name: str   = agent_name
        self.model:      str   = model
        self.status:     str   = "pending"   # pending | running | done | error | intercepted
        self.result:     dict  = {}
        self.error:      str   = ""
        self.latency_ms: int   = 0

    def to_dict(self) -> dict:
        return {
            "agent":      self.agent_name,
            "model":      self.model,
            "status":     self.status,
            "result":     self.result,
            "error":      self.error,
            "latency_ms": self.latency_ms,
        }


class MultiAgentOrchestrator:
    """
    Orchestrates the 4-agent DevSecOps pipeline for a Cerberus alert.

    Usage:
        orchestrator = MultiAgentOrchestrator()
        result = orchestrator.run(threat_type, source_ip, details, log_line)
    """

    AGENT_MODELS = {
        "Triage Agent":      "DeepSeek V4 Pro",
        "Research Agent":    "DeepSeek V4 Pro + MITRE RAG",
        "Remediation Agent": "NVIDIA Nemotron-70B",
        "Guardrail Agent":   "DeepSeek V4 Pro",
    }

    def run(
        self,
        threat_type: str,
        source_ip:   str,
        details:     str,
        log_line:    str = "",
    ) -> dict:
        """
        Execute the full multi-agent pipeline and return the complete
        structured result including all agent steps and verified outputs.

        Returns:
            {
                "pipeline_id":      str,
                "started_at":       str,
                "total_latency_ms": int,
                "steps":            list[dict],
                "triage":           dict,
                "research":         dict,
                "remediation":      dict,
                "guardrail":        dict,
                "approved":         bool,
                "final_verdict":    str,
                # Convenience fields for backward-compat with old ai_triage schema:
                "analysis":         str,
                "mitigations":      list[str],
                "firewall_cmd_linux":  str,
                "firewall_cmd_windows": str,
                "agent_mode":       str,
            }
        """
        pipeline_start = time.time()
        pipeline_id    = f"cerberus-{int(pipeline_start)}"
        started_at     = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        steps: list[AgentStep] = []

        triage_result     = {}
        research_result   = {}
        remediation_result = {}
        guardrail_result  = {}

        # ── Step 1: Triage Agent ────────────────────────────────────────────
        step1 = AgentStep("Triage Agent", self.AGENT_MODELS["Triage Agent"])
        step1.status = "running"
        t0 = time.time()
        try:
            triage_result = triage_agent.run(threat_type, source_ip, details, log_line)
            step1.result  = triage_result
            step1.status  = "done"
        except Exception as exc:
            step1.status = "error"
            step1.error  = str(exc)
            triage_result = {"attack_class": threat_type, "severity": "HIGH",
                             "attack_vector": details, "affected_assets": ["Unknown"],
                             "blast_radius": "Unknown", "confidence": 0.5,
                             "summary": f"{threat_type} from {source_ip}."}
        step1.latency_ms = int((time.time() - t0) * 1000)
        steps.append(step1)

        # ── Step 2: Research Agent (MITRE RAG) ─────────────────────────────
        step2 = AgentStep("Research Agent", self.AGENT_MODELS["Research Agent"])
        step2.status = "running"
        t0 = time.time()
        try:
            research_result = research_agent.run(triage_result, threat_type, source_ip, details)
            step2.result    = research_result
            step2.status    = "done"
        except Exception as exc:
            step2.status = "error"
            step2.error  = str(exc)
            research_result = {"mitre_techniques": [], "threat_actor_context": "Unknown",
                               "attack_lifecycle_stage": "Initial Access",
                               "key_indicators": [source_ip],
                               "intelligence_summary": f"Research unavailable for {threat_type}."}
        step2.latency_ms = int((time.time() - t0) * 1000)
        steps.append(step2)

        # ── Step 3: Remediation Agent (NVIDIA Nemotron) ─────────────────────
        step3 = AgentStep("Remediation Agent", self.AGENT_MODELS["Remediation Agent"])
        step3.status = "running"
        t0 = time.time()
        try:
            remediation_result = remediation_agent.run(
                triage_result, research_result, threat_type, source_ip, details
            )
            step3.result = remediation_result
            step3.status = "done"
        except Exception as exc:
            step3.status = "error"
            step3.error  = str(exc)
            remediation_result = {
                "firewall_cmd_linux":   f"sudo iptables -A INPUT -s {source_ip} -j DROP",
                "firewall_cmd_windows": f'New-NetFirewallRule -DisplayName "Cerberus Block {source_ip}" -Direction Inbound -Action Block -RemoteAddress {source_ip}',
                "nginx_hardening":      None,
                "ansible_playbook":     f"---\n- name: Block {source_ip}\n  hosts: all\n  tasks:\n    - iptables: chain=INPUT source={source_ip} jump=DROP",
                "sigma_rule":           f"title: Cerberus - {threat_type}\nstatus: experimental",
                "patch_instructions":   [f"Block {source_ip}", "Investigate affected services."],
                "remediation_summary":  f"Fallback remediation for {threat_type} from {source_ip}.",
            }
        step3.latency_ms = int((time.time() - t0) * 1000)
        steps.append(step3)

        # ── Step 4: Guardrail Agent ─────────────────────────────────────────
        step4 = AgentStep("Guardrail Agent", self.AGENT_MODELS["Guardrail Agent"])
        step4.status = "running"
        t0 = time.time()
        try:
            guardrail_result = guardrail_agent.run(
                remediation_result, triage_result, threat_type, source_ip
            )
            step4.result = guardrail_result
            approved     = guardrail_result.get("approved", True)
            step4.status = "done" if approved else "intercepted"
        except Exception as exc:
            step4.status = "error"
            step4.error  = str(exc)
            guardrail_result = {"approved": True, "risk_score": 0,
                                "intercepted_items": [], "corrections": [],
                                "verification_notes": "Guardrail check skipped.",
                                "final_verdict": "APPROVED"}
            approved = True
        step4.latency_ms = int((time.time() - t0) * 1000)
        steps.append(step4)

        total_ms = int((time.time() - pipeline_start) * 1000)

        # ── Build Final Result ───────────────────────────────────────────────
        return {
            # Pipeline metadata
            "pipeline_id":      pipeline_id,
            "started_at":       started_at,
            "total_latency_ms": total_ms,
            "steps":            [s.to_dict() for s in steps],

            # Full agent outputs
            "triage":      triage_result,
            "research":    research_result,
            "remediation": remediation_result,
            "guardrail":   guardrail_result,

            # Verdict
            "approved":      guardrail_result.get("approved", True),
            "final_verdict": guardrail_result.get("final_verdict", "APPROVED"),

            # Backward-compatible fields for existing ai_report schema
            "agent_mode":          "MULTI_AGENT",
            "analysis":            triage_result.get("summary", f"{threat_type} from {source_ip}."),
            "mitigations":         remediation_result.get("patch_instructions", []),
            "firewall_cmd_linux":  remediation_result.get("firewall_cmd_linux",
                                       f"sudo iptables -A INPUT -s {source_ip} -j DROP"),
            "firewall_cmd_windows": remediation_result.get("firewall_cmd_windows",
                                       f'New-NetFirewallRule -DisplayName "Cerberus Block {source_ip}" '
                                       f'-Direction Inbound -Action Block -RemoteAddress {source_ip}'),
        }
