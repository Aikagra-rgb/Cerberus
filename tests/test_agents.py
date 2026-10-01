import json
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from openai import OpenAIError
from src.agents import (
    guardrail_agent,
    llm_provider,
    remediation_agent,
    research_agent,
    triage_agent,
)
from src.agents.orchestrator import AgentStep, MultiAgentOrchestrator
from src.agents.rag_engine import RAGEngine


class AgentStepTests(unittest.TestCase):
    def test_agent_step_lifecycle(self):
        step = AgentStep("Triage Agent", "DeepSeek V4 Pro")
        self.assertEqual(step.agent_name, "Triage Agent")
        self.assertEqual(step.status, "pending")

        step.status = "done"
        step.result = {"verdict": "malicious"}
        step.latency_ms = 450

        d = step.to_dict()
        self.assertEqual(d["status"], "done")
        self.assertEqual(d["result"]["verdict"], "malicious")
        self.assertEqual(d["latency_ms"], 450)


class LLMProviderTests(unittest.TestCase):
    def test_call_llm_missing_api_key_raises_error(self):
        with patch.object(llm_provider, "_DEEPSEEK_KEY", ""):
            with self.assertRaises((RuntimeError, OpenAIError)):
                llm_provider.call_llm("sys", "user", model_family="deepseek")

    def test_call_llm_successful(self):
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_choice = MagicMock()
        mock_choice.message.content = "Analysis completed."
        mock_response.choices = [mock_choice]
        mock_client.chat.completions.create.return_value = mock_response

        with (
            patch.object(llm_provider, "_deepseek_client", return_value=mock_client),
            patch.object(llm_provider, "_DEEPSEEK_KEY", "test-key"),
        ):
            res = llm_provider.call_llm("sys", "user", model_family="deepseek")
            self.assertEqual(res, "Analysis completed.")

    def test_call_llm_json_parsing(self):
        mock_json_str = '{"verdict": "blocked", "confidence": 0.95}'
        with patch.object(llm_provider, "call_llm", return_value=mock_json_str):
            res = llm_provider.call_llm_json("sys", "user")
            self.assertEqual(res["verdict"], "blocked")
            self.assertEqual(res["confidence"], 0.95)

    def test_call_llm_json_markdown_wrapped_fallback(self):
        markdown_json = 'Here is the result:\n```json\n{"status": "ok"}\n```'
        with patch.object(llm_provider, "call_llm", return_value=markdown_json):
            res = llm_provider.call_llm_json("sys", "user")
            self.assertEqual(res.get("status"), "ok")


class SpecializedAgentsTests(unittest.TestCase):
    def test_triage_agent(self):
        mock_triage_output = {
            "attack_class": "SQL Injection",
            "severity": "HIGH",
            "attack_vector": "UNION SELECT injection",
            "affected_assets": ["Web DB"],
            "blast_radius": "Database leak",
            "confidence": 0.95,
            "summary": "Attacker attempted SQL injection.",
        }
        with patch.object(triage_agent, "call_llm_json", return_value=mock_triage_output):
            result = triage_agent.run(
                threat_type="SQL Injection",
                source_ip="192.168.1.100",
                details="UNION SELECT detected",
                log_line="GET /api?id=1' UNION SELECT",
            )
            self.assertEqual(result["severity"], "HIGH")
            self.assertEqual(result["attack_class"], "SQL Injection")

    def test_research_agent(self):
        mock_research_output = {
            "mitre_technique_id": "T1190",
            "mitre_technique_name": "Exploit Public-Facing Application",
            "tactic": "Initial Access",
            "threat_actor_context": "APT-29",
            "attack_lifecycle_stage": "Initial Access",
            "key_indicators": ["HTTP 500 error", "UNION SELECT"],
            "intelligence_summary": "Known exploit targeting web application.",
        }
        mock_rag = MagicMock()
        mock_rag.search.return_value = [
            {"id": "T1190", "name": "Exploit Public-Facing Application"}
        ]

        with (
            patch("src.agents.research_agent.get_rag_engine", return_value=mock_rag),
            patch.object(research_agent, "call_llm_json", return_value=mock_research_output),
        ):
            result = research_agent.run(
                triage_result={"attack_class": "SQL Injection"},
                threat_type="SQL Injection",
                source_ip="192.168.1.100",
                details="UNION SELECT",
            )
            self.assertEqual(result["mitre_technique_id"], "T1190")

    def test_remediation_agent(self):
        mock_remediation_output = {
            "firewall_cmd_linux": "iptables -A INPUT -s 192.168.1.100 -j DROP",
            "firewall_cmd_windows": "netsh advfirewall firewall add rule ...",
            "ansible_playbook": "- hosts: all\n  tasks: []",
            "sigma_rule": "title: SQL Injection Rule",
            "patch_instructions": ["Use parameterized queries"],
            "remediation_summary": "Block IP immediately.",
        }
        with patch.object(remediation_agent, "call_llm_json", return_value=mock_remediation_output):
            result = remediation_agent.run(
                triage_result={"attack_class": "SQL Injection"},
                research_result={"mitre_technique_id": "T1190"},
                threat_type="SQL Injection",
                source_ip="192.168.1.100",
                details="UNION SELECT",
            )
            self.assertIn("iptables", result["firewall_cmd_linux"])

    def test_guardrail_agent_approves_safe_plan(self):
        mock_guardrail_output = {
            "approved": True,
            "risk_score": 10,
            "intercepted_items": [],
            "corrections": [],
            "verification_notes": "Safe rule.",
            "final_verdict": "APPROVED",
        }
        safe_remediation = {
            "firewall_cmd_linux": "iptables -A INPUT -s 192.168.1.100 -j DROP",
            "firewall_cmd_windows": "netsh advfirewall firewall add rule name='Block 192.168.1.100' dir=in action=block remoteip=192.168.1.100",
        }
        with patch.object(guardrail_agent, "call_llm_json", return_value=mock_guardrail_output):
            result = guardrail_agent.run(
                remediation_result=safe_remediation,
                triage_result={"attack_class": "SQL Injection"},
                threat_type="SQL Injection",
                source_ip="192.168.1.100",
            )
            self.assertTrue(result["approved"])
            self.assertEqual(result["final_verdict"], "APPROVED")

    def test_guardrail_agent_static_safety_check(self):
        malicious_remediation = {
            "firewall_cmd_linux": "rm -rf / --no-preserve-root",
        }
        result = guardrail_agent.run(
            remediation_result=malicious_remediation,
            triage_result={},
            threat_type="Test",
            source_ip="1.2.3.4",
        )
        self.assertFalse(result["approved"])
        self.assertEqual(result["final_verdict"], "INTERCEPTED")


class MultiAgentOrchestratorTests(unittest.TestCase):
    def test_orchestrator_full_flow(self):
        orchestrator = MultiAgentOrchestrator()

        mock_triage = {
            "attack_class": "Port Scan",
            "severity": "HIGH",
            "summary": "Rapid SYN flood scan.",
        }
        mock_research = {
            "mitre_technique_id": "T1046",
            "mitre_technique_name": "Network Service Discovery",
            "tactic": "Discovery",
        }
        mock_remediation = {
            "firewall_cmd_linux": "iptables -A INPUT -s 10.0.0.99 -j DROP",
            "firewall_cmd_windows": "netsh ...",
            "patch_instructions": ["Block scanning subnet"],
            "remediation_summary": "Blocked IP.",
        }
        mock_guardrail = {
            "approved": True,
            "risk_score": 5,
            "intercepted_items": [],
            "corrections": [],
            "verification_notes": "Safe",
            "final_verdict": "APPROVED",
        }

        with (
            patch("src.agents.triage_agent.run", return_value=mock_triage),
            patch("src.agents.research_agent.run", return_value=mock_research),
            patch("src.agents.remediation_agent.run", return_value=mock_remediation),
            patch("src.agents.guardrail_agent.run", return_value=mock_guardrail),
        ):
            out = orchestrator.run("Port Scan", "10.0.0.99", "Rapid SYN flood")
            self.assertTrue(out["approved"])
            self.assertEqual(len(out["steps"]), 4)
            self.assertEqual(out["firewall_cmd_linux"], "iptables -A INPUT -s 10.0.0.99 -j DROP")
            self.assertIn("pipeline_id", out)


class RAGEngineTests(unittest.TestCase):
    def test_rag_engine_search(self):
        sample_mitre_data = {
            "techniques": [
                {
                    "id": "T1190",
                    "name": "Exploit Public-Facing Application",
                    "tactics": ["Initial Access"],
                    "description": "Adversaries may attempt to exploit vulnerabilities in Internet-facing software.",
                    "detection": "Monitor application logs for abnormal traffic.",
                },
                {
                    "id": "T1110",
                    "name": "Brute Force",
                    "tactics": ["Credential Access"],
                    "description": "Adversaries may use brute force techniques to attempt authentication.",
                    "detection": "Monitor authentication failures.",
                },
            ]
        }
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json") as f:
            json.dump(sample_mitre_data, f)
            temp_path = f.name

        try:
            rag = RAGEngine(mitre_path=temp_path)
            self.assertTrue(rag.ready)
            self.assertEqual(rag.technique_count, 2)

            results = rag.search("brute force login attempt", top_k=1)
            self.assertGreaterEqual(len(results), 1)
            self.assertEqual(results[0]["id"], "T1110")
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)
