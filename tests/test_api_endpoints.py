import os
import subprocess
import unittest
from unittest import mock

# Set test environment variables before importing api
os.environ.setdefault("ADMIN_USERNAME", "testadmin")
os.environ.setdefault("ADMIN_PASSWORD", "TestPass123!")

import api
from fastapi.testclient import TestClient


class FakeAIEngine:
    def __init__(self, ready=True):
        self.ready = ready
        self.models = {}


class FakeSignatureEngine:
    signatures = [{"pattern": "attack"}]


class FakeDetector:
    def __init__(self, ready=True):
        self.ai_engine = FakeAIEngine(ready)
        self.signature_engine = FakeSignatureEngine()

    def process_log_line(self, line, persist=True):
        if "attack" not in line.lower():
            return []
        return [
            {
                "Timestamp": "2026-05-23 20:00:00",
                "Type": "Test Attack",
                "Source IP": "203.0.113.10",
                "Location": "External / Internet",
                "Details": "Synthetic API test alert",
            }
        ]


class _FakeRAG:
    ready = True
    technique_count = 709

    def search(self, q, top_k=5):
        return [{"id": "T1003", "name": "OS Credential Dumping"}]


class _FakeOrchestrator:
    def run(self, **kwargs):
        return {
            "approved": True,
            "final_verdict": "CONTAINED",
            "steps": [{"agent": "Triage", "status": "ok", "latency_ms": 12}],
        }


class ApiEndpointTests(unittest.TestCase):
    def setUp(self):
        self._orig_detector = api.detector
        api.detector = FakeDetector(ready=True)
        api._login_attempts.clear()
        self.client = TestClient(api.app)
        api.app.dependency_overrides[api.get_current_user] = self._admin

    def tearDown(self):
        api.detector = self._orig_detector
        api.app.dependency_overrides.clear()
        api._login_attempts.clear()

    def _admin(self):
        return {"username": "testadmin", "role": "ADMIN"}

    def _ws_exchange(self, path, send=None):
        data = None
        try:
            with self.client.websocket_connect(path) as ws:
                if send is not None:
                    ws.send_text(send)
                data = ws.receive_json()
        except Exception:
            # The server may close the socket (e.g. policy violation) during teardown.
            pass
        return data

    # ---------- System endpoints ----------
    def test_live(self):
        response = self.client.get("/live")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "alive"})

    def test_ready_when_ready(self):
        with mock.patch("api.list_alerts", return_value=[]):
            response = self.client.get("/ready")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "ready")

    def test_ready_returns_503_when_ai_unready(self):
        api.detector = FakeDetector(ready=False)
        with mock.patch("api.list_alerts", return_value=[]):
            response = self.client.get("/ready")
        self.assertEqual(response.status_code, 503)

    def test_metrics_endpoint_exposes_prometheus(self):
        response = self.client.get("/metrics")
        self.assertEqual(response.status_code, 200)
        self.assertIn("cerberus_http_requests_total", response.text)

    # ---------- Authentication ----------
    def test_login_success(self):
        with (
            mock.patch(
                "api.authenticate_user", return_value={"username": "admin", "role": "ADMIN"}
            ),
            mock.patch("api.create_session", return_value="tok123"),
        ):
            response = self.client.post(
                "/api/auth/login", json={"username": "admin", "password": "pw"}
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"token": "tok123", "username": "admin", "role": "ADMIN"})

    def test_login_invalid_credentials(self):
        with mock.patch("api.authenticate_user", return_value=None):
            response = self.client.post(
                "/api/auth/login", json={"username": "admin", "password": "bad"}
            )
        self.assertEqual(response.status_code, 401)

    def test_login_rate_limit_trips_after_threshold(self):
        with mock.patch("api.authenticate_user", return_value=None):
            for _ in range(api.LOGIN_RATE_LIMIT):
                self.client.post("/api/auth/login", json={"username": "limited", "password": "bad"})
            response = self.client.post(
                "/api/auth/login", json={"username": "limited", "password": "bad"}
            )
        self.assertEqual(response.status_code, 429)

    def test_logout_revokes_token(self):
        with mock.patch("api.delete_session") as delete:
            response = self.client.post("/api/auth/logout", headers={"Authorization": "Bearer tok"})
        self.assertEqual(response.status_code, 200)
        delete.assert_called_once_with("tok")

    def test_me_returns_current_session(self):
        response = self.client.get("/api/auth/me")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["role"], "ADMIN")

    # ---------- Ingestion & alerts ----------
    def test_batch_ingest_counts_alerts(self):
        response = self.client.post(
            "/api/logs/batch",
            json={"lines": ["a attack line", "a clean line"], "source": "unit"},
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["line_count"], 2)
        self.assertEqual(payload["alert_count"], 1)

    def test_alerts_listing_unpacks_ai_report(self):
        fake_alerts = [
            {"Type": "PortScan", "Source IP": "10.0.0.5", "ai_report": '{"severity": "MEDIUM"}'}
        ]
        with mock.patch("api.list_alerts", return_value=fake_alerts):
            response = self.client.get("/api/alerts")
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["count"], 1)
        self.assertEqual(body["alerts"][0]["ai_report"], {"severity": "MEDIUM"})

    def test_threat_intel_returns_reputations(self):
        with mock.patch(
            "api.list_all_reputations", return_value=[{"ip": "1.1.1.1", "score": 120.0}]
        ):
            response = self.client.get("/api/threat-intel")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()[0]["ip"], "1.1.1.1")

    # ---------- MITRE RAG ----------
    def test_mitre_search_returns_matches(self):
        with mock.patch("api.get_rag_engine", return_value=_FakeRAG()):
            response = self.client.get("/api/threat-intel/mitre", params={"q": "credential"})
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["total_techniques"], 709)
        self.assertEqual(payload["results"][0]["id"], "T1003")

    def test_mitre_search_503_when_engine_not_ready(self):
        not_ready = mock.Mock()
        not_ready.ready = False
        with mock.patch("api.get_rag_engine", return_value=not_ready):
            response = self.client.get("/api/threat-intel/mitre", params={"q": "credential"})
        self.assertEqual(response.status_code, 503)

    # ---------- Multi-agent pipeline ----------
    def test_multi_agent_triage_runs_pipeline(self):
        with mock.patch.object(api, "_orchestrator", _FakeOrchestrator()):
            response = self.client.post(
                "/api/triage/multi-agent",
                json={
                    "threat_type": "SQL Injection",
                    "source_ip": "10.0.0.5",
                    "details": "UNION SELECT",
                    "log_line": "x",
                },
            )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["approved"])

    # ---------- Firewall / IPS ----------
    def test_deploy_firewall_rejects_invalid_ip(self):
        response = self.client.post("/api/ips/deploy-firewall", json={"ip": "999.999.999.999"})
        self.assertEqual(response.status_code, 400)

    def test_deploy_firewall_reports_command_failure(self):
        class _Result:
            returncode = 1
            stdout = ""
            stderr = "Access is denied"

        with mock.patch("api.subprocess.run", return_value=_Result()):
            response = self.client.post("/api/ips/deploy-firewall", json={"ip": "1.2.3.4"})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["success"])
        self.assertIn("Access is denied", response.json()["message"])

    def test_deploy_firewall_handles_timeout(self):
        with mock.patch(
            "api.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="iptables", timeout=15),
        ):
            response = self.client.post("/api/ips/deploy-firewall", json={"ip": "1.2.3.4"})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["success"])
        self.assertIn("timed out", response.json()["message"])

    # ---------- WebSocket ----------
    def test_ws_requires_token(self):
        data = self._ws_exchange("/api/live-alerts")
        self.assertIn("error", data)

    def test_ws_rejects_invalid_token(self):
        with mock.patch("api.get_session", return_value=None):
            data = self._ws_exchange("/api/live-alerts?token=bad")
        self.assertIn("Unauthorized", data["error"])

    def test_ws_analyst_cannot_ingest(self):
        with mock.patch("api.get_session", return_value={"username": "a", "role": "ANALYST"}):
            data = self._ws_exchange("/api/live-alerts?token=tok", send="attack")
        self.assertIn("Permission denied", data["error"])

    def test_ws_admin_receives_alerts(self):
        with mock.patch("api.get_session", return_value={"username": "admin", "role": "ADMIN"}):
            data = self._ws_exchange("/api/live-alerts?token=tok", send="attack here")
        self.assertEqual(data["alert_count"], 1)


if __name__ == "__main__":
    unittest.main()
