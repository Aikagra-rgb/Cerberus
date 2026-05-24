import unittest

from fastapi.testclient import TestClient

import api


class FakeAIEngine:
    ready = False
    models = {}


class FakeSignatureEngine:
    signatures = [{"pattern": "attack"}]


class FakeDetector:
    ai_engine = FakeAIEngine()
    signature_engine = FakeSignatureEngine()

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


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.original_detector = api.detector
        api.detector = FakeDetector()
        self.client = TestClient(api.app)
        
        # Override get_current_user to act as an ADMIN by default for existing unit tests
        api.app.dependency_overrides[api.get_current_user] = self.mock_admin_user

    def tearDown(self):
        api.detector = self.original_detector
        api.app.dependency_overrides.clear()

    def mock_admin_user(self):
        return {"username": "testadmin", "role": "ADMIN"}

    def mock_analyst_user(self):
        return {"username": "testanalyst", "role": "ANALYST"}

    def test_health_reports_detector_status(self):
        response = self.client.get("/health")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["status"], "ok")
        self.assertFalse(payload["ai_ready"])
        self.assertEqual(payload["signature_count"], 1)

    def test_ingest_log_returns_alerts_as_admin(self):
        response = self.client.post(
            "/api/logs",
            json={"line": "203.0.113.10 attack payload", "source": "unit-test"},
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["source"], "unit-test")
        self.assertEqual(payload["alert_count"], 1)
        self.assertEqual(payload["alerts"][0]["Type"], "Test Attack")

    def test_ingest_log_accepts_benign_line_as_admin(self):
        response = self.client.post(
            "/api/logs",
            json={"line": "203.0.113.10 normal request", "source": "unit-test"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["alert_count"], 0)

    def test_ingest_log_rejects_unauthenticated_user(self):
        # Remove dependency overrides to simulate a real unauthenticated request
        api.app.dependency_overrides.clear()
        
        response = self.client.post(
            "/api/logs",
            json={"line": "203.0.113.10 attack payload", "source": "unit-test"},
        )
        
        # Should return 401 Unauthorized due to missing header
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["detail"], "Missing or invalid session token")

    def test_ingest_log_rejects_analyst_role(self):
        # Override current user as a read-only ANALYST
        api.app.dependency_overrides[api.get_current_user] = self.mock_analyst_user
        
        response = self.client.post(
            "/api/logs",
            json={"line": "203.0.113.10 attack payload", "source": "unit-test"},
        )
        
        # Should return 403 Forbidden due to insufficient role permissions
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["detail"], "Action restricted to Administrator role")

    def test_get_blocked_ips(self):
        import api
        original_list_blocked_ips = api.list_blocked_ips
        api.list_blocked_ips = lambda: [{"ip": "1.2.3.4", "score": 150.0, "updated_at": "2026-05-23 20:00:00"}]
        try:
            response = self.client.get("/api/blocked-ips")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json(), [{"ip": "1.2.3.4", "score": 150.0, "updated_at": "2026-05-23 20:00:00"}])
        finally:
            api.list_blocked_ips = original_list_blocked_ips

    def test_unblock_ip(self):
        import api
        original_unblock_ip = api.unblock_ip
        unblocked_ip = []
        api.unblock_ip = lambda ip: unblocked_ip.append(ip)
        try:
            response = self.client.post("/api/ips/unblock", json={"ip": "1.2.3.4"})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["message"], "IP 1.2.3.4 unblocked successfully")
            self.assertEqual(unblocked_ip, ["1.2.3.4"])
        finally:
            api.unblock_ip = original_unblock_ip

    def test_get_model_analytics(self):
        response = self.client.get("/api/model-analytics")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIn("analytics", payload)
        self.assertIn("web", payload["analytics"])
        self.assertEqual(payload["analytics"]["web"]["model_type"], "web")

    def test_deploy_firewall_fails_on_empty_ip(self):
        response = self.client.post("/api/ips/deploy-firewall", json={"ip": "short"})
        self.assertEqual(response.status_code, 422)

    def test_deploy_firewall_successful(self):
        import subprocess
        original_run = subprocess.run
        class DummyResult:
            returncode = 0
            stdout = "success"
            stderr = ""
        subprocess.run = lambda *args, **kwargs: DummyResult()
        try:
            response = self.client.post("/api/ips/deploy-firewall", json={"ip": "1.2.3.4"})
            self.assertEqual(response.status_code, 200)
            payload = response.json()
            self.assertTrue(payload["success"])
            self.assertIn("Firewall rule deployed to block 1.2.3.4", payload["message"])
        finally:
            subprocess.run = original_run


if __name__ == "__main__":
    unittest.main()
