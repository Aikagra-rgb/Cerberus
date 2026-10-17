import json
import os
import tempfile
import unittest
from unittest import mock

import numpy as np
from src.detection_service import (
    DEFAULT_SIGNATURES,
    AIEngine,
    DetectionService,
    SignatureEngine,
    classify_location,
    extract_ip,
    get_score_for_severity,
    get_threat_severity,
    make_alert,
)

# A simulation-format line (contains ?key=value params) so feature extraction succeeds.
SIM_LINE = "1.2.3.4 - GET /traffic?dport=80&dur=1200&fpkts=8 HTTP/1.1"


class _FakePipeline:
    def __init__(self, prediction=1, proba=0.9):
        self._prediction = prediction
        self._proba = proba

    def predict(self, features):
        return np.array([self._prediction])

    def predict_proba(self, features):
        p = self._proba
        return np.array([[1 - p, p]])


class _FakeSignatureEngine:
    def __init__(self, alert=None):
        self.alert = alert

    def detect(self, line):
        return self.alert


class _FakeAIEngine:
    def __init__(self, alerts=None, ready=True):
        self.alerts = alerts or []
        self.ready = ready

    def detect_all(self, line):
        return list(self.alerts)


class _FakeTriage:
    def generate_triage_report(self, *args, **kwargs):
        return {"summary": "synthetic triage"}


class HelperFunctionTests(unittest.TestCase):
    def test_extract_ip_finds_ipv4(self):
        self.assertEqual(extract_ip("bad login from 203.0.113.9"), "203.0.113.9")

    def test_extract_ip_returns_unknown_when_absent(self):
        self.assertEqual(extract_ip("no address here"), "Unknown")

    def test_classify_location_internal_networks(self):
        for ip in ("192.168.1.10", "10.0.0.5", "127.0.0.1", "Unknown"):
            self.assertEqual(classify_location(ip), "Internal Network")

    def test_classify_location_external_and_override(self):
        self.assertEqual(classify_location("8.8.8.8"), "External / Internet")
        self.assertEqual(classify_location("8.8.8.8", "Datacenter"), "Datacenter")

    def test_make_alert_builds_expected_shape(self):
        alert = make_alert(
            "XSS Attack", "8.8.8.8", "Unknown", "  payload  ", timestamp="2026-01-01 00:00:00"
        )
        self.assertEqual(alert["Type"], "XSS Attack")
        self.assertEqual(alert["Location"], "External / Internet")
        self.assertEqual(alert["Details"], "payload")
        self.assertEqual(alert["Timestamp"], "2026-01-01 00:00:00")

    def test_get_threat_severity_known_and_default(self):
        self.assertEqual(get_threat_severity("SQL Injection"), "CRITICAL")
        self.assertEqual(get_threat_severity("AI-RECON"), "MEDIUM")
        self.assertEqual(get_threat_severity("Unmapped Threat"), "MEDIUM")

    def test_get_score_for_severity_maps(self):
        self.assertEqual(get_score_for_severity("CRITICAL"), 100.0)
        self.assertEqual(get_score_for_severity("HIGH"), 65.0)
        self.assertEqual(get_score_for_severity("MEDIUM"), 35.0)
        self.assertEqual(get_score_for_severity("LOW"), 15.0)
        self.assertEqual(get_score_for_severity("UNKNOWN"), 35.0)


class SignatureEngineTests(unittest.TestCase):
    def test_load_signatures_creates_defaults_when_missing(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "sigs.json")
            engine = SignatureEngine(signature_file=path)
            self.assertTrue(os.path.exists(path))
            self.assertEqual(engine.signatures, DEFAULT_SIGNATURES)

    def test_load_signatures_handles_invalid_json(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "sigs.json")
            with open(path, "w") as f:
                f.write("not-json")
            engine = SignatureEngine(signature_file=path)
            self.assertEqual(engine.signatures, [])

    def _engine_with(self, rules):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = os.path.join(tmp.name, "sigs.json")
        with open(path, "w") as f:
            json.dump(rules, f)
        return SignatureEngine(signature_file=path)

    def test_detect_matches_url_encoded_pattern(self):
        engine = self._engine_with([{"pattern": "UNION SELECT", "type": "SQL Injection"}])
        alert = engine.detect("GET /?q=UNION%20SELECT+1")
        self.assertIsNotNone(alert)
        self.assertEqual(alert["Type"], "SQL Injection")
        self.assertIn("Pattern matched", alert["Details"])

    def test_detect_returns_none_without_match(self):
        engine = self._engine_with([{"pattern": "<script>", "type": "XSS Attack"}])
        self.assertIsNone(engine.detect("GET /index.html HTTP/1.1"))

    def test_check_returns_bool_and_persists(self):
        engine = self._engine_with([{"pattern": "<script>", "type": "XSS Attack"}])
        with mock.patch("src.detection_service.persist_alert") as persist:
            self.assertTrue(engine.check("GET /?x=<script>", persist=True))
        persist.assert_called_once()
        with mock.patch("src.detection_service.persist_alert") as persist:
            self.assertFalse(engine.check("GET /clean", persist=True))
        persist.assert_not_called()


class AIEngineTests(unittest.TestCase):
    def test_not_ready_returns_no_alerts(self):
        engine = AIEngine(load_models=False)
        self.assertFalse(engine.ready)
        self.assertEqual(engine.detect_all(SIM_LINE), [])

    def test_detect_all_produces_alert_for_positive_prediction(self):
        engine = AIEngine(load_models=False)
        engine.models = {"web": _FakePipeline(prediction=1)}
        engine.ready = True
        alerts = engine.detect_all(SIM_LINE)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["Type"], "AI-WEB")
        self.assertIn("Confidence:", alerts[0]["Details"])

    def test_detect_all_skips_benign_prediction(self):
        engine = AIEngine(load_models=False)
        engine.models = {"web": _FakePipeline(prediction=0)}
        engine.ready = True
        self.assertEqual(engine.detect_all(SIM_LINE), [])

    def test_check_all_persists_when_requested(self):
        engine = AIEngine(load_models=False)
        engine.models = {"web": _FakePipeline(prediction=1)}
        engine.ready = True
        with mock.patch("src.detection_service.persist_alert") as persist:
            alerts = engine.check_all(SIM_LINE, persist=True)
        self.assertEqual(len(alerts), 1)
        persist.assert_called_once()


class DetectionServiceTests(unittest.TestCase):
    def _service(self, sig_alert=None, ai_alerts=None):
        return DetectionService(
            signature_engine=_FakeSignatureEngine(sig_alert),
            ai_engine=_FakeAIEngine(ai_alerts),
            triage_agent=_FakeTriage(),
        )

    def test_blocked_ip_short_circuits(self):
        svc = self._service()
        with (
            mock.patch("src.detection_service.is_ip_blocked", return_value=True),
            mock.patch("src.detection_service.persist_alert") as persist,
        ):
            alerts = svc.process_log_line(SIM_LINE, persist=True)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["Type"], "Blocked by IPS")
        persist.assert_called_once()

    def test_signature_alert_returns_first(self):
        sig = make_alert("SQL Injection", "1.2.3.4", "Unknown", "Pattern matched")
        ai = make_alert("AI-WEB", "1.2.3.4", "Unknown", "Confidence: 90%")
        svc = self._service(sig_alert=sig, ai_alerts=[ai])
        with (
            mock.patch("src.detection_service.is_ip_blocked", return_value=False),
            mock.patch("src.detection_service.persist_alert"),
            mock.patch("src.detection_service.update_ip_reputation") as rep,
        ):
            alerts = svc.process_log_line(SIM_LINE, persist=True)
        self.assertEqual([a["Type"] for a in alerts], ["SQL Injection"])
        self.assertIn("ai_report", alerts[0])
        rep.assert_called_once()

    def test_signature_then_ai_when_not_stopping(self):
        sig = make_alert("SQL Injection", "1.2.3.4", "Unknown", "p")
        ai = make_alert("AI-WEB", "1.2.3.4", "Unknown", "c")
        svc = self._service(sig_alert=sig, ai_alerts=[ai])
        with (
            mock.patch("src.detection_service.is_ip_blocked", return_value=False),
            mock.patch("src.detection_service.persist_alert"),
            mock.patch("src.detection_service.update_ip_reputation"),
        ):
            alerts = svc.process_log_line(SIM_LINE, persist=True, stop_after_signature=False)
        self.assertEqual([a["Type"] for a in alerts], ["SQL Injection", "AI-WEB"])

    def test_ai_only_path(self):
        ai = make_alert("AI-WEB", "1.2.3.4", "Unknown", "c")
        svc = self._service(ai_alerts=[ai])
        with (
            mock.patch("src.detection_service.is_ip_blocked", return_value=False),
            mock.patch("src.detection_service.persist_alert"),
            mock.patch("src.detection_service.update_ip_reputation"),
        ):
            alerts = svc.process_log_line(SIM_LINE, persist=True)
        self.assertEqual([a["Type"] for a in alerts], ["AI-WEB"])

    def test_persist_false_skips_db_writes(self):
        ai = make_alert("AI-WEB", "1.2.3.4", "Unknown", "c")
        svc = self._service(ai_alerts=[ai])
        with (
            mock.patch("src.detection_service.is_ip_blocked", return_value=False),
            mock.patch("src.detection_service.persist_alert") as persist,
            mock.patch("src.detection_service.update_ip_reputation") as rep,
        ):
            svc.process_log_line(SIM_LINE, persist=False)
        persist.assert_not_called()
        rep.assert_not_called()


class DetectionServiceAsyncTests(unittest.IsolatedAsyncioTestCase):
    def _service(self, sig_alert=None, ai_alerts=None):
        return DetectionService(
            signature_engine=_FakeSignatureEngine(sig_alert),
            ai_engine=_FakeAIEngine(ai_alerts),
            triage_agent=_FakeTriage(),
        )

    async def test_async_blocked_ip_path(self):
        svc = self._service()
        with (
            mock.patch(
                "src.detection_service.is_ip_blocked_async", new=mock.AsyncMock(return_value=True)
            ),
            mock.patch(
                "src.detection_service.persist_alert_async", new=mock.AsyncMock()
            ) as persist,
        ):
            alerts = await svc.process_log_line_async(SIM_LINE, persist=True)
        self.assertEqual(alerts[0]["Type"], "Blocked by IPS")
        persist.assert_awaited_once()

    async def test_async_signature_and_ai_path(self):
        sig = make_alert("SQL Injection", "1.2.3.4", "Unknown", "p")
        ai = make_alert("AI-WEB", "1.2.3.4", "Unknown", "c")
        svc = self._service(sig_alert=sig, ai_alerts=[ai])
        with (
            mock.patch(
                "src.detection_service.is_ip_blocked_async", new=mock.AsyncMock(return_value=False)
            ),
            mock.patch("src.detection_service.persist_alert_async", new=mock.AsyncMock()),
            mock.patch(
                "src.detection_service.update_ip_reputation_async", new=mock.AsyncMock()
            ) as rep,
        ):
            alerts = await svc.process_log_line_async(
                SIM_LINE, persist=True, stop_after_signature=False
            )
        self.assertEqual([a["Type"] for a in alerts], ["SQL Injection", "AI-WEB"])
        self.assertEqual(rep.await_count, 2)


if __name__ == "__main__":
    unittest.main()
