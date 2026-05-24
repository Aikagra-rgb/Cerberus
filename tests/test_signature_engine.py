import json
import tempfile
import unittest
from pathlib import Path

from src.detection_service import DetectionService, SignatureEngine


class SignatureEngineTests(unittest.TestCase):
    def test_signature_engine_matches_known_pattern(self):
        engine = SignatureEngine()

        # Ensure at least one default signature exists
        self.assertGreater(len(engine.signatures), 0)
        pattern = engine.signatures[0]["pattern"]

        alert = engine.detect(f"Suspicious request containing {pattern} from 10.0.0.1")

        self.assertIsNotNone(alert)
        self.assertEqual(alert["Source IP"], "10.0.0.1")

    def test_signature_engine_decodes_url_encoded_patterns(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            signature_file = Path(tmp_dir) / "signatures.json"
            with open(signature_file, "w") as f:
                json.dump(
                    [
                        {
                            "pattern": "UNION SELECT",
                            "type": "SQL Injection",
                            "severity": "Critical",
                        }
                    ],
                    f,
                )

            engine = SignatureEngine(signature_file=str(signature_file))
            alert = engine.detect("GET /search?q=union+select+password from 203.0.113.10")

            self.assertIsNotNone(alert)
            self.assertEqual(alert["Type"], "SQL Injection")
            self.assertEqual(alert["Location"], "External / Internet")

    def test_detection_service_stops_after_signature_by_default(self):
        class CountingAIEngine:
            ready = False
            models = {}

            def __init__(self):
                self.calls = 0

            def detect_all(self, line):
                self.calls += 1
                return []

        signature_engine = SignatureEngine()
        ai_engine = CountingAIEngine()
        service = DetectionService(signature_engine=signature_engine, ai_engine=ai_engine)

        pattern = signature_engine.signatures[0]["pattern"]
        alerts = service.process_log_line(
            f"Suspicious request containing {pattern} from 10.0.0.1",
            persist=False,
        )

        self.assertEqual(len(alerts), 1)
        self.assertEqual(ai_engine.calls, 0)


if __name__ == "__main__":
    unittest.main()

