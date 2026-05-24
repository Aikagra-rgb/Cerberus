import csv
import tempfile
import unittest
from pathlib import Path

from src.alert_store import ALERT_COLUMNS, add_alert, list_alerts, migrate_legacy_csv


class AlertStoreTests(unittest.TestCase):
    def test_add_and_list_alerts(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = str(Path(tmp_dir) / "sentinel.db")

            add_alert(
                "SQL Injection",
                "10.0.0.1",
                "Internal Network",
                "Pattern matched: UNION SELECT",
                timestamp="2026-05-23 19:00:00",
                db_path=db_path,
            )

            alerts = list_alerts(db_path=db_path)

            self.assertEqual(len(alerts), 1)
            self.assertEqual(alerts[0]["Type"], "SQL Injection")
            self.assertEqual(alerts[0]["Source IP"], "10.0.0.1")

    def test_migrate_legacy_csv_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            db_path = str(tmp_path / "sentinel.db")
            csv_path = tmp_path / "hids_alerts.csv"

            with open(csv_path, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=ALERT_COLUMNS)
                writer.writeheader()
                writer.writerow(
                    {
                        "Timestamp": "2026-05-23 19:00:00",
                        "Type": "XSS Attack",
                        "Source IP": "203.0.113.5",
                        "Location": "External / Internet",
                        "Details": "Pattern matched: <script>",
                    }
                )

            first_count = migrate_legacy_csv(str(csv_path), db_path=db_path)
            second_count = migrate_legacy_csv(str(csv_path), db_path=db_path)
            alerts = list_alerts(db_path=db_path)

            self.assertEqual(first_count, 1)
            self.assertEqual(second_count, 0)
            self.assertEqual(len(alerts), 1)

    def test_user_auth_and_sessions(self):
        from src.alert_store import create_user, authenticate_user, create_session, get_session, delete_session
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = str(Path(tmp_dir) / "sentinel.db")

            # 1. Test User Creation
            self.assertTrue(create_user("testadmin", "adminpass", "ADMIN", db_path=db_path))
            # Test duplicate user protection
            self.assertFalse(create_user("testadmin", "otherpass", "ANALYST", db_path=db_path))

            # 2. Test User Authentication
            auth_success = authenticate_user("testadmin", "adminpass", db_path=db_path)
            self.assertIsNotNone(auth_success)
            self.assertEqual(auth_success["role"], "ADMIN")

            auth_fail = authenticate_user("testadmin", "wrongpass", db_path=db_path)
            self.assertIsNone(auth_fail)

            # 3. Test Sessions
            token = create_session("testadmin", db_path=db_path)
            self.assertIsNotNone(token)

            session_data = get_session(token, db_path=db_path)
            self.assertIsNotNone(session_data)
            self.assertEqual(session_data["username"], "testadmin")
            self.assertEqual(session_data["role"], "ADMIN")

            # Test session deletion
            delete_session(token, db_path=db_path)
            session_after_delete = get_session(token, db_path=db_path)
            self.assertIsNone(session_after_delete)


if __name__ == "__main__":
    unittest.main()

