import os
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

os.environ.setdefault("ADMIN_USERNAME", "testadmin")
os.environ.setdefault("ADMIN_PASSWORD", "TestPass123!")

from src.alert_store import (
    add_alert,
    add_alert_async,
    authenticate_user,
    authenticate_user_async,
    create_session,
    create_session_async,
    create_user,
    create_user_async,
    delete_session_async,
    get_connection,
    get_ip_reputation,
    get_ip_reputation_async,
    get_session,
    get_session_async,
    hash_password,
    is_ip_blocked,
    is_ip_blocked_async,
    list_alerts,
    list_alerts_async,
    list_all_reputations,
    list_all_reputations_async,
    list_blocked_ips,
    list_blocked_ips_async,
    unblock_ip,
    unblock_ip_async,
    update_ip_reputation,
    update_ip_reputation_async,
    verify_password,
)


class _TempDbMixin:
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db = str(Path(self._tmp.name) / "sentinel.db")

    def tearDown(self):
        self._tmp.cleanup()


class ReputationTests(_TempDbMixin, unittest.TestCase):
    def test_new_ip_below_threshold_not_blocked(self):
        self.assertFalse(update_ip_reputation("8.8.8.8", 35.0, db_path=self.db))
        self.assertFalse(is_ip_blocked("8.8.8.8", db_path=self.db))

    def test_ip_blocks_at_threshold(self):
        self.assertTrue(update_ip_reputation("8.8.8.8", 100.0, db_path=self.db))
        self.assertTrue(is_ip_blocked("8.8.8.8", db_path=self.db))

    def test_reputation_accumulates_across_calls(self):
        self.assertFalse(update_ip_reputation("9.9.9.9", 65.0, db_path=self.db))
        self.assertFalse(is_ip_blocked("9.9.9.9", db_path=self.db))
        self.assertTrue(update_ip_reputation("9.9.9.9", 65.0, db_path=self.db))

    def test_local_addresses_are_never_blocked(self):
        for ip in ("Unknown", "127.0.0.1", "Localhost"):
            self.assertFalse(update_ip_reputation(ip, 500.0, db_path=self.db))

    def test_list_blocked_ips_returns_only_blocked(self):
        update_ip_reputation("1.1.1.1", 100.0, db_path=self.db)
        update_ip_reputation("2.2.2.2", 10.0, db_path=self.db)
        blocked = list_blocked_ips(db_path=self.db)
        self.assertEqual([row["ip"] for row in blocked], ["1.1.1.1"])

    def test_unblock_resets_score(self):
        update_ip_reputation("1.1.1.1", 100.0, db_path=self.db)
        unblock_ip("1.1.1.1", db_path=self.db)
        self.assertFalse(is_ip_blocked("1.1.1.1", db_path=self.db))
        self.assertEqual(get_ip_reputation("1.1.1.1", db_path=self.db)["score"], 0.0)

    def test_get_ip_reputation_for_unknown_ip(self):
        self.assertEqual(
            get_ip_reputation("2.2.2.2", db_path=self.db),
            {"ip": "2.2.2.2", "score": 0.0, "blocked": False, "updated_at": None},
        )

    def test_list_all_reputations(self):
        update_ip_reputation("3.3.3.3", 40.0, db_path=self.db)
        self.assertEqual(len(list_all_reputations(db_path=self.db)), 1)


class PasswordTests(unittest.TestCase):
    def test_hash_and_verify_roundtrip(self):
        hashed, salt = hash_password("secret")
        self.assertTrue(verify_password("secret", salt, hashed))
        self.assertFalse(verify_password("wrong", salt, hashed))

    def test_hash_honours_explicit_salt(self):
        _, salt = hash_password("secret", salt="fixedsalt")
        self.assertEqual(salt, "fixedsalt")


class SessionExpiryTests(_TempDbMixin, unittest.TestCase):
    def test_expired_session_is_rejected_and_purged(self):
        create_user("expiring", "pass123", "ADMIN", db_path=self.db)
        token = create_session("expiring", db_path=self.db)

        with closing(get_connection(self.db)) as conn:
            conn.execute(
                "UPDATE sessions SET expires_at = ? WHERE token = ?",
                ("2000-01-01 00:00:00", token),
            )
            conn.commit()

        self.assertIsNone(get_session(token, db_path=self.db))
        with closing(get_connection(self.db)) as conn:
            remaining = conn.execute("SELECT COUNT(*) AS c FROM sessions").fetchone()["c"]
        self.assertEqual(remaining, 0)


class SyncAlertTests(_TempDbMixin, unittest.TestCase):
    def test_add_and_list_alerts_order_and_limit(self):
        add_alert(
            "XSS Attack",
            "6.6.6.6",
            "External / Internet",
            "first",
            timestamp="2026-01-01 00:00:00",
            db_path=self.db,
        )
        add_alert(
            "SQL Injection",
            "7.7.7.7",
            "External / Internet",
            "second",
            timestamp="2026-01-02 00:00:00",
            db_path=self.db,
        )
        newest = list_alerts(limit=1, newest_first=True, db_path=self.db)
        self.assertEqual(len(newest), 1)
        self.assertEqual(newest[0]["Type"], "SQL Injection")

    def test_authenticate_unknown_user_returns_none(self):
        self.assertIsNone(authenticate_user("ghost", "nope", db_path=self.db))


class AsyncAlertStoreTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db = str(Path(self._tmp.name) / "sentinel.db")

    async def asyncTearDown(self):
        self._tmp.cleanup()

    async def test_async_user_session_lifecycle(self):
        self.assertTrue(await create_user_async("asyncuser", "pass123", "ANALYST", db_path=self.db))
        user = await authenticate_user_async("asyncuser", "pass123", db_path=self.db)
        self.assertIsNotNone(user)
        self.assertEqual(user["role"], "ANALYST")

        token = await create_session_async("asyncuser", db_path=self.db)
        session = await get_session_async(token, db_path=self.db)
        self.assertEqual(session["username"], "asyncuser")

        await delete_session_async(token, db_path=self.db)
        self.assertIsNone(await get_session_async(token, db_path=self.db))

    async def test_async_reputation_blocklist_lifecycle(self):
        self.assertTrue(await update_ip_reputation_async("5.5.5.5", 100.0, db_path=self.db))
        self.assertTrue(await is_ip_blocked_async("5.5.5.5", db_path=self.db))

        blocked = await list_blocked_ips_async(db_path=self.db)
        self.assertEqual([row["ip"] for row in blocked], ["5.5.5.5"])

        rep = await get_ip_reputation_async("5.5.5.5", db_path=self.db)
        self.assertTrue(rep["blocked"])

        await unblock_ip_async("5.5.5.5", db_path=self.db)
        self.assertFalse(await is_ip_blocked_async("5.5.5.5", db_path=self.db))

        self.assertEqual(len(await list_all_reputations_async(db_path=self.db)), 1)

    async def test_async_local_address_never_blocked(self):
        self.assertFalse(await update_ip_reputation_async("127.0.0.1", 500.0, db_path=self.db))

    async def test_async_add_and_list_alerts(self):
        await add_alert_async(
            "XSS Attack",
            "6.6.6.6",
            "External / Internet",
            "async",
            timestamp="2026-01-01 00:00:00",
            db_path=self.db,
        )
        alerts = await list_alerts_async(db_path=self.db)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["Type"], "XSS Attack")


if __name__ == "__main__":
    unittest.main()
