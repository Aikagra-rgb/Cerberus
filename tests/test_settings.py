import unittest

from src.settings import Settings, get_settings


class SettingsTests(unittest.TestCase):
    def test_default_settings(self):
        settings = Settings(
            ADMIN_USERNAME="admintest",
            ADMIN_PASSWORD="PassTest123!",
            ALLOWED_ORIGINS="http://example.com, https://app.example.com",
            VERCEL_DOMAINS="my-app.vercel.app",
        )
        self.assertEqual(settings.ADMIN_USERNAME, "admintest")
        self.assertEqual(settings.ADMIN_PASSWORD, "PassTest123!")
        self.assertEqual(
            settings.get_allowed_origins_list(),
            ["http://example.com", "https://app.example.com"],
        )
        self.assertEqual(settings.get_vercel_domains_list(), ["my-app.vercel.app"])

    def test_empty_origins_parsing(self):
        settings = Settings(ALLOWED_ORIGINS="", VERCEL_DOMAINS="")
        self.assertEqual(settings.get_allowed_origins_list(), [])
        self.assertEqual(settings.get_vercel_domains_list(), [])

    def test_singleton_get_settings(self):
        s1 = get_settings()
        s2 = get_settings()
        self.assertIs(s1, s2)
