import unittest

from src.config import FEATURE_SHORT_KEYS
from src.feature_extractor import FeatureExtractor


class FeatureExtractorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.extractor = FeatureExtractor()

    def test_extract_parses_valid_unified_line(self):
        line = (
            "192.168.1.5 - GET "
            "/traffic?dport=80&dur=1200&fpkts=8&bpkts=5&fwd_len=500"
            "&bwd_len=300&fwd_max=200&fwd_pkt_mean=62.5&bwd_max=150"
            "&bwd_pkt_mean=60&byte_rate=500.0&pkt_rate=10.5&iat_mean=20"
            "&iat_std=3.5&iat_min=1&fwd_iat_mean=18&fwd_iat_min=1"
            "&syn_cnt=1&rst_cnt=0&init_win_fwd=8192 HTTP/1.1"
        )

        features = self.extractor.extract(line)

        self.assertIsNotNone(features)
        self.assertEqual(features.shape, (1, len(FEATURE_SHORT_KEYS)))
        self.assertAlmostEqual(features[0][0], 80.0)
        self.assertAlmostEqual(features[0][1], 1200.0)
        self.assertAlmostEqual(features[0][2], 8.0)
        self.assertAlmostEqual(features[0][10], 500.0)
        self.assertAlmostEqual(features[0][19], 8192.0)

    def test_extract_defaults_missing_features_to_zero(self):
        line = "GET /traffic?dport=443&dur=10 HTTP/1.1"

        features = self.extractor.extract(line)

        self.assertIsNotNone(features)
        self.assertEqual(features.shape, (1, len(FEATURE_SHORT_KEYS)))
        self.assertAlmostEqual(features[0][0], 443.0)
        self.assertAlmostEqual(features[0][1], 10.0)
        self.assertAlmostEqual(features[0][2], 0.0)

    def test_extract_returns_none_for_normal_line(self):
        line = "GET /index.html HTTP/1.1"
        features = self.extractor.extract(line)
        self.assertIsNone(features)


if __name__ == "__main__":
    unittest.main()
