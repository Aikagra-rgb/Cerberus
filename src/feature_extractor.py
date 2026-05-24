import re
import numpy as np
from src.config import FEATURE_SHORT_KEYS


# Apache/Nginx Combined Log Format regex:
# 192.168.1.1 - - [21/Nov/2025:12:00:01 +0000] "GET /page HTTP/1.1" 200 1234
_COMBINED_LOG_RE = re.compile(
    r'^(?P<ip>\S+)\s+'                     # client IP
    r'\S+\s+'                               # ident
    r'\S+\s+'                               # auth user
    r'\[(?P<time>[^\]]+)\]\s+'             # timestamp
    r'"(?P<method>\S+)\s+'                 # request method
    r'(?P<uri>\S+)\s+'                     # request URI
    r'(?P<proto>[^"]+)"\s+'                # protocol
    r'(?P<status>\d+)\s+'                  # status code
    r'(?P<size>\S+)'                       # response size
)

# Common attack-associated destination ports for heuristic scoring
_SUSPICIOUS_PORTS = {22, 23, 25, 53, 80, 443, 445, 1433, 3306, 3389, 5432, 8080, 8443}


class FeatureExtractor:
    """
    Extracts a unified 20-feature vector from log lines.

    All models use the SAME feature set (defined in src/config.py).
    This simplifies the pipeline: one extraction call serves every brain.

    Supports TWO log formats:

    1. **Simulation format** (primary — exact feature mapping):
        192.168.1.5 - GET /login?dur=1200&fpkts=8&bpkts=5&byte_rate=500.0 HTTP/1.1 200

    2. **Real Apache/Nginx Combined Log format** (fallback — heuristic features):
        192.168.1.1 - - [21/Nov/2025:12:00:01 +0000] "GET /page HTTP/1.1" 200 1234

    The simulation format provides exact CIC-IDS2017 flow features.
    The real-log parser derives heuristic estimates so that AI brains can
    still fire on production access logs (with reduced accuracy vs. trained data).
    """

    def __init__(self):
        self.short_keys = FEATURE_SHORT_KEYS

    def extract(self, log_line):
        """
        Parses a log line and returns a (1, 20) numpy array, or None
        if extraction fails or the line has no usable parameters.

        Tries simulation format first (key=value query params), then
        falls back to real Apache/Nginx combined log format parsing.
        """
        # Strategy 1: Simulation format (key=value pairs in query string)
        result = self._extract_simulation(log_line)
        if result is not None:
            return result

        # Strategy 2: Real Apache/Nginx combined log format
        result = self._extract_real_log(log_line)
        return result

    def _extract_simulation(self, log_line):
        """Extracts features from simulation-format log lines with ?key=value parameters."""
        try:
            if "?" not in log_line:
                return None

            params = re.findall(r'(\w+)=([\d\.\-]+)', log_line)
            param_dict = {k: float(v) for k, v in params}

            if not param_dict:
                return None

            # Check if at least one known feature key is present
            known_hits = sum(1 for k in param_dict if k in self.short_keys)
            if known_hits == 0:
                return None

            vector = [param_dict.get(key, 0.0) for key in self.short_keys]
            return np.array([vector])

        except Exception:
            return None

    def _extract_real_log(self, log_line):
        """
        Derives heuristic flow features from a real Apache/Nginx combined log line.

        These are rough approximations mapped to CIC-IDS2017 feature positions.
        Accuracy is lower than true network flow data but enables basic anomaly
        detection on production logs.
        """
        try:
            match = _COMBINED_LOG_RE.match(log_line.strip())
            if not match:
                return None

            uri = match.group("uri")
            status = int(match.group("status"))
            size_str = match.group("size")
            method = match.group("method").upper()

            # Parse response size (handle '-' for zero)
            resp_size = int(size_str) if size_str.isdigit() else 0

            # Estimate destination port from URI or default
            dport = 443.0 if "https" in log_line.lower() else 80.0

            # Heuristic: request URI length as proxy for payload size
            uri_len = float(len(uri))

            # Heuristic: query string complexity as proxy for flow features
            query_params = 0
            if "?" in uri:
                query_part = uri.split("?", 1)[1]
                query_params = query_part.count("&") + 1

            # Attack indicator flags based on status codes
            is_error = 1.0 if status >= 400 else 0.0
            is_server_error = 1.0 if status >= 500 else 0.0

            # Method-based risk scoring
            method_risk = {"GET": 0.0, "HEAD": 0.0, "POST": 1.0, "PUT": 2.0, "DELETE": 3.0}.get(method, 1.5)

            # Map heuristic values to the 20-feature positions:
            # This mapping is approximate — trained models expect true flow data,
            # but these heuristics allow the StandardScaler to produce
            # usable (if noisy) inputs for anomaly detection.
            vector = [
                dport,                  # dport:        Destination Port
                uri_len * 1000,         # dur:          Flow Duration (proxy: URI length × 1000µs)
                1.0 + query_params,     # fpkts:        Total Fwd Packets (1 base + params)
                1.0 if resp_size > 0 else 0.0,  # bpkts: Total Backward Packets
                uri_len,                # fwd_len:      Total Length of Fwd Packets (URI length)
                float(resp_size),       # bwd_len:      Total Length of Bwd Packets (response size)
                uri_len,                # fwd_max:      Fwd Packet Length Max
                uri_len,                # fwd_pkt_mean: Fwd Packet Length Mean
                float(resp_size),       # bwd_max:      Bwd Packet Length Max
                float(resp_size),       # bwd_pkt_mean: Bwd Packet Length Mean
                float(resp_size + uri_len),  # byte_rate: Flow Bytes/s (total bytes)
                2.0 + query_params,     # pkt_rate:     Flow Packets/s
                500.0 * (1 + is_error), # iat_mean:     Flow IAT Mean (error = longer IAT heuristic)
                100.0 * method_risk,    # iat_std:      Flow IAT Std
                10.0,                   # iat_min:      Flow IAT Min
                500.0,                  # fwd_iat_mean: Fwd IAT Mean
                10.0,                   # fwd_iat_min:  Fwd IAT Min
                1.0,                    # syn_cnt:      SYN Flag Count (1 per connection)
                is_server_error,        # rst_cnt:      RST Flag Count (server errors may RST)
                65535.0,                # init_win_fwd: Init Window bytes (default max)
            ]

            return np.array([vector])

        except Exception:
            return None

    def get_feature_count(self):
        """Returns the number of features in the unified vector."""
        return len(self.short_keys)
