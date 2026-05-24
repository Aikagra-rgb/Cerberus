import json
import os
import re
from datetime import datetime
from urllib.parse import unquote_plus

from src.alert_store import add_alert, is_ip_blocked, update_ip_reputation
from src.config import DATA_DIR, MODEL_CONFIGS, MODELS_DIR
from src.feature_extractor import FeatureExtractor
from src.ai_triage import AITriageAgent


SIGNATURE_FILE = os.path.join(DATA_DIR, "signatures.json")

DEFAULT_SIGNATURES = [
    {"pattern": "UNION SELECT", "type": "SQL Injection", "severity": "Critical"},
    {"pattern": "<script>", "type": "XSS Attack", "severity": "High"},
    {"pattern": "/etc/passwd", "type": "Path Traversal", "severity": "Critical"},
]


def extract_ip(log_line):
    """Extracts the first IPv4 address from a log line."""
    regex = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    match = re.search(regex, log_line)
    return match.group(0) if match else "Unknown"


def classify_location(ip, location="Unknown"):
    """Small local-network classifier used until real geolocation exists."""
    if ip == "Unknown" or ip.startswith("192.168") or ip == "127.0.0.1" or ip.startswith("10."):
        return "Internal Network"
    if location == "Unknown":
        return "External / Internet"
    return location


def make_alert(threat_type, source_ip, location, details, timestamp=None, ai_report=None):
    timestamp = timestamp or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return {
        "Timestamp": timestamp,
        "Type": threat_type,
        "Source IP": source_ip,
        "Location": classify_location(source_ip, location),
        "Details": details.strip(),
        "ai_report": ai_report
    }


def get_threat_severity(threat_type):
    """Maps alert type to its respective severity level."""
    SEVERITY_MAP = {
        "SQL Injection": "CRITICAL",
        "XSS Attack": "HIGH",
        "Path Traversal": "CRITICAL",
        "File Tampering": "CRITICAL",
        "AI-WEB": "HIGH",
        "AI-AUTH": "HIGH",
        "AI-DOS": "CRITICAL",
        "AI-DDOS": "CRITICAL",
        "AI-RECON": "MEDIUM",
        "AI-BOTNET": "HIGH",
        "AI-INFILTRATION": "CRITICAL",
    }
    return SEVERITY_MAP.get(threat_type, "MEDIUM")


def get_score_for_severity(severity):
    """Maps severity level to reputation threat score additions."""
    SCORE_MAP = {
        "CRITICAL": 100.0,
        "HIGH": 65.0,
        "MEDIUM": 35.0,
        "LOW": 15.0
    }
    return SCORE_MAP.get(severity, 35.0)


def persist_alert(alert):
    add_alert(
        alert["Type"],
        alert["Source IP"],
        alert["Location"],
        alert["Details"],
        timestamp=alert["Timestamp"],
        ai_report=json.dumps(alert["ai_report"]) if alert["ai_report"] else None
    )


class SignatureEngine:
    def __init__(self, signature_file=SIGNATURE_FILE):
        self.signature_file = signature_file
        self.signatures = self.load_signatures()

    def _normalize(self, text):
        return unquote_plus(str(text)).lower()

    def load_signatures(self):
        if not os.path.exists(self.signature_file):
            try:
                with open(self.signature_file, "w") as f:
                    json.dump(DEFAULT_SIGNATURES, f, indent=4)
            except OSError:
                pass
            return DEFAULT_SIGNATURES

        try:
            with open(self.signature_file, "r") as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            return []

    def detect(self, line):
        normalized_line = self._normalize(line)
        for rule in self.signatures:
            pattern = self._normalize(rule.get("pattern", ""))
            if pattern and pattern in normalized_line:
                ip = extract_ip(line)
                return make_alert(
                    rule.get("type", "Signature Match"),
                    ip,
                    "Unknown",
                    f"Pattern matched: {rule.get('pattern', '')}",
                )
        return None

    def check(self, line, persist=True):
        alert = self.detect(line)
        if alert and persist:
            persist_alert(alert)
        return bool(alert)


class AIEngine:
    def __init__(self, load_models=True):
        self.models = {}
        self.extractor = FeatureExtractor()
        self.ready = False

        if load_models:
            for brain_name in MODEL_CONFIGS:
                self._load_brain(brain_name)
            self.ready = bool(self.models)

    def _load_brain(self, name):
        path = os.path.join(MODELS_DIR, f"{name}_classifier.pkl")
        if os.path.exists(path):
            try:
                import joblib
                self.models[name] = joblib.load(path)
            except Exception:
                pass

    def detect_all(self, line):
        if not self.ready:
            return []

        features = self.extractor.extract(line)
        if features is None:
            return []

        alerts = []
        for model_type, pipeline in self.models.items():
            prediction = pipeline.predict(features)
            if prediction[0] != 1:
                continue

            confidence = 0.0
            try:
                proba = pipeline.predict_proba(features)
                confidence = proba[0][1] * 100
            except Exception:
                pass

            ip = extract_ip(line)
            alerts.append(
                make_alert(
                    f"AI-{model_type.upper()}",
                    ip,
                    "Unknown",
                    f"Confidence: {confidence:.1f}% | Features: {features.tolist()}",
                )
            )
        return alerts

    def check_all(self, line, persist=True):
        alerts = self.detect_all(line)
        if persist:
            for alert in alerts:
                persist_alert(alert)
        return alerts


class DetectionService:
    def __init__(self, signature_engine=None, ai_engine=None, triage_agent=None):
        self.signature_engine = signature_engine or SignatureEngine()
        self.ai_engine = ai_engine or AIEngine()
        self.triage_agent = triage_agent or AITriageAgent()

    def process_log_line(self, line, persist=True, stop_after_signature=True):
        ip = extract_ip(line)
        
        # ==========================================
        # GATE 1: ACTIVE IPS INTERCEPTION CHECK
        # ==========================================
        if ip != "Unknown" and is_ip_blocked(ip):
            blocked_alert = make_alert(
                "Blocked by IPS",
                ip,
                "Unknown",
                "Connection blocked at active IPS gatekeeper. Suppressed AI/Signature checks.",
                ai_report=self.triage_agent.generate_triage_report(
                    "Blocked by IPS",
                    ip,
                    "IP was blacklisted automatically due to cumulative threat score reaching 100."
                )
            )
            if persist:
                persist_alert(blocked_alert)
            return [blocked_alert]

        alerts = []
        
        # 1. Signature Check
        signature_alert = self.signature_engine.detect(line)
        if signature_alert:
            # Generate AI Triage Report
            sev = get_threat_severity(signature_alert["Type"])
            triage_report = self.triage_agent.generate_triage_report(
                signature_alert["Type"],
                signature_alert["Source IP"],
                signature_alert["Details"]
            )
            signature_alert["ai_report"] = triage_report
            alerts.append(signature_alert)
            
            if persist:
                persist_alert(signature_alert)
                # Increment attacker IP reputation threat score
                score_to_add = get_score_for_severity(sev)
                update_ip_reputation(signature_alert["Source IP"], score_to_add)
                
            if stop_after_signature:
                return alerts

        # 2. AI Multi-Brain Checks
        ai_alerts = self.ai_engine.detect_all(line)
        for alert in ai_alerts:
            sev = get_threat_severity(alert["Type"])
            triage_report = self.triage_agent.generate_triage_report(
                alert["Type"],
                alert["Source IP"],
                alert["Details"]
            )
            alert["ai_report"] = triage_report
            alerts.append(alert)
            
            if persist:
                persist_alert(alert)
                score_to_add = get_score_for_severity(sev)
                update_ip_reputation(alert["Source IP"], score_to_add)
                
        return alerts
