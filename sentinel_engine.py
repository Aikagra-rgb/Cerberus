import hashlib
import os
import threading
import time
from datetime import datetime

from src.alert_store import init_db
from src.config import DATA_DIR
from src.detection_service import (
    AIEngine,
    DetectionService,
    SIGNATURE_FILE,
    SignatureEngine,
    make_alert,
    persist_alert,
)


WEB_LOG_FILE = os.path.join(DATA_DIR, "demo_access.log")
AUTH_LOG_FILE = os.path.join(DATA_DIR, "demo_auth.log")
CRITICAL_FILES = ["critical_config.conf", "server_bin.exe"]


class Colors:
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    RESET = "\033[0m"


def log_incident(threat_type, ip, location, details):
    """Compatibility wrapper used by FIM and older tests."""
    alert = make_alert(
        threat_type,
        ip,
        location,
        details,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )
    try:
        persist_alert(alert)
    except Exception as e:
        print(f"{Colors.RED}[ERR] Cannot write alert to database: {e}{Colors.RESET}")


def print_alert(alert):
    alert_type = alert["Type"]
    ip = alert["Source IP"]
    details = alert["Details"]

    if alert_type.startswith("AI-"):
        confidence = 0.0
        if "Confidence:" in details:
            try:
                confidence = float(details.split("Confidence:")[1].split("%")[0].strip())
            except (ValueError, IndexError):
                pass

        if confidence >= 90:
            color = Colors.RED
        elif confidence >= 70:
            color = Colors.YELLOW
        else:
            color = Colors.CYAN

        print(
            f"{color}[AI ALERT] {alert_type[3:]} Attack detected from {ip} "
            f"(Confidence: {confidence:.1f}%){Colors.RESET}"
        )
        return

    print(f"{Colors.RED}[SIGNATURE MATCH] {alert_type} detected from {ip}{Colors.RESET}")


class FIMEngine:
    def __init__(self, files):
        self.files = files
        self.hashes = {}
        self.baseline_ready = False

    def calculate_hash(self, filepath):
        if not os.path.exists(filepath):
            return None
        sha = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                while chunk := f.read(4096):
                    sha.update(chunk)
            return sha.hexdigest()
        except OSError:
            return None

    def start(self):
        print(f"{Colors.GREEN}[INIT] FIM Monitoring Started.{Colors.RESET}")

        for f in self.files:
            if not os.path.exists(f):
                with open(f, "w") as t:
                    t.write("SECRET_CONFIG=TRUE")

        for f in self.files:
            self.hashes[f] = self.calculate_hash(f)
        self.baseline_ready = True

        while True:
            time.sleep(3)
            if not self.baseline_ready:
                continue

            for f in self.files:
                current_hash = self.calculate_hash(f)
                if current_hash != self.hashes.get(f):
                    print(f"\n{Colors.RED}[FIM ALERT] CRITICAL FILE MODIFIED: {f}{Colors.RESET}")
                    log_incident(
                        "File Tampering",
                        "Localhost",
                        "Server Internal",
                        f"Hash mismatch for {f}",
                    )
                    self.hashes[f] = current_hash


def monitor_log_file(path, detector, label):
    if not os.path.exists(path):
        open(path, "w").close()

    print(f"{Colors.BLUE}[INFO] Monitoring {label} Log: {path}{Colors.RESET}")
    last_pos = os.path.getsize(path)

    while True:
        try:
            if not os.path.exists(path):
                time.sleep(1)
                continue

            current_size = os.path.getsize(path)
            if current_size > last_pos:
                with open(path, "r", errors="ignore") as f:
                    f.seek(last_pos)
                    lines = f.readlines()
                    last_pos = f.tell()

                for line in lines:
                    if not line.strip():
                        continue
                    for alert in detector.process_log_line(line):
                        print_alert(alert)

            elif current_size < last_pos:
                last_pos = 0

            time.sleep(1)
        except Exception as e:
            print(f"{Colors.YELLOW}[WARN] {label} monitor error: {e}{Colors.RESET}")
            time.sleep(1)


def monitor_web_logs(detector):
    monitor_log_file(WEB_LOG_FILE, detector, "Web")


def monitor_auth_logs(detector):
    monitor_log_file(AUTH_LOG_FILE, detector, "Auth")


if __name__ == "__main__":
    print(
        r"""
   _____            _   _            _
  / ____|          | | (_)          | |
 | (___   ___ _ __ | |_ _ _ __   ___| |
  \___ \ / _ \ '_ \| __| | '_ \ / _ \ |
  ____) |  __/ | | | |_| | | | |  __/ |
 |_____/ \___|_| |_|\__|_|_| |_|\___|_|
         v6.0 - Service-Ready Random Forest HIDS
    """
    )

    init_db()
    detector = DetectionService()
    fim_engine = FIMEngine(CRITICAL_FILES)

    if detector.ai_engine.ready:
        print(
            f"{Colors.GREEN}[INIT] AI Engine Online. "
            f"Active Brains: {list(detector.ai_engine.models.keys())}{Colors.RESET}"
        )
    else:
        print(f"{Colors.RED}[WARN] No AI Brains loaded. Run 'python trainer.py --type all'.{Colors.RESET}")

    t_web = threading.Thread(target=monitor_web_logs, args=(detector,), daemon=True)
    t_auth = threading.Thread(target=monitor_auth_logs, args=(detector,), daemon=True)
    t_fim = threading.Thread(target=fim_engine.start, daemon=True)

    t_web.start()
    t_auth.start()
    t_fim.start()

    print(f"{Colors.CYAN}[SYSTEM] All Sentinels deployed. Press Ctrl+C to stop.{Colors.RESET}")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[SYSTEM] Shutting down...{Colors.RESET}")
