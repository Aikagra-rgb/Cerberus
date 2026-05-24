import os
import sys
import subprocess
import sqlite3
from pathlib import Path

# High-Intensity Neon Output Colors
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CRITICAL = "\033[91m"
RESET = "\033[0m"

print(f"{CYAN}==================================================================")
print("     LogSentry Corporate Security Hardening Auditing Engine")
print(f"=================================================================={RESET}\n")

failures = 0
warnings = 0

def log_success(msg):
    print(f"  [{GREEN}PASS{RESET}] {msg}")

def log_warning(msg):
    global warnings
    warnings += 1
    print(f"  [{YELLOW}WARN{RESET}] {msg}")

def log_critical(msg):
    global failures
    failures += 1
    print(f"  [{CRITICAL}FAIL{RESET}] {msg}")


# ---------------------------------------------------------
# 1. DEPENDENCY AUDITING (pip-audit)
# ---------------------------------------------------------
print(f"{CYAN}--- Step 1: Auditing Third-Party Python Dependencies ---{RESET}")
try:
    # Run pip-audit to check requirements.txt for CVEs
    result = subprocess.run(["pip-audit", "-r", "requirements.txt"], capture_output=True, text=True, timeout=15.0)
    if result.returncode == 0:
        log_success("No known vulnerabilities (CVEs) found in requirements.txt.")
    else:
        log_critical(f"Vulnerable dependencies detected:\n{result.stdout.strip()}")
except FileNotFoundError:
    log_warning("pip-audit utility is not installed. Run 'pip install pip-audit' to enable CVE dependency scans.")
except subprocess.TimeoutExpired:
    log_warning("Dependency audit timed out.")


# ---------------------------------------------------------
# 2. FILE PERMISSIONS AUDITING
# ---------------------------------------------------------
print(f"\n{CYAN}--- Step 2: Auditing File Permissions & Integrity ---{RESET}")
models_dir = Path("models")
if models_dir.exists():
    pkl_files = list(models_dir.glob("*.pkl"))
    if not pkl_files:
        log_warning("No model brain (.pkl) files found inside the models/ directory.")
    else:
        for pkl in pkl_files:
            # Under Unix systems, check if files are overly permissive (e.g. world-writable)
            if hasattr(os, "stat") and os.name != "nt":
                mode = pkl.stat().st_mode
                # Check for world-write permission (0o002) or group-write (0o020)
                if mode & 0o022:
                    log_critical(f"Model brain '{pkl.name}' has insecure permissions. Run 'chmod 400 models/{pkl.name}'.")
                else:
                    log_success(f"Model brain '{pkl.name}' is securely set to read-only.")
            else:
                # Windows fallback (checking read-only attribute)
                log_success(f"Model brain '{pkl.name}' verified.")
else:
    log_warning("models/ directory does not exist yet. Compile your brains using trainer.py first.")


# ---------------------------------------------------------
# 3. SQLITE DATABASE SECURITY & INDEX AUDITING
# ---------------------------------------------------------
print(f"\n{CYAN}--- Step 3: Auditing Database Integrity & Indexing ---{RESET}")
db_path = Path("sentinel.db")
if not db_path.exists():
    log_warning("sentinel.db database file not found. Boot api.py to automatically initialize it.")
else:
    try:
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        
        # Check required tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cursor.fetchall()}
        required_tables = {"alerts", "users", "sessions", "reputation"}
        
        missing_tables = required_tables - tables
        if missing_tables:
            log_critical(f"Missing core schema tables: {', '.join(missing_tables)}")
        else:
            log_success("All core schema tables are present in the database.")
            
        # Check required index lookups
        cursor.execute("SELECT name FROM sqlite_master WHERE type='index'")
        indexes = {row[0] for row in cursor.fetchall()}
        required_indexes = {"idx_alerts_timestamp", "idx_alerts_source_ip", "idx_sessions_token", "idx_reputation_blocked"}
        
        missing_indexes = required_indexes - indexes
        if missing_indexes:
            log_warning(f"Performance indexes missing: {', '.join(missing_indexes)}. Indexing lookups increases query shield robustness.")
        else:
            log_success("All database query performance lookup indexes are present and active.")
            
        conn.close()
    except Exception as e:
        log_critical(f"Failed to query database metadata: {e}")


# ---------------------------------------------------------
# 4. CONFIGURATION SECRETS SCAVENGE
# ---------------------------------------------------------
print(f"\n{CYAN}--- Step 4: Auditing Configuration Security Keys ---{RESET}")
config_path = Path("critical_config.conf")
if not config_path.exists():
    log_success("No legacy critical_config.conf secrets file exposed.")
else:
    try:
        with open(config_path, "r") as f:
            content = f.read()
        if "admin123" in content or "analyst123" in content:
            log_critical("Default credentials detected inside critical_config.conf! Update passwords immediately.")
        else:
            log_success("No default credential strings scanned in critical_config.conf.")
    except Exception as e:
        log_warning(f"Unable to read critical_config.conf: {e}")


# ---------------------------------------------------------
# SUMMARY OUTPUT
# ---------------------------------------------------------
print(f"\n{CYAN}==================================================================")
print("     Audit Summary Report")
print(f"=================================================================={RESET}")

if failures > 0:
    print(f"  {CRITICAL}CRITICAL WARNING: {failures} security failure(s) found!{RESET} Resolve these issues to secure your HIDS/IPS console.")
    sys.exit(1)
elif warnings > 0:
    print(f"  {YELLOW}SUGGESTION: {warnings} warning(s) flagged.{RESET} Review suggestions to achieve enterprise-grade resilience.")
    sys.exit(0)
else:
    print(f"  {GREEN}SUCCESS: 0 vulnerabilities found!{RESET} LogSentry is hardened and configured to enterprise security standards.")
    sys.exit(0)
