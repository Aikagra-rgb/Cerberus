import json
import urllib.request
import urllib.error
from urllib.parse import unquote_plus
import re


class AITriageAgent:
    """
    Hybrid AI Triage Agent.
    
    1. Checks if a local Ollama LLM server is active on startup.
    2. If Ollama is active, it queries the local LLM to generate custom security triage reports.
    3. If Ollama is offline, it falls back to a highly sophisticated local cyber-expert
        heuristics database to construct unlimited, instant, 100% free security mitigations.
    """

    def __init__(self, ollama_url="http://127.0.0.1:11434", model_name="llama3"):
        self.ollama_url = ollama_url
        self.model_name = model_name
        self.ollama_ready = self._check_ollama_service()

    def _check_ollama_service(self) -> bool:
        """Pings the local Ollama server to verify availability."""
        try:
            # Quick health check probe to Ollama's index
            response = urllib.request.urlopen(f"{self.ollama_url}/", timeout=1.5)
            return response.status == 200
        except Exception:
            return False

    def generate_triage_report(self, threat_type: str, source_ip: str, details: str) -> dict:
        """
        Generates a comprehensive security report containing attack analysis,
        mitigation checkmarks, and customized OS-level firewall scripts.
        """
        # 1. Generate customized OS-level blocking commands
        windows_cmd = f'New-NetFirewallRule -DisplayName "Block Cerberus Attacker {source_ip}" -Direction Inbound -Action Block -RemoteAddress {source_ip}'
        linux_cmd = f'sudo iptables -A INPUT -s {source_ip} -j DROP'

        # 2. Extract probability/confidence if present in details
        confidence = "100.0%"
        if "Confidence:" in details:
            try:
                confidence = details.split("Confidence:")[1].split("%")[0].strip() + "%"
            except IndexError:
                pass

        # 3. Check if we can run Generative LLM analysis
        if self.ollama_ready:
            try:
                report = self._query_ollama_llm(threat_type, source_ip, details, confidence, windows_cmd, linux_cmd)
                if report:
                    return report
            except Exception:
                pass # Fallback if model fails or crashes

        # 4. Fallback to Local Expert heuristics engine
        return self._generate_expert_fallback(threat_type, source_ip, details, confidence, windows_cmd, linux_cmd)

    def _query_ollama_llm(self, threat_type: str, source_ip: str, details: str, confidence: str, win_cmd: str, lin_cmd: str) -> dict | None:
        """Queries local Ollama instance for cybersecurity incident response analysis."""
        prompt = (
            f"You are an expert Security Operations Center (SOC) incident responder.\n"
            f"Analyze this high-severity intrusion alert caught by the Cerberus IDS:\n"
            f" - Attacking IP: {source_ip}\n"
            f" - Alert Classification: {threat_type}\n"
            f" - Classifier Details: {details}\n"
            f" - AI Model Ensemble Confidence: {confidence}\n\n"
            f"Generate a professional, structured JSON object with EXACTLY the following structure. "
            f"Do not output markdown code blocks outside of the JSON. Do not write extra sentences. "
            f"Your output must be parseable by json.loads() in Python:\n"
            f'{{\n'
            f'  "analysis": "A concise 2-3 sentence breakdown of the threat, how the payload targets vulnerabilities, and the potential impact.",\n'
            f'  "mitigations": [\n'
            f'    "Actionable step 1: Specific system or service configuration check.",\n'
            f'    "Actionable step 2: Configuration mitigation, WAF rule, or rate limiter setup.",\n'
            f'    "Actionable step 3: Administrative action (e.g. credential rotation, session termination)."\n'
            f'  ]\n'
            f'}}'
        )

        payload = {
            "model": self.model_name,
            "prompt": prompt,
            "stream": False,
            "format": "json"
        }

        try:
            req = urllib.request.Request(
                f"{self.ollama_url}/api/generate",
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"}
            )
            response = urllib.request.urlopen(req, timeout=10.0)
            result = json.loads(response.read().decode())
            parsed_response = json.loads(result["response"].strip())
            
            return {
                "probability": confidence,
                "analysis": parsed_response.get("analysis", "Threat analyzed successfully by local AI Agent."),
                "mitigations": parsed_response.get("mitigations", ["Block the attacker's IP.", "Verify server inputs."]),
                "firewall_cmd_windows": win_cmd,
                "firewall_cmd_linux": lin_cmd,
                "agent_mode": "Ollama LLM Mode"
            }
        except Exception:
            return None

    def _generate_expert_fallback(self, threat_type: str, source_ip: str, details: str, confidence: str, win_cmd: str, lin_cmd: str) -> dict:
        """Fallback heuristics database compiling granular incident response reports."""
        norm_details = unquote_plus(details).lower()
        threat_upper = threat_type.upper()

        analysis = "An anomalous log payload was detected that matches known heuristic threat profiles."
        mitigations = [
            "Block the attacker's IP address globally at the perimeter firewall.",
            "Verify all log headers and inputs to prevent parameter tampering.",
            "Review administrative configurations and application dependencies."
        ]

        # Case 1: SQL Injection
        if "SQL" in threat_upper or "UNION" in norm_details or "SELECT" in norm_details:
            analysis = (
                f"SQL Injection (SQLi) attempt detected from {source_ip}. "
                f"The attacker attempted to inject structured query commands (e.g., SELECT or UNION statements) "
                f"into web parameters to bypass authentication, expose system schemas, or hijack database contents."
            )
            mitigations = [
                "Implement Parameterized Queries (Prepared Statements) in the backend to ensure SQL commands are never compiled directly from input strings.",
                "Deploy a Web Application Firewall (WAF) rule to block common SQL payloads (like 'UNION SELECT' or 'OR 1=1').",
                "Ensure the database service user is running with restricted privileges (Least Privilege principle) to prevent file system reads/writes.",
                "Sanitize and validate all query-string inputs using strict alphanumeric whitelisting."
            ]

        # Case 2: XSS Attacks
        elif "XSS" in threat_upper or "SCRIPT" in norm_details or "ALERT(" in norm_details:
            analysis = (
                f"Cross-Site Scripting (XSS) attempt detected from {source_ip}. "
                f"The payload contained browser-executable script tokens (like <script> tags or javascript alerts) "
                f"designed to hijack legitimate users' session cookies, deface layouts, or inject drive-by downloads."
            )
            mitigations = [
                "Implement strict Context-Aware Output Encoding (e.g., converting '<' to '&lt;') before rendering parameters in HTML.",
                "Enable Content Security Policy (CSP) headers (e.g., Content-Security-Policy: default-src 'self') to prevent inline script execution.",
                "Apply the HttpOnly and Secure flags to all user session cookies, shielding them from client-side JavaScript access.",
                "Deploy input validation libraries to intercept malicious tags before processing."
            ]

        # Case 3: Path Traversal
        elif "TRAVERSAL" in threat_upper or "PASSWD" in norm_details or "../" in norm_details:
            analysis = (
                f"Directory / Path Traversal attempt detected from {source_ip}. "
                f"The attacker attempted to traverse the server directory hierarchy using directory dots (../) "
                f"to read sensitive operating system configurations (e.g., /etc/passwd or application config keys)."
            )
            mitigations = [
                "Configure absolute path resolution (canonicalization) on the web server to verify that requested files lie strictly within the designated public directory.",
                "Restrict file system read permissions of the web daemon process so it is forbidden from opening OS folders.",
                "Do not pass user-supplied input strings directly into file path resolver APIs.",
                "Deploy security rules to drop any request containing '../' or '%2e%2e/' URL sequences."
            ]

        # Case 4: File Tampering (FIM)
        elif "TAMPERING" in threat_upper or "FILE TAMPERING" in threat_upper:
            analysis = (
                f"File Integrity Monitoring (FIM) alarm triggered on the host. "
                f"The hashes of critical operating system binaries or server configurations do not match their trusted baselines, "
                f"indicating unauthorized file modification, malware injection, or a potential compromise."
            )
            mitigations = [
                "Isolate the host system immediately from the local network to prevent lateral movement or Command and Control (C2) communication.",
                "Inspect running system services and process lists (`tasklist` / `ps aux`) to identify unauthorized active binaries.",
                "Restore the modified file from a secure, read-only backup directory to re-establish the system baseline.",
                "Review administrative system access logs to determine who or what process modified the config."
            ]

        # Case 5: AI Anomalous Web Flood (AI-WEB)
        elif "AI-WEB" in threat_upper:
            analysis = (
                f"The AI Web Brain classified a network log line as anomalous with {confidence} confidence. "
                f"The parameter features (e.g., Flow Duration, Fwd Packet counts) indicate highly irregular flow patterns "
                f"that strongly correlate with web brute force attacks, SQLmap scanning tools, or automated payload floods."
            )
            mitigations = [
                "Deploy rate limiting constraints on the web server (e.g. Nginx `limit_req` module) to restrict request rates per client IP.",
                "Inspect the payload details to identify specific user-agents or headers representing automated bots, and drop them at the gate.",
                "Enforce CAPTCHA validations on input portals (such as logins) to block automated brute-force scripts."
            ]

        # Case 6: AI anomalous authentication (AI-AUTH)
        elif "AI-AUTH" in threat_upper:
            analysis = (
                f"The AI Authentication Brain caught an anomalous login flow profile with {confidence} confidence. "
                f"The extracted features indicate patterns typical of SSH Patator, FTP brute-forcing, or automated login credential stuffing."
            )
            mitigations = [
                "Enable Fail2ban or a similar brute-force blocker to automatically drop connection packets after 3-5 failed login attempts.",
                "Disable password authentication on critical access ports (e.g. SSH) in favor of secure public-key cryptography (authorized_keys).",
                "Change SSH and FTP default ports (e.g., mapping port 22 to a non-standard high port) to minimize automated script discoverability."
            ]

        # Case 7: AI Anomalous Traffic Floods (AI-DOS / AI-DDOS)
        elif "AI-DOS" in threat_upper or "AI-DDOS" in threat_upper:
            analysis = (
                f"The AI Flooding Brain caught a high-volume traffic flood with {confidence} confidence. "
                f"The flow profile (SYN bursts, RST flags, packet frequencies) indicates a DoS/DDoS LOIC flood, GoldenEye attack, or bulk packet flooding."
            )
            mitigations = [
                "Enable TCP SYN cookies on the operating system (`sysctl -w net.ipv4.tcp_syncookies=1`) to prevent SYN queue depletion under flood attacks.",
                "Configure the local firewall (iptables or Windows Firewall) to limit the max number of concurrent TCP connections per IP.",
                "Configure Nginx connection limits (`limit_conn`) to cap client socket allowances.",
                "Migrate the public endpoint behind a cloud-based DDoS mitigation proxy (e.g., Cloudflare) to absorb bulk volume spikes."
            ]

        return {
            "probability": confidence,
            "analysis": analysis,
            "mitigations": mitigations,
            "firewall_cmd_windows": win_cmd,
            "firewall_cmd_linux": lin_cmd,
            "agent_mode": "Local Cyber-Expert Fallback Mode"
        }
