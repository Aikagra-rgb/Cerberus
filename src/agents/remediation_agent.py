"""
Cerberus Multi-Agent Pipeline — Remediation Agent (Powered by NVIDIA Nemotron)
===============================================================================
Uses NVIDIA Nemotron-70B (strict instruction-following, precise code generation)
to draft actionable, syntax-validated security remediation artifacts:
  - OS-level firewall rules (Linux iptables + Windows PowerShell)
  - Nginx / Apache hardening configuration snippets
  - Ansible remediation playbook
  - Sigma detection rule
  - Step-by-step manual incident response checklist

Output (JSON):
{
    "firewall_cmd_linux":   str,
    "firewall_cmd_windows": str,
    "nginx_hardening":      str | null,
    "ansible_playbook":     str,
    "sigma_rule":           str,
    "patch_instructions":   list[str],
    "remediation_summary":  str,
}
"""

from .llm_provider import call_llm_json

_SYSTEM_PROMPT = """You are the Cerberus Remediation Agent — powered by NVIDIA Nemotron-70B.
You specialize in generating exact, production-ready security remediation artifacts.

STRICT RULES:
1. Return ONLY a valid JSON object. No markdown fences, no prose.
2. All shell commands must be syntactically correct and safe to execute.
3. NEVER include commands that could cause data loss (no rm -rf /, no truncate system files).
4. Ansible playbook must be valid YAML within the JSON string (use \\n for newlines).
5. Sigma rule must follow the official Sigma rule YAML specification.

Required JSON keys:
- firewall_cmd_linux   (string): Complete Linux iptables command to block the attacker IP
- firewall_cmd_windows (string): Complete PowerShell New-NetFirewallRule command
- nginx_hardening      (string or null): Relevant Nginx location block or header config if applicable, else null
- ansible_playbook     (string): Short Ansible playbook YAML (as escaped string) to remediate this attack class
- sigma_rule           (string): Sigma detection rule YAML (as escaped string) to detect this attack pattern
- patch_instructions   (array of strings): 4-6 step-by-step manual remediation actions for the SOC team
- remediation_summary  (string): 2-3 sentence summary of what actions were taken and their expected impact
"""


def run(
    triage_result: dict,
    research_result: dict,
    threat_type: str,
    source_ip: str,
    details: str,
) -> dict:
    """
    Run the Remediation Agent to generate security fixes using NVIDIA Nemotron.

    Args:
        triage_result:   Output from Triage Agent
        research_result: Output from Research Agent
        threat_type:     Original Cerberus alert type
        source_ip:       Attacker IP
        details:         Alert details

    Returns:
        Structured remediation artifacts dict
    """
    attack_class = triage_result.get("attack_class", threat_type)
    severity     = triage_result.get("severity", "HIGH")
    assets       = ", ".join(triage_result.get("affected_assets", ["Web Server"]))
    lifecycle    = research_result.get("attack_lifecycle_stage", "Initial Access")

    mitre_ids = ", ".join(
        t.get("id", "") for t in research_result.get("mitre_techniques", [])[:3]
    ) or "Unknown"

    user_prompt = f"""
=== REMEDIATION REQUEST ===
Attack Type         : {attack_class}
Severity            : {severity}
Attacker IP         : {source_ip}
Affected Assets     : {assets}
MITRE Techniques    : {mitre_ids}
Attack Lifecycle    : {lifecycle}
Alert Details       : {details}

Generate the complete remediation artifact JSON for this security incident.
""".strip()

    try:
        result = call_llm_json(
            system_prompt=_SYSTEM_PROMPT,
            user_prompt=user_prompt,
            model_family="nemotron",
            temperature=0.05,   # Very low temp for Nemotron — precision over creativity
            max_tokens=1500,
        )
        # Safety defaults
        result.setdefault(
            "firewall_cmd_linux",
            f"sudo iptables -A INPUT -s {source_ip} -j DROP && sudo iptables -A INPUT -s {source_ip} -j LOG --log-prefix 'CERBERUS_BLOCK: '"
        )
        result.setdefault(
            "firewall_cmd_windows",
            f'New-NetFirewallRule -DisplayName "Cerberus Block {source_ip}" -Direction Inbound -Action Block -RemoteAddress {source_ip}'
        )
        result.setdefault("nginx_hardening", None)
        result.setdefault(
            "ansible_playbook",
            f"---\n- name: Cerberus Remediation\n  hosts: all\n  tasks:\n    - name: Block attacker IP\n      iptables:\n        chain: INPUT\n        source: {source_ip}\n        jump: DROP"
        )
        result.setdefault("sigma_rule", f"title: Cerberus Detection - {attack_class}\nstatus: experimental\ndetection:\n    selection:\n        src_ip: '{source_ip}'\n    condition: selection")
        result.setdefault("patch_instructions", [
            f"Block attacker IP {source_ip} at all perimeter firewall layers.",
            f"Review all access logs for requests from {source_ip} in the past 24 hours.",
            f"Patch or disable the vulnerable {assets} endpoint immediately.",
            "Rotate all credentials that may have been exposed.",
            "Enable enhanced logging and alerting for this attack pattern.",
        ])
        result.setdefault("remediation_summary", f"IP {source_ip} has been identified as the attacker. Firewall rules deployed and remediation steps provided.")
        return result
    except Exception as exc:
        return {
            "firewall_cmd_linux":   f"sudo iptables -A INPUT -s {source_ip} -j DROP",
            "firewall_cmd_windows": f'New-NetFirewallRule -DisplayName "Cerberus Block {source_ip}" -Direction Inbound -Action Block -RemoteAddress {source_ip}',
            "nginx_hardening":      None,
            "ansible_playbook":     f"---\n- name: Block {source_ip}\n  hosts: all\n  tasks:\n    - iptables: chain=INPUT source={source_ip} jump=DROP",
            "sigma_rule":           f"title: Cerberus - {threat_type}\nstatus: experimental\ndetection:\n  selection:\n    src_ip: '{source_ip}'\n  condition: selection",
            "patch_instructions":   [
                f"Immediately block {source_ip} at the firewall.",
                "Investigate affected services for signs of compromise.",
                "Review and patch vulnerable endpoints.",
                "Notify security team and escalate if CRITICAL.",
            ],
            "remediation_summary":  f"Fallback remediation for {threat_type} from {source_ip}. Nemotron LLM unavailable.",
            "error":                str(exc),
        }
