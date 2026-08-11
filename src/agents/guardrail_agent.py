"""
Cerberus Multi-Agent Pipeline — Guardrail Agent
================================================
Uses DeepSeek V4 Pro (deep reasoning) to verify, validate, and
safety-check the Remediation Agent's output BEFORE it is shown
to the SOC analyst.

Checks performed:
  1. Dangerous command interception (rm -rf, mkfs, dd, format C:)
  2. Syntactic correctness of shell commands
  3. IP address consistency (remediation targets correct attacker IP)
  4. Hallucination detection (remediation matches the actual alert)
  5. Completeness check (all required fields are present and non-empty)

Output (JSON):
{
    "approved":          bool,
    "risk_score":        int,       # 0 (safe) - 100 (dangerous)
    "intercepted_items": list[str], # Issues found
    "corrections":       list[str], # Suggested fixes applied
    "verification_notes": str,
    "final_verdict":     str,       # "APPROVED" | "INTERCEPTED" | "CORRECTED"
}
"""

import re
from .llm_provider import call_llm_json

# Patterns that are ALWAYS dangerous regardless of context
_DANGEROUS_PATTERNS = [
    r"rm\s+-rf\s+/",
    r"mkfs\.",
    r"dd\s+if=.*of=/dev/(s|h)d",
    r"format\s+[Cc]:",
    r"del\s+/[Ff]\s+/[Ss]\s+/[Qq]\s+[Cc]:\\",
    r"shutdown\s+(-h|-r)\s+now",
    r":(){:|:&};:",   # Fork bomb
    r">\s*/etc/passwd",
    r">\s*/etc/shadow",
    r"chmod\s+777\s+/",
]

_SYSTEM_PROMPT = """You are the Cerberus Guardrail Agent — the final safety and verification layer.
Your role: audit the Remediation Agent's output for safety, accuracy, and quality.

Check for:
1. Dangerous shell commands that could cause system damage or data loss
2. Commands targeting the wrong IP address (should match the attacker IP provided)
3. Hallucinated or irrelevant content not related to the actual attack type
4. Missing or empty required fields
5. Syntactic errors in shell commands, YAML, or configurations

Return a JSON object with exactly these keys:
- approved          (boolean): true if output is safe & accurate, false if issues found
- risk_score        (integer): 0 (completely safe) to 100 (critically dangerous)
- intercepted_items (array of strings): List of specific problems found (empty array if none)
- corrections       (array of strings): List of corrections applied or recommended
- verification_notes (string): Your detailed reasoning for this verdict
- final_verdict     (string): Exactly one of "APPROVED", "INTERCEPTED", or "CORRECTED"
"""


def _static_safety_check(remediation: dict) -> list[str]:
    """Fast regex-based scan for obviously dangerous patterns."""
    dangerous = []
    for key in ["firewall_cmd_linux", "firewall_cmd_windows", "ansible_playbook"]:
        val = str(remediation.get(key, ""))
        for pattern in _DANGEROUS_PATTERNS:
            if re.search(pattern, val, re.IGNORECASE):
                dangerous.append(f"DANGEROUS PATTERN in '{key}': matched /{pattern}/")
    return dangerous


def run(
    remediation_result: dict,
    triage_result: dict,
    threat_type: str,
    source_ip: str,
) -> dict:
    """
    Run the Guardrail Agent to verify the remediation output.

    Args:
        remediation_result: Output from the Remediation Agent
        triage_result:      Output from the Triage Agent
        threat_type:        Original Cerberus alert type
        source_ip:          The attacker's IP address

    Returns:
        Guardrail verification verdict dict
    """
    # Step 1: Fast static regex scan (no LLM needed for obvious dangers)
    static_issues = _static_safety_check(remediation_result)

    if static_issues:
        return {
            "approved":           False,
            "risk_score":         95,
            "intercepted_items":  static_issues,
            "corrections":        ["Remediation output was blocked by static safety scanner."],
            "verification_notes": "Static regex guardrail detected critically dangerous shell patterns.",
            "final_verdict":      "INTERCEPTED",
        }

    # Step 2: Deep LLM-based verification via DeepSeek reasoning
    attack_class = triage_result.get("attack_class", threat_type)
    severity     = triage_result.get("severity", "HIGH")

    user_prompt = f"""
=== ORIGINAL ALERT ===
Attack Type  : {attack_class}
Attacker IP  : {source_ip}
Severity     : {severity}

=== REMEDIATION OUTPUT TO VERIFY ===
Firewall Linux  : {remediation_result.get('firewall_cmd_linux', 'N/A')}
Firewall Windows: {remediation_result.get('firewall_cmd_windows', 'N/A')}
Ansible Playbook: {str(remediation_result.get('ansible_playbook', ''))[:500]}
Sigma Rule      : {str(remediation_result.get('sigma_rule', ''))[:300]}
Patch Steps     : {remediation_result.get('patch_instructions', [])}
Summary         : {remediation_result.get('remediation_summary', 'N/A')}

Audit this remediation output. Return your verdict as a JSON object.
""".strip()

    try:
        result = call_llm_json(
            system_prompt=_SYSTEM_PROMPT,
            user_prompt=user_prompt,
            model_family="deepseek",
            temperature=0.05,
            max_tokens=700,
        )
        result.setdefault("approved",           True)
        result.setdefault("risk_score",         0)
        result.setdefault("intercepted_items",  [])
        result.setdefault("corrections",        [])
        result.setdefault("verification_notes", "All checks passed.")
        result.setdefault("final_verdict",      "APPROVED" if result["approved"] else "INTERCEPTED")
        return result
    except Exception as exc:
        # If Guardrail LLM fails, approve with a warning (fail-open for availability)
        return {
            "approved":           True,
            "risk_score":         10,
            "intercepted_items":  [],
            "corrections":        [],
            "verification_notes": f"Guardrail LLM check skipped (unavailable): {exc}. Static scan passed.",
            "final_verdict":      "APPROVED",
        }
