"""
Cerberus Multi-Agent Pipeline — Triage Agent
=============================================
Uses DeepSeek V4 Pro (deep reasoning) to analyze an incoming alert,
classify the attack vector, assess blast radius, and assign severity.

Output (JSON):
{
    "attack_class":   str,   # e.g. "SQL Injection", "Remote Code Execution"
    "severity":       str,   # CRITICAL | HIGH | MEDIUM | LOW
    "attack_vector":  str,   # brief technical description
    "affected_assets": list[str],
    "blast_radius":   str,   # scope of potential damage
    "confidence":     float, # 0.0 - 1.0
    "summary":        str,   # 1-2 sentence analyst summary
}
"""

from .llm_provider import call_llm_json

_SYSTEM_PROMPT = """You are the Cerberus Triage Agent — an elite cybersecurity incident classifier.
Your task: analyze the provided security alert and return a JSON object with the exact structure shown.
Be precise, technical, and concise. Do NOT add commentary outside the JSON object.

Required JSON keys:
- attack_class    (string): The specific attack type (e.g. SQL Injection, Path Traversal, SSH Brute Force)
- severity        (string): One of CRITICAL / HIGH / MEDIUM / LOW
- attack_vector   (string): Technical description of how this attack works (1-2 sentences)
- affected_assets (array of strings): Services or data stores at risk (e.g. ["PostgreSQL DB", "Web Server", "Auth Service"])
- blast_radius    (string): What can the attacker achieve if successful? (1-2 sentences)
- confidence      (number): Your classification confidence between 0.0 and 1.0
- summary         (string): Executive-level 1-2 sentence summary of this incident
"""


def run(
    threat_type: str,
    source_ip: str,
    details: str,
    log_line: str = "",
) -> dict:
    """
    Run the Triage Agent on a detected alert.

    Args:
        threat_type: Alert type from Cerberus signature/AI engine
        source_ip:   Source IP of the attacker
        details:     Alert detail string from Cerberus
        log_line:    Original raw log line (optional)

    Returns:
        Structured triage analysis dict
    """
    user_prompt = f"""
=== CERBERUS ALERT ===
Threat Type  : {threat_type}
Source IP    : {source_ip}
Details      : {details}
Raw Log Line : {log_line or 'N/A'}

Analyze this alert and return your classification as a JSON object.
""".strip()

    try:
        result = call_llm_json(
            system_prompt=_SYSTEM_PROMPT,
            user_prompt=user_prompt,
            model_family="deepseek",
            temperature=0.1,
            max_tokens=800,
        )
        # Validate required keys exist
        result.setdefault("attack_class",    threat_type)
        result.setdefault("severity",        "HIGH")
        result.setdefault("attack_vector",   details)
        result.setdefault("affected_assets", ["Web Server"])
        result.setdefault("blast_radius",    "Unknown — further investigation required.")
        result.setdefault("confidence",      0.85)
        result.setdefault("summary",         f"{threat_type} attack detected from {source_ip}.")
        return result
    except Exception as exc:
        # Structured fallback so Orchestrator never crashes
        return {
            "attack_class":    threat_type,
            "severity":        "HIGH",
            "attack_vector":   details,
            "affected_assets": ["Unknown"],
            "blast_radius":    "Could not determine — LLM unavailable.",
            "confidence":      0.5,
            "summary":         f"{threat_type} detected from {source_ip}. Manual review required.",
            "error":           str(exc),
        }
