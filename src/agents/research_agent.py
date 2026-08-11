"""
Cerberus Multi-Agent Pipeline — Research Agent
===============================================
Uses DeepSeek V4 Pro + MITRE ATT&CK RAG to retrieve relevant threat
intelligence, technique IDs, tactics, and adversary behavior context
for the classified alert.

Output (JSON):
{
    "mitre_techniques": list[{id, name, tactics, relevance}],
    "threat_actor_context": str,
    "attack_lifecycle_stage": str,
    "key_indicators": list[str],
    "intelligence_summary": str,
}
"""

from .llm_provider import call_llm_json
from .rag_engine import get_rag_engine

_SYSTEM_PROMPT = """You are the Cerberus Research Agent — a threat intelligence specialist powered by MITRE ATT&CK.

You receive:
1. A triage analysis of an active security incident
2. Relevant MITRE ATT&CK technique context retrieved from the knowledge base

Your task: synthesize this information into a structured threat intelligence report.
Return ONLY a valid JSON object with these exact keys:

- mitre_techniques     (array): Top techniques relevant to this attack, each with:
    - id        (string):  MITRE technique ID (e.g. T1190)
    - name      (string):  Technique name
    - tactics   (array):   Associated tactics
    - relevance (string):  1 sentence explaining why this technique applies
- threat_actor_context    (string): Known threat actor groups or campaigns that use this technique
- attack_lifecycle_stage  (string): Reconnaissance | Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Exfiltration | Impact
- key_indicators          (array of strings): 3-5 key IoCs or behavioral indicators to look for
- intelligence_summary    (string): 2-3 sentence intelligence brief for the SOC analyst
"""


def run(triage_result: dict, threat_type: str, source_ip: str, details: str) -> dict:
    """
    Run the Research Agent on a triage result using MITRE RAG.

    Args:
        triage_result: Output dict from the Triage Agent
        threat_type:   Original Cerberus alert type
        source_ip:     Attacker IP
        details:       Alert details

    Returns:
        Structured threat intelligence dict with MITRE context
    """
    rag = get_rag_engine()

    # Build RAG search query from triage result
    query = " ".join([
        triage_result.get("attack_class", threat_type),
        triage_result.get("attack_vector", ""),
        " ".join(triage_result.get("affected_assets", [])),
        details,
    ])

    mitre_results = rag.search(query, top_k=5)
    mitre_context = rag.format_for_prompt(mitre_results)

    user_prompt = f"""
=== INCIDENT TRIAGE SUMMARY ===
Attack Class   : {triage_result.get('attack_class', threat_type)}
Severity       : {triage_result.get('severity', 'HIGH')}
Source IP      : {source_ip}
Attack Vector  : {triage_result.get('attack_vector', details)}
Affected Assets: {', '.join(triage_result.get('affected_assets', ['Unknown']))}
Blast Radius   : {triage_result.get('blast_radius', 'Unknown')}

=== MITRE ATT&CK RAG CONTEXT (Top Matches) ===
{mitre_context}

Based on the above, produce a structured threat intelligence report as JSON.
""".strip()

    try:
        result = call_llm_json(
            system_prompt=_SYSTEM_PROMPT,
            user_prompt=user_prompt,
            model_family="deepseek",
            temperature=0.15,
            max_tokens=1000,
        )
        # Ensure raw RAG hits are always embedded for UI display
        if "mitre_techniques" not in result or not result["mitre_techniques"]:
            result["mitre_techniques"] = [
                {
                    "id": t["id"],
                    "name": t["name"],
                    "tactics": t["tactics"],
                    "relevance": "Matched via MITRE ATT&CK RAG retrieval.",
                }
                for t in mitre_results[:3]
            ]
        result.setdefault("threat_actor_context",   "Unknown — no specific threat actor attribution.")
        result.setdefault("attack_lifecycle_stage",  "Initial Access")
        result.setdefault("key_indicators",          [source_ip, threat_type])
        result.setdefault("intelligence_summary",    f"Attack of type '{threat_type}' from {source_ip}.")
        return result
    except Exception as exc:
        return {
            "mitre_techniques": [
                {
                    "id": t["id"],
                    "name": t["name"],
                    "tactics": t["tactics"],
                    "relevance": "Retrieved via MITRE ATT&CK RAG fallback.",
                }
                for t in mitre_results[:3]
            ],
            "threat_actor_context":   "LLM unavailable — RAG fallback results shown.",
            "attack_lifecycle_stage": "Initial Access",
            "key_indicators":         [source_ip],
            "intelligence_summary":   f"'{threat_type}' from {source_ip}. LLM enrichment unavailable.",
            "error":                  str(exc),
        }
