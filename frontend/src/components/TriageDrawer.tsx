import React, { useEffect, useState } from "react";
import {
  AlertRecord,
  MultiAgentPipelineResult,
  severityFor,
  UserSession,
} from "../types";
import {
  X,
  Zap,
  ShieldAlert,
  Copy,
  Check,
  Terminal,
  Cpu,
  ShieldCheck,
  AlertTriangle,
} from "lucide-react";

interface TriageDrawerProps {
  alert: AlertRecord | null;
  onClose: () => void;
  apiBase: string;
  user: UserSession | null;
  authHeaders: () => Record<string, string>;
  onRefresh: () => void;
  notify: (msg: string, type?: "info" | "success" | "error") => void;
}

type AgentKey = "triage" | "research" | "remediation" | "guardrail";
type AgentState = "pending" | "running" | "done" | "error" | "intercepted";
type RemTab = "firewall" | "ansible" | "sigma" | "steps";

export const TriageDrawer: React.FC<TriageDrawerProps> = ({
  alert,
  onClose,
  apiBase,
  user,
  authHeaders,
  onRefresh,
  notify,
}) => {
  const [running, setRunning] = useState(false);
  const [pipelineResult, setPipelineResult] = useState<MultiAgentPipelineResult | null>(null);
  const [agentStatuses, setAgentStatuses] = useState<
    Record<AgentKey, { status: AgentState; latency?: number }>
  >({
    triage: { status: "pending" },
    research: { status: "pending" },
    remediation: { status: "pending" },
    guardrail: { status: "pending" },
  });
  const [activeRemTab, setActiveRemTab] = useState<RemTab>("firewall");
  const [deployingFirewall, setDeployingFirewall] = useState(false);
  const [deployMessage, setDeployMessage] = useState<string>("");
  const [deploySuccess, setDeploySuccess] = useState<boolean | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  useEffect(() => {
    setPipelineResult(null);
    setAgentStatuses({
      triage: { status: "pending" },
      research: { status: "pending" },
      remediation: { status: "pending" },
      guardrail: { status: "pending" },
    });
    setActiveRemTab("firewall");
    setDeployMessage("");
    setDeploySuccess(null);
  }, [alert]);

  if (!alert) return null;

  const severity = severityFor(alert.Type);
  const sourceIp = alert["Source IP"] || "0.0.0.0";

  const copyText = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    notify("Copied command to clipboard", "success");
    setTimeout(() => setCopiedId(null), 1800);
  };

  const runMultiAgentPipeline = async () => {
    setRunning(true);
    setPipelineResult(null);
    setAgentStatuses({
      triage: { status: "running" },
      research: { status: "pending" },
      remediation: { status: "pending" },
      guardrail: { status: "pending" },
    });

    try {
      const resp = await fetch(`${apiBase}/api/triage/multi-agent`, {
        method: "POST",
        headers: authHeaders(),
        body: JSON.stringify({
          threat_type: alert.Type || "Unknown Threat",
          source_ip: sourceIp,
          details: alert.Details || "",
          log_line: alert["Log Line"] || alert.Details || "",
        }),
      });

      if (!resp.ok) {
        const err = await resp.json().catch(() => ({}));
        throw new Error(err.detail || resp.statusText || "Pipeline failed");
      }

      const data: MultiAgentPipelineResult = await resp.json();
      setPipelineResult(data);

      const nextStatuses: Record<AgentKey, { status: AgentState; latency?: number }> = {
        triage: { status: "done" },
        research: { status: "done" },
        remediation: { status: "done" },
        guardrail: { status: "done" },
      };

      const stepMap: Record<string, AgentKey> = {
        "Triage Agent": "triage",
        "Research Agent": "research",
        "Remediation Agent": "remediation",
        "Guardrail Agent": "guardrail",
      };

      for (const s of data.steps || []) {
        const key = stepMap[s.agent];
        if (key) {
          nextStatuses[key] = {
            status: (s.status as AgentState) || "done",
            latency: s.latency_ms,
          };
        }
      }
      setAgentStatuses(nextStatuses);
      notify("Multi-Agent DevSecOps analysis completed", "success");
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Pipeline failed";
      setAgentStatuses({
        triage: { status: "error" },
        research: { status: "error" },
        remediation: { status: "error" },
        guardrail: { status: "error" },
      });
      notify(message, "error");
    } finally {
      setRunning(false);
    }
  };

  const handleDeployFirewall = async () => {
    if (!user || user.role !== "ADMIN") {
      notify("Administrator privileges required to deploy firewall rules", "error");
      return;
    }
    setDeployingFirewall(true);
    setDeployMessage("Deploying host OS firewall rule...");
    setDeploySuccess(null);

    try {
      const resp = await fetch(`${apiBase}/api/ips/deploy-firewall`, {
        method: "POST",
        headers: authHeaders(),
        body: JSON.stringify({ ip: sourceIp }),
      });
      const payload = await resp.json().catch(() => ({}));
      if (resp.ok && payload.success) {
        setDeploySuccess(true);
        setDeployMessage(payload.message || `Firewall rule deployed for ${sourceIp}`);
        notify(`Firewall rule deployed for ${sourceIp}`, "success");
        onRefresh();
      } else {
        setDeploySuccess(false);
        setDeployMessage(payload.message || payload.detail || "Firewall execution failed");
        notify("Firewall rule deployment failed", "error");
      }
    } catch (err: unknown) {
      setDeploySuccess(false);
      setDeployMessage(err instanceof Error ? err.message : "Connection error");
    } finally {
      setDeployingFirewall(false);
    }
  };

  const defaultLinuxCmd =
    pipelineResult?.remediation?.firewall_cmd_linux ||
    `sudo iptables -A INPUT -s ${sourceIp} -j DROP`;
  const defaultWinCmd =
    pipelineResult?.remediation?.firewall_cmd_windows ||
    `New-NetFirewallRule -DisplayName "Block Cerberus Attacker ${sourceIp}" -Direction Inbound -Action Block -RemoteAddress ${sourceIp}`;
  const ansiblePlaybook =
    pipelineResult?.remediation?.ansible_playbook ||
    `---\n- name: Quarantine Attacker ${sourceIp}\n  hosts: perimeter\n  become: true\n  tasks:\n    - name: Drop traffic from ${sourceIp}\n      ansible.builtin.iptables:\n        chain: INPUT\n        source: ${sourceIp}\n        jump: DROP`;
  const sigmaRule =
    pipelineResult?.remediation?.sigma_rule ||
    `title: Cerberus Alert - ${alert.Type}\nstatus: experimental\nlogsource:\n  category: webserver\ndetection:\n  selection:\n    c-ip: '${sourceIp}'\n  condition: selection\nlevel: ${severity.toLowerCase()}`;
  const remediationSteps = pipelineResult?.remediation?.patch_instructions?.length
    ? pipelineResult.remediation.patch_instructions
    : [
        `Block attacker IP ${sourceIp} at the perimeter firewall and IPS gateway.`,
        `Audit recent access logs from ${sourceIp} for secondary payloads or lateral movement.`,
        `Verify input sanitization and WAF rules against ${alert.Type}.`,
      ];

  const agentMeta: Array<{ key: AgentKey; name: string; model: string; icon: string }> = [
    { key: "triage", name: "Triage Agent", model: "DeepSeek V4 Pro", icon: "🎯" },
    { key: "research", name: "Research Agent", model: "MITRE RAG + DeepSeek", icon: "🔬" },
    { key: "remediation", name: "Remediation Agent", model: "NVIDIA Nemotron-70B", icon: "🔧" },
    { key: "guardrail", name: "Guardrail Agent", model: "DeepSeek V4 Pro", icon: "🛡️" },
  ];

  return (
    <div className="drawer-backdrop" onClick={onClose}>
      <aside
        className="triage-console open"
        onClick={(e) => e.stopPropagation()}
        aria-label="Multi-Agent Triage Console"
      >
        <header className="triage-header">
          <div className="triage-brand">
            <span className="pulse-ring">
              <Cpu size={20} />
            </span>
            <div>
              <h3>Multi-Agent Incident Triage</h3>
              <span className="drawer-subtitle">4-Stage Autonomous DevSecOps Pipeline</span>
            </div>
          </div>
          <button
            className="close-triage-btn"
            type="button"
            onClick={onClose}
            title="Close Panel (Esc)"
          >
            <X size={18} />
          </button>
        </header>

        <div className="triage-body">
          {/* Incident Context Summary */}
          <section className="triage-summary-card">
            <div className="summary-row">
              <span className="summary-label">Threat Classification</span>
              <span className={`severity-pill ${severity.toLowerCase()}`}>{alert.Type}</span>
            </div>
            <div className="summary-row">
              <span className="summary-label">Source IPv4</span>
              <strong className="mono">{sourceIp}</strong>
            </div>
            <div className="summary-row">
              <span className="summary-label">Timestamp</span>
              <span className="mono text-dim" style={{ fontSize: 12 }}>
                {alert.Timestamp}
              </span>
            </div>
            <div className="summary-row">
              <span className="summary-label">Telemetry Details</span>
              <span className="text-dim" style={{ fontSize: 12, textAlign: "right", maxWidth: 260 }}>
                {alert.Details || "Signature / AI Heuristic Trigger"}
              </span>
            </div>
          </section>

          {/* 4-Agent Pipeline Stepper */}
          <section className="triage-section">
            <div className="section-title-row">
              <h4>⚡ Autonomous Agent Pipeline</h4>
              {pipelineResult?.total_latency_ms && (
                <span className="latency-chip">
                  {(pipelineResult.total_latency_ms / 1000).toFixed(2)}s total
                </span>
              )}
            </div>

            <div className="agent-pipeline-grid">
              {agentMeta.map((a) => {
                const st = agentStatuses[a.key];
                const badgeText =
                  st.status === "done" && st.latency
                    ? `${st.latency}ms`
                    : st.status.toUpperCase();
                return (
                  <div key={a.key} className={`agent-step ${st.status}`}>
                    <div className="agent-step-icon">{a.icon}</div>
                    <div className="agent-step-info">
                      <div className="agent-step-name">{a.name}</div>
                      <div className="agent-step-model">{a.model}</div>
                    </div>
                    <div className={`agent-step-badge ${st.status}`}>{badgeText}</div>
                  </div>
                );
              })}
            </div>

            <button
              type="button"
              className="button button-primary width-100"
              style={{ marginTop: 12, display: "flex", alignItems: "center", justifyContent: "center", gap: 8 }}
              disabled={running}
              onClick={runMultiAgentPipeline}
            >
              <Zap size={16} />
              {running ? "Executing 4-Agent Pipeline..." : "Run Multi-Agent Analysis"}
            </button>
          </section>

          {/* Triage Output */}
          <section className="triage-section">
            <h4>🎯 Triage Assessment</h4>
            <div className="triage-content-box">
              {pipelineResult?.triage ? (
                <>
                  <div style={{ display: "flex", gap: 10, alignItems: "center", marginBottom: 8 }}>
                    <span
                      className={`severity-pill ${(pipelineResult.triage.severity || severity).toLowerCase()}`}
                    >
                      {pipelineResult.triage.severity || severity}
                    </span>
                    <span className="mono text-dim" style={{ fontSize: 11 }}>
                      Confidence: {((pipelineResult.triage.confidence ?? 0.92) * 100).toFixed(0)}%
                    </span>
                  </div>
                  <p style={{ fontSize: 13, fontWeight: 600, color: "#f8fafc", marginBottom: 6 }}>
                    {pipelineResult.triage.attack_class || alert.Type}
                  </p>
                  <p style={{ fontSize: 12, color: "#94a3b8", marginBottom: 6 }}>
                    {pipelineResult.triage.attack_vector || alert.Details}
                  </p>
                  {pipelineResult.triage.blast_radius && (
                    <p style={{ fontSize: 12, color: "#cbd5e1", marginTop: 6 }}>
                      <strong>Blast Radius:</strong> {pipelineResult.triage.blast_radius}
                    </p>
                  )}
                  {pipelineResult.triage.summary && (
                    <p
                      style={{
                        fontSize: 12,
                        color: "#cbd5e1",
                        marginTop: 8,
                        paddingTop: 8,
                        borderTop: "1px solid rgba(148,163,184,0.12)",
                      }}
                    >
                      {pipelineResult.triage.summary}
                    </p>
                  )}
                </>
              ) : (
                <p style={{ fontSize: 12.5, color: "#94a3b8" }}>
                  {alert.Details ||
                    "Click 'Run Multi-Agent Analysis' to execute deep LLM triage, MITRE ATT&CK RAG correlation, and guardrail verification."}
                </p>
              )}
            </div>
          </section>

          {/* MITRE ATT&CK Research Output */}
          {pipelineResult?.research && (
            <section className="triage-section">
              <h4>🔬 MITRE ATT&CK Intelligence</h4>
              <div className="triage-content-box">
                <p style={{ fontSize: 12, color: "#cbd5e1", marginBottom: 6 }}>
                  <strong>Lifecycle Stage:</strong>{" "}
                  {pipelineResult.research.attack_lifecycle_stage || "Initial Access"}
                </p>
                <p style={{ fontSize: 12, color: "#94a3b8", marginBottom: 8 }}>
                  {pipelineResult.research.intelligence_summary}
                </p>
                {pipelineResult.research.mitre_techniques &&
                  pipelineResult.research.mitre_techniques.length > 0 && (
                    <div className="mitre-tags" style={{ marginTop: 8 }}>
                      {pipelineResult.research.mitre_techniques.map((t) => (
                        <span key={t.id} className="mitre-tag" title={t.name}>
                          {t.id} · {t.name}
                        </span>
                      ))}
                    </div>
                  )}
              </div>
            </section>
          )}

          {/* Remediation Playbook Tabs */}
          <section className="triage-section">
            <h4>🔧 Remediation Playbook</h4>
            <div className="remediation-tabs">
              {(["firewall", "ansible", "sigma", "steps"] as RemTab[]).map((tab) => (
                <button
                  key={tab}
                  type="button"
                  className={`rem-tab ${activeRemTab === tab ? "active" : ""}`}
                  onClick={() => setActiveRemTab(tab)}
                >
                  {tab === "firewall"
                    ? "Firewall CLI"
                    : tab === "ansible"
                    ? "Ansible YAML"
                    : tab === "sigma"
                    ? "Sigma Rule"
                    : "Action Steps"}
                </button>
              ))}
            </div>

            {activeRemTab === "firewall" && (
              <div>
                <div className="terminal-container">
                  <div className="terminal-header">
                    <span>
                      <Terminal size={12} style={{ marginRight: 5, verticalAlign: "middle" }} />
                      Linux iptables
                    </span>
                    <button
                      type="button"
                      className="copy-terminal-btn"
                      onClick={() => copyText(defaultLinuxCmd, "lin")}
                    >
                      {copiedId === "lin" ? <Check size={12} /> : <Copy size={12} />}{" "}
                      {copiedId === "lin" ? "Copied" : "Copy"}
                    </button>
                  </div>
                  <pre className="terminal-body">
                    <span className="prompt">$</span> <code>{defaultLinuxCmd}</code>
                  </pre>
                </div>

                <div className="terminal-container">
                  <div className="terminal-header">
                    <span>
                      <Terminal size={12} style={{ marginRight: 5, verticalAlign: "middle" }} />
                      Windows PowerShell
                    </span>
                    <button
                      type="button"
                      className="copy-terminal-btn"
                      onClick={() => copyText(defaultWinCmd, "win")}
                    >
                      {copiedId === "win" ? <Check size={12} /> : <Copy size={12} />}{" "}
                      {copiedId === "win" ? "Copied" : "Copy"}
                    </button>
                  </div>
                  <pre className="terminal-body">
                    <span className="prompt">PS&gt;</span> <code>{defaultWinCmd}</code>
                  </pre>
                </div>
              </div>
            )}

            {activeRemTab === "ansible" && (
              <div className="terminal-container">
                <div className="terminal-header">
                  <span>Ansible Remediation Playbook</span>
                  <button
                    type="button"
                    className="copy-terminal-btn"
                    onClick={() => copyText(ansiblePlaybook, "ansible")}
                  >
                    {copiedId === "ansible" ? "Copied" : "Copy"}
                  </button>
                </div>
                <pre className="terminal-body">
                  <code>{ansiblePlaybook}</code>
                </pre>
              </div>
            )}

            {activeRemTab === "sigma" && (
              <div className="terminal-container">
                <div className="terminal-header">
                  <span>Sigma Detection Rule</span>
                  <button
                    type="button"
                    className="copy-terminal-btn"
                    onClick={() => copyText(sigmaRule, "sigma")}
                  >
                    {copiedId === "sigma" ? "Copied" : "Copy"}
                  </button>
                </div>
                <pre className="terminal-body">
                  <code>{sigmaRule}</code>
                </pre>
              </div>
            )}

            {activeRemTab === "steps" && (
              <ul className="triage-list">
                {remediationSteps.map((step, i) => (
                  <li key={i}>{step}</li>
                ))}
              </ul>
            )}
          </section>

          {/* Guardrail Verdict */}
          {pipelineResult?.guardrail && (
            <section className="triage-section">
              <h4>🛡️ Guardrail Safety Verification</h4>
              <div
                className={`guardrail-verdict ${(
                  pipelineResult.guardrail.final_verdict || "APPROVED"
                ).toLowerCase()}`}
              >
                {pipelineResult.guardrail.final_verdict === "INTERCEPTED" ? (
                  <AlertTriangle size={20} />
                ) : (
                  <ShieldCheck size={20} />
                )}
                <div>
                  <div>{pipelineResult.guardrail.final_verdict || "APPROVED"}</div>
                  <div style={{ fontSize: 11, fontWeight: 400, opacity: 0.85 }}>
                    Risk Score: {pipelineResult.guardrail.risk_score ?? 0}/100
                  </div>
                </div>
              </div>
              {pipelineResult.guardrail.verification_notes && (
                <div className="triage-content-box" style={{ marginTop: 8, fontSize: 12 }}>
                  {pipelineResult.guardrail.verification_notes}
                </div>
              )}
            </section>
          )}

          {/* Active OS Firewall Deployment */}
          <section className="triage-section" style={{ marginTop: "auto" }}>
            <button
              type="button"
              className="button button-danger width-100"
              disabled={deployingFirewall || user?.role !== "ADMIN"}
              onClick={handleDeployFirewall}
              style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 8 }}
            >
              <ShieldAlert size={16} />
              {deployingFirewall
                ? "Deploying OS Firewall Rule..."
                : `Block ${sourceIp} on Host Firewall`}
            </button>
            <div
              className="deploy-note"
              style={{
                color:
                  deploySuccess === true
                    ? "var(--low)"
                    : deploySuccess === false
                    ? "var(--critical)"
                    : undefined,
              }}
            >
              {deployMessage ||
                (user?.role === "ADMIN"
                  ? "Executes OS-level netsh/iptables rule immediately"
                  : "Administrator role required to execute OS firewall rules")}
            </div>
          </section>
        </div>
      </aside>
    </div>
  );
};
