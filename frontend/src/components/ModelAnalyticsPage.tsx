import React, { useEffect, useState } from "react";
import { ModelAnalyticsResponse, ModelMetricEntry } from "../types";
import { Brain, CheckCircle, AlertCircle } from "lucide-react";

interface ModelAnalyticsPageProps {
  apiBase: string;
  authHeaders: () => Record<string, string>;
}

const BRAIN_METADATA: Array<{ key: string; icon: string; name: string; desc: string }> = [
  { key: "web", icon: "🌐", name: "WEB Brain", desc: "SQLi, XSS & Web Application Attacks" },
  { key: "auth", icon: "🔑", name: "AUTH Brain", desc: "SSH/FTP Brute Force & Credential Stuffing" },
  { key: "dos", icon: "💥", name: "DOS Brain", desc: "Hulk, GoldenEye & Slowloris Floods" },
  { key: "recon", icon: "🔍", name: "RECON Brain", desc: "Nmap Port Scans & Service Discovery" },
  { key: "ddos", icon: "🌊", name: "DDOS Brain", desc: "LOIC Volumetric Distributed Floods" },
  { key: "botnet", icon: "🤖", name: "BOTNET Brain", desc: "Ares Botnet Command & Control Traffic" },
  { key: "infiltration", icon: "🕵️", name: "INFILTRATION Brain", desc: "Internal Lateral Movement & Exfiltration" },
];

export const ModelAnalyticsPage: React.FC<ModelAnalyticsPageProps> = ({
  apiBase,
  authHeaders,
}) => {
  const [selectedBrain, setSelectedBrain] = useState<string>("web");
  const [analytics, setAnalytics] = useState<Record<string, ModelMetricEntry>>({});
  const [brainsLoaded, setBrainsLoaded] = useState<number>(0);

  useEffect(() => {
    const load = async () => {
      try {
        const resp = await fetch(`${apiBase}/api/model-analytics`, {
          headers: authHeaders(),
        });
        if (resp.ok) {
          const data: ModelAnalyticsResponse = await resp.json();
          setAnalytics(data.analytics || {});
          setBrainsLoaded(data.brains_loaded || 0);
        }
      } catch {
        // ignore
      }
    };
    load();
  }, [apiBase]);

  const currentMetrics: ModelMetricEntry | undefined = analytics[selectedBrain];
  const fmtPct = (v: number) => `${((v || 0) * 100).toFixed(1)}%`;

  const sortedFeatures = Object.entries(currentMetrics?.feature_importances || {}).sort(
    (a, b) => b[1] - a[1]
  );
  const maxFeatureWeight = Math.max(0.0001, ...sortedFeatures.map(([, w]) => w));

  return (
    <div className="tab-page">
      {/* 7-Brain Fleet Status Selector Cards */}
      <div className="panel" style={{ marginBottom: 24 }}>
        <div className="panel-header">
          <div>
            <h2>7-Brain Random Forest Ensemble Fleet</h2>
            <p className="panel-subtext">
              Select any specialized CIC-IDS2017 classifier brain below to inspect its validation metrics and feature weights
            </p>
          </div>
          <span className="panel-note">{brainsLoaded}/7 Brains Online</span>
        </div>

        <div className="brain-fleet-grid">
          {BRAIN_METADATA.map((b) => {
            const m = analytics[b.key];
            const isOnline = Boolean(m?.trained);
            const isSelected = selectedBrain === b.key;
            return (
              <button
                key={b.key}
                type="button"
                className={`brain-fleet-card ${isSelected ? "selected" : ""}`}
                onClick={() => setSelectedBrain(b.key)}
              >
                <div className="brain-fleet-top">
                  <span className="brain-fleet-icon">{b.icon}</span>
                  <span className={`brain-status-dot ${isOnline ? "online" : "offline"}`}>
                    {isOnline ? <CheckCircle size={12} /> : <AlertCircle size={12} />}
                    {isOnline ? "READY" : "UNTRAINED"}
                  </span>
                </div>
                <strong className="brain-fleet-title">{b.name}</strong>
                <span className="brain-fleet-desc">{b.desc}</span>
                {isOnline && (
                  <div className="brain-fleet-f1">
                    F1: <strong>{fmtPct(m.f1_score)}</strong>
                  </div>
                )}
              </button>
            );
          })}
        </div>
      </div>

      {/* KPI Metrics Row for Selected Brain */}
      <section className="metric-grid">
        <article className="metric-card">
          <span className="metric-label">Validation Accuracy</span>
          <strong className="low">{fmtPct(currentMetrics?.accuracy || 0)}</strong>
          <span className="metric-hint">
            {currentMetrics?.trained_at
              ? `Compiled ${currentMetrics.trained_at}`
              : "Overall test split predictions"}
          </span>
        </article>
        <article className="metric-card">
          <span className="metric-label">Precision</span>
          <strong style={{ color: "#38bdf8" }}>{fmtPct(currentMetrics?.precision || 0)}</strong>
          <span className="metric-hint">Low false-positive assurance</span>
        </article>
        <article className="metric-card">
          <span className="metric-label">Recall (Sensitivity)</span>
          <strong style={{ color: "#a855f7" }}>{fmtPct(currentMetrics?.recall || 0)}</strong>
          <span className="metric-hint">True attack capture rate</span>
        </article>
        <article className="metric-card">
          <span className="metric-label">Harmonic F1-Score</span>
          <strong className="low">{fmtPct(currentMetrics?.f1_score || 0)}</strong>
          <span className="metric-hint">Precision / Recall balance</span>
        </article>
      </section>

      {/* Feature Importances & Confusion Matrix */}
      <section className="double-grid">
        <div className="panel">
          <div className="panel-header">
            <div>
              <h2>Random Forest Feature Importances</h2>
              <p className="panel-subtext">
                Gini impurity reduction weights across the 20 unified network flow features
              </p>
            </div>
            <span className="panel-note">
              <Brain size={14} style={{ verticalAlign: "middle", marginRight: 4 }} />
              {selectedBrain.toUpperCase()}
            </span>
          </div>

          {!currentMetrics?.trained || sortedFeatures.length === 0 ? (
            <div className="empty-chart">
              <span>
                Model brain &apos;{selectedBrain}&apos; has not been compiled yet. Run{" "}
                <code>python trainer.py --type {selectedBrain}</code>
              </span>
            </div>
          ) : (
            <div className="severity-bars">
              {sortedFeatures.slice(0, 12).map(([feature, weight]) => {
                const pct = `${(weight * 100).toFixed(1)}%`;
                const width = Math.max(4, Math.round((weight / maxFeatureWeight) * 100));
                return (
                  <div key={feature} className="severity-row">
                    <span
                      className="mono text-dim"
                      style={{
                        width: 175,
                        fontSize: 11.5,
                        textTransform: "none",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                      }}
                      title={feature}
                    >
                      {feature}
                    </span>
                    <span className="bar-track">
                      <span
                        className="bar-fill"
                        style={{
                          width: `${width}%`,
                          background: "linear-gradient(90deg, #06b6d4, #8b5cf6)",
                        }}
                      />
                    </span>
                    <strong
                      className="mono"
                      style={{ width: 52, textAlign: "right", fontSize: 12 }}
                    >
                      {pct}
                    </strong>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        <div className="panel">
          <div className="panel-header">
            <div>
              <h2>Stratified Validation Confusion Matrix</h2>
              <p className="panel-subtext">
                Ground-truth verification on held-out CIC-IDS2017 evaluation split
              </p>
            </div>
            <span className="panel-note">Confusion Matrix</span>
          </div>

          <div className="matrix-grid">
            <div className="matrix-card">
              <span className="matrix-label low">True Negatives (TN)</span>
              <strong>
                {(currentMetrics?.confusion_matrix?.tn || 0).toLocaleString()}
              </strong>
              <span className="matrix-hint">Benign traffic accurately cleared</span>
            </div>
            <div className="matrix-card">
              <span className="matrix-label critical">False Positives (FP)</span>
              <strong>
                {(currentMetrics?.confusion_matrix?.fp || 0).toLocaleString()}
              </strong>
              <span className="matrix-hint">Benign traffic flagged as threat</span>
            </div>
            <div className="matrix-card">
              <span className="matrix-label critical">False Negatives (FN)</span>
              <strong>
                {(currentMetrics?.confusion_matrix?.fn || 0).toLocaleString()}
              </strong>
              <span className="matrix-hint">Malicious traffic missed</span>
            </div>
            <div className="matrix-card">
              <span className="matrix-label low">True Positives (TP)</span>
              <strong>
                {(currentMetrics?.confusion_matrix?.tp || 0).toLocaleString()}
              </strong>
              <span className="matrix-hint">Malicious attacks intercepted</span>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
};
