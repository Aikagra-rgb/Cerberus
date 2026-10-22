import React, { useEffect, useState } from "react";
import {
  IPReputationRecord,
  MitreSearchResponse,
  MitreTechnique,
  UserSession,
} from "../types";
import { Search, Shield, ExternalLink, Unlock, Crosshair, Globe } from "lucide-react";

interface ThreatIntelPageProps {
  apiBase: string;
  authHeaders: () => Record<string, string>;
  user: UserSession | null;
  onUnblockIP: (ip: string) => Promise<void>;
  notify: (msg: string, type?: "info" | "success" | "error") => void;
}

const PRESET_QUERIES = [
  "SQL Injection",
  "Brute Force",
  "Command and Scripting Interpreter",
  "Endpoint Denial of Service",
  "Valid Accounts",
  "Network Service Discovery",
];

export const ThreatIntelPage: React.FC<ThreatIntelPageProps> = ({
  apiBase,
  authHeaders,
  user,
  onUnblockIP,
  notify,
}) => {
  const [query, setQuery] = useState("SQL Injection");
  const [searching, setSearching] = useState(false);
  const [totalTechniques, setTotalTechniques] = useState<number>(709);
  const [results, setResults] = useState<MitreTechnique[]>([]);
  const [reputations, setReputations] = useState<IPReputationRecord[]>([]);
  const [loadingRep, setLoadingRep] = useState(false);

  const searchMitre = async (q: string) => {
    const trimmed = q.trim();
    if (trimmed.length < 2) {
      notify("Enter at least 2 characters to search MITRE ATT&CK", "info");
      return;
    }
    setSearching(true);
    try {
      const resp = await fetch(
        `${apiBase}/api/threat-intel/mitre?q=${encodeURIComponent(trimmed)}&top_k=8`,
        { headers: authHeaders() }
      );
      if (!resp.ok) throw new Error("MITRE RAG search failed");
      const data: MitreSearchResponse = await resp.json();
      setResults(data.results || []);
      if (data.total_techniques) setTotalTechniques(data.total_techniques);
    } catch {
      notify("Unable to query MITRE ATT&CK RAG engine", "error");
    } finally {
      setSearching(false);
    }
  };

  const fetchReputations = async () => {
    setLoadingRep(true);
    try {
      const resp = await fetch(`${apiBase}/api/threat-intel`, {
        headers: authHeaders(),
      });
      if (resp.ok) {
        const data: IPReputationRecord[] = await resp.json();
        setReputations(data || []);
      }
    } catch {
      // ignore
    } finally {
      setLoadingRep(false);
    }
  };

  useEffect(() => {
    searchMitre(query);
    fetchReputations();
  }, []);

  return (
    <div className="tab-page">
      <div className="double-grid">
        {/* Left: MITRE ATT&CK Knowledge Base Semantic Search */}
        <div className="panel">
          <div className="panel-header">
            <div>
              <h2>MITRE ATT&amp;CK Knowledge Base</h2>
              <p className="panel-subtext">
                Semantic RAG retrieval across {totalTechniques} Enterprise ATT&amp;CK techniques
              </p>
            </div>
            <span className="panel-note">RAG Engine</span>
          </div>

          <form
            className="search-bar-row"
            onSubmit={(e) => {
              e.preventDefault();
              searchMitre(query);
            }}
          >
            <div className="search-input-wrap">
              <Search size={16} className="search-icon" />
              <input
                type="text"
                className="input search-input"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search tactics, techniques, or CVEs (e.g. T1190, SQLi, credential dumping)..."
              />
            </div>
            <button type="submit" className="button button-primary" disabled={searching}>
              {searching ? "Searching..." : "Search ATT&CK"}
            </button>
          </form>

          <div className="preset-chips">
            {PRESET_QUERIES.map((preset) => (
              <button
                key={preset}
                type="button"
                className={`chip-btn ${query === preset ? "active" : ""}`}
                onClick={() => {
                  setQuery(preset);
                  searchMitre(preset);
                }}
              >
                {preset}
              </button>
            ))}
          </div>

          <div className="mitre-results-list">
            {results.length === 0 ? (
              <div className="empty-chart">
                <span>No matching techniques found</span>
              </div>
            ) : (
              results.map((tech) => (
                <article key={tech.id} className="mitre-card">
                  <div className="mitre-card-head">
                    <div>
                      <span className="mitre-id-badge">{tech.id}</span>
                      <strong className="mitre-card-title">{tech.name}</strong>
                    </div>
                    {tech.url && (
                      <a
                        href={tech.url}
                        target="_blank"
                        rel="noreferrer"
                        className="mitre-ext-link"
                        title="Open on MITRE ATT&CK"
                      >
                        <ExternalLink size={14} />
                      </a>
                    )}
                  </div>

                  {tech.tactics && tech.tactics.length > 0 && (
                    <div className="mitre-tags" style={{ margin: "8px 0" }}>
                      {tech.tactics.map((tac) => (
                        <span key={tac} className="mitre-tag">
                          <Crosshair size={10} /> {tac}
                        </span>
                      ))}
                    </div>
                  )}

                  {tech.description && (
                    <p className="mitre-card-desc">
                      {tech.description.length > 260
                        ? `${tech.description.slice(0, 260)}...`
                        : tech.description}
                    </p>
                  )}
                </article>
              ))
            )}
          </div>
        </div>

        {/* Right: Cumulative IP Reputation & Threat Actor Tracker */}
        <div className="panel">
          <div className="panel-header">
            <div>
              <h2>IP Threat Reputation Ledger</h2>
              <p className="panel-subtext">
                Cumulative risk scoring across all observed network sources (Auto-block threshold: 100)
              </p>
            </div>
            <button
              type="button"
              className="button button-secondary"
              style={{ padding: "6px 14px", fontSize: 12 }}
              onClick={fetchReputations}
            >
              {loadingRep ? "Refreshing..." : "Refresh Ledger"}
            </button>
          </div>

          <div className="table-wrap max-h-520">
            <table>
              <thead>
                <tr>
                  <th>Source IP</th>
                  <th>Risk Score</th>
                  <th>IPS Status</th>
                  <th>Last Activity</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {reputations.length === 0 ? (
                  <tr className="empty-row">
                    <td colSpan={5}>No IP reputation telemetry recorded yet.</td>
                  </tr>
                ) : (
                  reputations.map((rep) => {
                    const isBlocked = Boolean(rep.blocked) || rep.score >= 100;
                    const pct = Math.min(100, Math.round(rep.score));
                    return (
                      <tr key={rep.ip}>
                        <td className="mono">
                          <Globe size={13} style={{ marginRight: 6, verticalAlign: "middle" }} />
                          {rep.ip}
                        </td>
                        <td>
                          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                            <div className="bar-track" style={{ width: 80, height: 8 }}>
                              <span
                                className={`bar-fill ${
                                  rep.score >= 100
                                    ? "bg-critical"
                                    : rep.score >= 50
                                    ? "bg-high"
                                    : "bg-low"
                                }`}
                                style={{ width: `${pct}%` }}
                              />
                            </div>
                            <strong
                              className={`mono ${
                                rep.score >= 100
                                  ? "critical"
                                  : rep.score >= 50
                                  ? "high"
                                  : "low"
                              }`}
                            >
                              {Number(rep.score).toFixed(0)}
                            </strong>
                          </div>
                        </td>
                        <td>
                          {isBlocked ? (
                            <span className="severity-pill critical">BLACKLISTED</span>
                          ) : (
                            <span className="severity-pill low">MONITORED</span>
                          )}
                        </td>
                        <td className="mono text-dim" style={{ fontSize: 11.5 }}>
                          {rep.updated_at || "--"}
                        </td>
                        <td>
                          {isBlocked && user?.role === "ADMIN" ? (
                            <button
                              type="button"
                              className="button button-secondary"
                              style={{ padding: "4px 10px", fontSize: 11 }}
                              onClick={async () => {
                                await onUnblockIP(rep.ip);
                                fetchReputations();
                              }}
                            >
                              <Unlock size={12} style={{ marginRight: 4 }} />
                              Reset
                            </button>
                          ) : (
                            <span className="text-muted" style={{ fontSize: 11 }}>
                              <Shield size={12} style={{ verticalAlign: "middle" }} /> Active
                            </span>
                          )}
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};
