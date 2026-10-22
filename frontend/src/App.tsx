import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Background3D } from "./Background3D";
import {
  AlertTimelineChart,
  ThreatDonutChart,
  TopAttackersChart,
} from "./components/Charts";
import { TriageDrawer } from "./components/TriageDrawer";
import { ThreatIntelPage } from "./components/ThreatIntelPage";
import { LogIngestionPage } from "./components/LogIngestionPage";
import { ModelAnalyticsPage } from "./components/ModelAnalyticsPage";
import {
  AlertRecord,
  BlockedIPRecord,
  HealthResponse,
  SeverityLevel,
  severityFor,
  UserSession,
} from "./types";
import {
  Shield,
  RefreshCw,
  LogOut,
  Search,
  Download,
  FileJson,
  Activity,
  Terminal,
  Brain,
  Radar,
  Unlock,
  AlertOctagon,
  Filter,
  ChevronLeft,
  ChevronRight,
  Menu,
  X,
} from "lucide-react";

type ConsoleTab = "dashboard" | "intel" | "ingestion" | "brains";

interface ToastItem {
  id: number;
  message: string;
  type: "info" | "success" | "error";
}

function resolveDefaultApiBase(): string {
  const h = window.location.hostname;
  if (h !== "localhost" && h !== "127.0.0.1") {
    return "";
  }
  return "http://127.0.0.1:8000";
}

export const App: React.FC = () => {
  // ── Auth & Connection State ──
  const [apiBaseInput, setApiBaseInput] = useState<string>(resolveDefaultApiBase);
  const [user, setUser] = useState<UserSession | null>(() => {
    const token = localStorage.getItem("logsentry_token");
    const username = localStorage.getItem("logsentry_username");
    const role = localStorage.getItem("logsentry_role") as "ADMIN" | "ANALYST" | null;
    if (token && username && role) {
      return { token, username, role };
    }
    return null;
  });

  const [loginUser, setLoginUser] = useState("");
  const [loginPass, setLoginPass] = useState("");
  const [loginError, setLoginError] = useState("");
  const [loggingIn, setLoggingIn] = useState(false);

  // ── Navigation & Responsive State ──
  const [activeTab, setActiveTab] = useState<ConsoleTab>("dashboard");
  const [sidebarOpen, setSidebarOpen] = useState(false);

  // ── Telemetry State ──
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [apiOnline, setApiOnline] = useState<boolean | null>(null);
  const [allAlerts, setAllAlerts] = useState<AlertRecord[]>([]);
  const [blockedIPs, setBlockedIPs] = useState<BlockedIPRecord[]>([]);
  const [lastUpdated, setLastUpdated] = useState<string>("Connecting...");

  // ── Filters, Search & Pagination ──
  const [threatFilter, setThreatFilter] = useState<string>("");
  const [severityFilter, setSeverityFilter] = useState<string>("");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [refreshIntervalSec, setRefreshIntervalSec] = useState<number>(5);
  const [currentPage, setCurrentPage] = useState<number>(1);
  const pageSize = 25;

  // ── Triage Drawer & Toasts ──
  const [selectedAlert, setSelectedAlert] = useState<AlertRecord | null>(null);
  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const searchInputRef = useRef<HTMLInputElement>(null);

  const apiBase = useMemo(() => {
    const val = apiBaseInput.trim().replace(/\/$/, "");
    const isCloud =
      window.location.hostname !== "localhost" && window.location.hostname !== "127.0.0.1";
    if (isCloud && (val.includes("localhost") || val.includes("127.0.0.1"))) {
      return "";
    }
    return val;
  }, [apiBaseInput]);

  const notify = useCallback((message: string, type: "info" | "success" | "error" = "info") => {
    const id = Date.now() + Math.floor(Math.random() * 1000);
    setToasts((prev) => [...prev.slice(-3), { id, message, type }]);
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 3800);
  }, []);

  const authHeaders = useCallback((): Record<string, string> => {
    const h: Record<string, string> = { "Content-Type": "application/json" };
    if (user?.token) {
      h["Authorization"] = `Bearer ${user.token}`;
    }
    return h;
  }, [user]);

  const handleLogout = useCallback(async () => {
    if (user?.token) {
      try {
        await fetch(`${apiBase}/api/auth/logout`, {
          method: "POST",
          headers: authHeaders(),
        });
      } catch {
        // ignore
      }
    }
    localStorage.removeItem("logsentry_token");
    localStorage.removeItem("logsentry_username");
    localStorage.removeItem("logsentry_role");
    setUser(null);
    setSelectedAlert(null);
    setAllAlerts([]);
  }, [apiBase, authHeaders, user]);

  // Verify session on startup
  useEffect(() => {
    if (!user?.token) return;
    let cancelled = false;
    (async () => {
      try {
        const resp = await fetch(`${apiBase}/api/auth/me`, {
          headers: authHeaders(),
        });
        if (!resp.ok && !cancelled) {
          handleLogout();
        }
      } catch {
        // Keep cached session if network temporarily unavailable
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const refreshData = useCallback(async () => {
    if (!user?.token) return;
    try {
      const [healthResp, alertsResp, blockedResp] = await Promise.all([
        fetch(`${apiBase}/health`, { headers: authHeaders() }),
        fetch(`${apiBase}/api/alerts?limit=500&newest_first=true`, { headers: authHeaders() }),
        fetch(`${apiBase}/api/blocked-ips`, { headers: authHeaders() }),
      ]);

      if (
        healthResp.status === 401 ||
        alertsResp.status === 401 ||
        blockedResp.status === 401
      ) {
        handleLogout();
        return;
      }

      if (!healthResp.ok || !alertsResp.ok || !blockedResp.ok) {
        throw new Error("API error");
      }

      const healthData: HealthResponse = await healthResp.json();
      const alertsData = await alertsResp.json();
      const blockedData: BlockedIPRecord[] = await blockedResp.json();

      setHealth(healthData);
      setAllAlerts(alertsData.alerts || []);
      setBlockedIPs(blockedData || []);
      setApiOnline(true);
      setLastUpdated(`Synced ${new Date().toLocaleTimeString()}`);
    } catch {
      setApiOnline(false);
      setLastUpdated("Unable to reach API");
    }
  }, [apiBase, authHeaders, handleLogout, user]);

  useEffect(() => {
    if (!user?.token) return;
    refreshData();
    if (refreshIntervalSec <= 0) return;
    const timer = setInterval(refreshData, refreshIntervalSec * 1000);
    return () => clearInterval(timer);
  }, [user, refreshIntervalSec, refreshData]);

  // Keyboard shortcuts: Esc closes drawer, "/" focuses search
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape" && selectedAlert) {
        setSelectedAlert(null);
      } else if (
        e.key === "/" &&
        document.activeElement?.tagName !== "INPUT" &&
        document.activeElement?.tagName !== "TEXTAREA"
      ) {
        e.preventDefault();
        searchInputRef.current?.focus();
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [selectedAlert]);

  const handleLoginSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!loginUser.trim() || !loginPass) {
      setLoginError("Please enter both username and password");
      return;
    }
    setLoggingIn(true);
    setLoginError("");
    try {
      const resp = await fetch(`${apiBase}/api/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: loginUser.trim(), password: loginPass }),
      });

      if (!resp.ok) {
        const err = await resp.json().catch(() => ({}));
        throw new Error(err.detail || "Invalid username or password");
      }

      const payload = await resp.json();
      const session: UserSession = {
        token: payload.token,
        username: payload.username,
        role: payload.role,
      };
      localStorage.setItem("logsentry_token", session.token);
      localStorage.setItem("logsentry_username", session.username);
      localStorage.setItem("logsentry_role", session.role);
      setUser(session);
      setLoginPass("");
      notify(`Welcome back, ${session.username} (${session.role})`, "success");
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Authentication failed";
      if (msg.toLowerCase().includes("fetch")) {
        setLoginError(
          `Backend unreachable at ${apiBase || window.location.origin}. Ensure FastAPI server is running.`
        );
      } else {
        setLoginError(msg);
      }
    } finally {
      setLoggingIn(false);
    }
  };

  const handleUnblockIP = async (ip: string) => {
    try {
      const resp = await fetch(`${apiBase}/api/ips/unblock`, {
        method: "POST",
        headers: authHeaders(),
        body: JSON.stringify({ ip }),
      });
      if (resp.status === 403) {
        notify("Access Denied: Administrator role required to unblock IPs", "error");
        return;
      }
      if (!resp.ok) throw new Error("Failed to unblock IP");
      notify(`IP ${ip} unblocked and reputation score reset`, "success");
      await refreshData();
    } catch {
      notify(`Failed to unblock ${ip}`, "error");
    }
  };

  // Distinct threat types for dropdown
  const threatTypes = useMemo(() => {
    return [...new Set(allAlerts.map((a) => a.Type))].sort();
  }, [allAlerts]);

  // Filtered alerts
  const filteredAlerts = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return allAlerts.filter((a) => {
      const matchThreat = !threatFilter || a.Type === threatFilter;
      const matchSev = !severityFilter || severityFor(a.Type) === severityFilter;
      const matchSearch =
        !q ||
        a.Type.toLowerCase().includes(q) ||
        (a["Source IP"] || "").toLowerCase().includes(q) ||
        (a.Details || "").toLowerCase().includes(q) ||
        (a.Location || "").toLowerCase().includes(q);
      return matchThreat && matchSev && matchSearch;
    });
  }, [allAlerts, threatFilter, severityFilter, searchQuery]);

  // Reset pagination when filters change
  useEffect(() => {
    setCurrentPage(1);
  }, [threatFilter, severityFilter, searchQuery]);

  const totalPages = Math.max(1, Math.ceil(filteredAlerts.length / pageSize));
  const paginatedAlerts = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return filteredAlerts.slice(start, start + pageSize);
  }, [filteredAlerts, currentPage]);

  // KPI aggregations
  const kpiStats = useMemo(() => {
    const sevCounts: Record<SeverityLevel, number> = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
    };
    const typeCounts: Record<string, number> = {};
    for (const a of filteredAlerts) {
      const s = severityFor(a.Type);
      sevCounts[s] = (sevCounts[s] || 0) + 1;
      typeCounts[a.Type] = (typeCounts[a.Type] || 0) + 1;
    }
    const topThreatEntry = Object.entries(typeCounts).sort((a, b) => b[1] - a[1])[0];
    return {
      sevCounts,
      topThreat: topThreatEntry ? topThreatEntry[0] : "None",
      topThreatCount: topThreatEntry ? topThreatEntry[1] : 0,
    };
  }, [filteredAlerts]);

  // Export CSV / JSON helpers
  const exportCSV = () => {
    if (!filteredAlerts.length) {
      notify("No alerts to export", "info");
      return;
    }
    const headers = ["Timestamp", "Severity", "Type", "Source IP", "Location", "Details"];
    const rows = filteredAlerts.map((a) => [
      a.Timestamp,
      severityFor(a.Type),
      a.Type,
      a["Source IP"],
      a.Location,
      (a.Details || "").replace(/"/g, '""'),
    ]);
    const csvContent =
      [headers.join(","), ...rows.map((r) => r.map((v) => `"${v}"`).join(","))].join("\n");
    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `cerberus_incidents_${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    notify(`Exported ${filteredAlerts.length} incidents to CSV`, "success");
  };

  const exportJSON = () => {
    if (!filteredAlerts.length) {
      notify("No alerts to export", "info");
      return;
    }
    const blob = new Blob([JSON.stringify(filteredAlerts, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `cerberus_incidents_${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
    notify(`Exported ${filteredAlerts.length} incidents to JSON`, "success");
  };

  const formatTime = (ts: string) => {
    if (!ts) return "--";
    const d = new Date(ts.replace(" ", "T"));
    if (Number.isNaN(d.getTime())) {
      return ts.split(" ").pop() || ts;
    }
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  };

  return (
    <>
      <Background3D />

      {/* Toast Notification Stack */}
      <div className="toast-stack" aria-live="polite">
        {toasts.map((t) => (
          <div key={t.id} className={`toast-item toast-${t.type}`}>
            <span>{t.message}</span>
          </div>
        ))}
      </div>

      {/* ==========================================
          LOGIN PORTAL OVERLAY
          ========================================== */}
      {!user ? (
        <div className="login-overlay">
          <div className="login-card">
            <div className="brand-header">
              <div className="brand-badge">🛡️</div>
              <h2>Cerberus</h2>
              <p>Autonomous Security Operations Center</p>
            </div>

            <form className="login-form" onSubmit={handleLoginSubmit}>
              <div className="input-group">
                <label className="field-label" htmlFor="loginUser">
                  Operator Username
                </label>
                <input
                  id="loginUser"
                  type="text"
                  className="input"
                  placeholder="Enter operator username"
                  value={loginUser}
                  onChange={(e) => setLoginUser(e.target.value)}
                  required
                  autoComplete="username"
                />
              </div>

              <div className="input-group">
                <label className="field-label" htmlFor="loginPass">
                  Security Passphrase
                </label>
                <input
                  id="loginPass"
                  type="password"
                  className="input"
                  placeholder="••••••••••••"
                  value={loginPass}
                  onChange={(e) => setLoginPass(e.target.value)}
                  required
                  autoComplete="current-password"
                />
              </div>

              {loginError && <div className="login-error">{loginError}</div>}

              <button
                type="submit"
                className="button button-primary width-100"
                disabled={loggingIn}
              >
                {loggingIn ? "Authenticating Session..." : "Initialize SOC Session"}
              </button>
            </form>

            <div className="login-footer">
              7-Brain ML Intrusion Detection · MITRE ATT&amp;CK RAG · Active IPS
            </div>
          </div>
        </div>
      ) : (
        /* ==========================================
           MAIN AUTHENTICATED SOC WORKSPACE
           ========================================== */
        <div className="shell">
          {/* Sidebar */}
          <aside className={`sidebar ${sidebarOpen ? "open" : ""}`}>
            <div className="brand-block">
              <div className="brand-mark">
                <Shield size={18} />
              </div>
              <div>
                <div className="brand-name">Cerberus</div>
                <div className="brand-subtitle">SOC Intelligence v1.0</div>
              </div>
              <button
                type="button"
                className="mobile-close-btn"
                onClick={() => setSidebarOpen(false)}
                aria-label="Close Sidebar"
              >
                <X size={18} />
              </button>
            </div>

            {/* Primary Navigation */}
            <div className="sidebar-nav-section">
              <span className="field-label">Operations Modules</span>
              <nav className="sidebar-nav">
                <button
                  type="button"
                  className={`sidebar-nav-btn ${activeTab === "dashboard" ? "active" : ""}`}
                  onClick={() => {
                    setActiveTab("dashboard");
                    setSidebarOpen(false);
                  }}
                >
                  <Activity size={16} />
                  <span>Threat Command Center</span>
                </button>

                <button
                  type="button"
                  className={`sidebar-nav-btn ${activeTab === "intel" ? "active" : ""}`}
                  onClick={() => {
                    setActiveTab("intel");
                    setSidebarOpen(false);
                  }}
                >
                  <Radar size={16} />
                  <span>MITRE &amp; Threat Intel</span>
                </button>

                {user.role === "ADMIN" && (
                  <button
                    type="button"
                    className={`sidebar-nav-btn ${activeTab === "ingestion" ? "active" : ""}`}
                    onClick={() => {
                      setActiveTab("ingestion");
                      setSidebarOpen(false);
                    }}
                  >
                    <Terminal size={16} />
                    <span>Log Attack Sandbox</span>
                  </button>
                )}

                <button
                  type="button"
                  className={`sidebar-nav-btn ${activeTab === "brains" ? "active" : ""}`}
                  onClick={() => {
                    setActiveTab("brains");
                    setSidebarOpen(false);
                  }}
                >
                  <Brain size={16} />
                  <span>ML Brain Analytics</span>
                </button>
              </nav>
            </div>

            {/* Global Telemetry Filters */}
            <section className="control-group">
              <label className="field-label" htmlFor="threatFilter">
                Threat Classification
              </label>
              <select
                id="threatFilter"
                className="input"
                value={threatFilter}
                onChange={(e) => setThreatFilter(e.target.value)}
              >
                <option value="">All threat vectors ({allAlerts.length})</option>
                {threatTypes.map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </select>
            </section>

            <section className="control-group">
              <label className="field-label" htmlFor="severityFilter">
                Severity Tier
              </label>
              <select
                id="severityFilter"
                className="input"
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
              >
                <option value="">All severities</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>
            </section>

            <section className="control-group">
              <label className="field-label" htmlFor="refreshInterval">
                Telemetry Sync Rate
              </label>
              <select
                id="refreshInterval"
                className="input"
                value={refreshIntervalSec}
                onChange={(e) => setRefreshIntervalSec(Number(e.target.value))}
              >
                <option value={0}>Manual sync only</option>
                <option value={5}>Every 5 seconds</option>
                <option value={15}>Every 15 seconds</option>
                <option value={30}>Every 30 seconds</option>
              </select>
            </section>

            <section className="control-group">
              <label className="field-label" htmlFor="apiUrl">
                API Gateway Endpoint
              </label>
              <input
                id="apiUrl"
                className="input mono"
                style={{ fontSize: 12 }}
                value={apiBaseInput}
                onChange={(e) => setApiBaseInput(e.target.value)}
                placeholder="Relative (/api) or http://..."
              />
            </section>

            {/* Active AI Brains Status Mini-Panel */}
            <div className="sidebar-brains-box">
              <div className="sidebar-brains-head">
                <span className="field-label" style={{ marginBottom: 0 }}>
                  Active AI Brains
                </span>
                <span className="mono low" style={{ fontSize: 11 }}>
                  {health?.active_brains?.length || 0}/7
                </span>
              </div>
              <div className="sidebar-brain-pills">
                {(health?.active_brains || ["web", "auth", "dos", "recon", "ddos", "botnet", "infiltration"]).map(
                  (b) => (
                    <span key={b} className="mini-brain-tag">
                      <span className="mini-dot" />
                      {b.toUpperCase()}
                    </span>
                  )
                )}
              </div>
            </div>
          </aside>

          {/* Main Workspace */}
          <main className="workspace">
            {/* Topbar */}
            <header className="topbar">
              <div className="topbar-left">
                <button
                  type="button"
                  className="mobile-menu-btn"
                  onClick={() => setSidebarOpen(true)}
                  aria-label="Open Navigation"
                >
                  <Menu size={20} />
                </button>
                <div>
                  <h1>
                    {activeTab === "dashboard"
                      ? "Security Operations Command Center"
                      : activeTab === "intel"
                      ? "MITRE ATT&CK & Threat Intelligence"
                      : activeTab === "ingestion"
                      ? "Adversarial Log Simulation Sandbox"
                      : "Machine Learning Brain Telemetry"}
                  </h1>
                  <p>{lastUpdated} · Signature Rules: {health?.signature_count ?? 35}</p>
                </div>
              </div>

              <div className="topbar-actions">
                <span
                  className={`status-pill ${
                    apiOnline === true
                      ? "status-online"
                      : apiOnline === false
                      ? "status-offline"
                      : "status-muted"
                  }`}
                >
                  {apiOnline === true
                    ? health?.ai_ready
                      ? "● AI Ensemble Online"
                      : "● API Online"
                    : apiOnline === false
                    ? "● Offline"
                    : "● Connecting"}
                </span>

                <button
                  type="button"
                  className="button button-secondary"
                  onClick={refreshData}
                  style={{ display: "flex", alignItems: "center", gap: 6, padding: "8px 14px" }}
                  title="Force telemetry sync"
                >
                  <RefreshCw size={14} /> Sync
                </button>

                <div className="user-pill">
                  <span
                    className={`role-badge ${
                      user.role === "ADMIN" ? "role-admin" : "role-analyst"
                    }`}
                  >
                    {user.role}
                  </span>
                  <span className="user-name">{user.username}</span>
                  <button
                    type="button"
                    className="logout-btn"
                    onClick={handleLogout}
                    title="Sign Out"
                  >
                    <LogOut size={15} />
                  </button>
                </div>
              </div>
            </header>

            {/* ==========================================
                TAB 1: THREAT COMMAND CENTER (DASHBOARD)
                ========================================== */}
            {activeTab === "dashboard" && (
              <div className="tab-page">
                {/* 4 Executive KPI Cards */}
                <section className="metric-grid">
                  <article className="metric-card">
                    <span className="metric-label">Total Incidents</span>
                    <strong>{filteredAlerts.length}</strong>
                    <span className="metric-hint">
                      {filteredAlerts.length === allAlerts.length
                        ? "All active telemetry records"
                        : `Filtered from ${allAlerts.length} total`}
                    </span>
                  </article>

                  <article className="metric-card card-critical">
                    <span className="metric-label">Critical Severity</span>
                    <strong>{kpiStats.sevCounts.CRITICAL}</strong>
                    <span className="metric-hint">
                      {kpiStats.sevCounts.HIGH} High · {kpiStats.sevCounts.MEDIUM} Medium
                    </span>
                  </article>

                  <article className="metric-card">
                    <span className="metric-label">IPS Blacklisted IPs</span>
                    <strong style={{ color: "#38bdf8" }}>{blockedIPs.length}</strong>
                    <span className="metric-hint">Active perimeter quarantine</span>
                  </article>

                  <article className="metric-card card-warning">
                    <span className="metric-label">Dominant Threat Vector</span>
                    <strong className="metric-text" title={kpiStats.topThreat}>
                      {kpiStats.topThreat}
                    </strong>
                    <span className="metric-hint">
                      {kpiStats.topThreatCount > 0
                        ? `${kpiStats.topThreatCount} matching events`
                        : "No active threats"}
                    </span>
                  </article>
                </section>

                {/* Row 1 of Visual Analytics: Donut + Top Attacker IPs + Timeline */}
                <section className="triple-analytics-grid">
                  <div className="panel">
                    <div className="panel-header">
                      <div>
                        <h2>Threat Vector Distribution</h2>
                        <p className="panel-subtext">Click any slice or label to filter feed</p>
                      </div>
                      {threatFilter && (
                        <button
                          type="button"
                          className="chip-btn active"
                          onClick={() => setThreatFilter("")}
                        >
                          Clear: {threatFilter} ✕
                        </button>
                      )}
                    </div>
                    <ThreatDonutChart
                      alerts={filteredAlerts}
                      onSelectType={(type) =>
                        setThreatFilter((prev) => (prev === type ? "" : type))
                      }
                    />
                  </div>

                  <div className="panel">
                    <div className="panel-header">
                      <div>
                        <h2>Top Attacker Sources</h2>
                        <p className="panel-subtext">Highest volume offending IPv4 nodes</p>
                      </div>
                      <span className="panel-note">Offenders</span>
                    </div>
                    <TopAttackersChart
                      alerts={filteredAlerts}
                      onSelectIP={(ip) =>
                        setSearchQuery((prev) => (prev === ip ? "" : ip))
                      }
                    />
                  </div>

                  <div className="panel">
                    <div className="panel-header">
                      <div>
                        <h2>Incident Velocity Timeline</h2>
                        <p className="panel-subtext">Real-time anomaly burst cadence</p>
                      </div>
                      <span className="panel-note">Live Pulse</span>
                    </div>
                    <AlertTimelineChart alerts={filteredAlerts} />
                  </div>
                </section>

                {/* Row 2: Severity Breakdown + Active IPS Blacklist */}
                <section className="double-grid">
                  <div className="panel">
                    <div className="panel-header">
                      <div>
                        <h2>Threat Severity Profile</h2>
                        <p className="panel-subtext">Distribution across NIST/SOC severity tiers</p>
                      </div>
                      <span className="panel-note">Cumulative</span>
                    </div>
                    <div className="severity-bars">
                      {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as SeverityLevel[]).map((sev) => {
                        const count = kpiStats.sevCounts[sev] || 0;
                        const max = Math.max(
                          1,
                          kpiStats.sevCounts.CRITICAL,
                          kpiStats.sevCounts.HIGH,
                          kpiStats.sevCounts.MEDIUM,
                          kpiStats.sevCounts.LOW
                        );
                        const width = Math.max(4, Math.round((count / max) * 100));
                        const cls = sev.toLowerCase();
                        return (
                          <div
                            key={sev}
                            className="severity-row"
                            style={{ cursor: "pointer" }}
                            onClick={() =>
                              setSeverityFilter((prev) => (prev === sev ? "" : sev))
                            }
                            title={`Click to filter by ${sev}`}
                          >
                            <span className={cls}>{sev}</span>
                            <span className="bar-track">
                              <span
                                className={`bar-fill bg-${cls}`}
                                style={{ width: `${width}%` }}
                              />
                            </span>
                            <strong className="mono">{count}</strong>
                          </div>
                        );
                      })}
                    </div>
                  </div>

                  <div className="panel">
                    <div className="panel-header">
                      <div>
                        <h2>Active IPS Quarantine Blacklist</h2>
                        <p className="panel-subtext">
                          Offending IPs automatically blocked at reputation score ≥ 100
                        </p>
                      </div>
                      <span className="panel-note">{blockedIPs.length} Blocked</span>
                    </div>
                    <div className="table-wrap max-h-260">
                      <table>
                        <thead>
                          <tr>
                            <th>Blocked IPv4</th>
                            <th>Risk Score</th>
                            <th>Quarantined At</th>
                            <th>Action</th>
                          </tr>
                        </thead>
                        <tbody>
                          {blockedIPs.length === 0 ? (
                            <tr className="empty-row">
                              <td colSpan={4}>No IPs currently blacklisted in active IPS.</td>
                            </tr>
                          ) : (
                            blockedIPs.map((row) => (
                              <tr key={row.ip}>
                                <td className="mono">{row.ip}</td>
                                <td>
                                  <span className="mono critical" style={{ fontWeight: 800 }}>
                                    {Number(row.score).toFixed(0)}
                                  </span>
                                </td>
                                <td className="mono text-dim" style={{ fontSize: 11.5 }}>
                                  {row.updated_at || "--"}
                                </td>
                                <td>
                                  <button
                                    type="button"
                                    className="button button-secondary"
                                    style={{ padding: "4px 10px", fontSize: 11 }}
                                    onClick={() => handleUnblockIP(row.ip)}
                                  >
                                    <Unlock size={11} style={{ marginRight: 4 }} />
                                    Unblock
                                  </button>
                                </td>
                              </tr>
                            ))
                          )}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </section>

                {/* Row 3: Live Incident Feed Table with Search, Filter Chips & CSV/JSON Export */}
                <section className="panel alert-panel">
                  <div className="alert-table-toolbar">
                    <div>
                      <h2>Live Incident Telemetry Feed</h2>
                      <p className="panel-subtext">
                        Showing {paginatedAlerts.length} of {filteredAlerts.length} incidents — click any row to launch 4-Agent AI Triage
                      </p>
                    </div>

                    <div className="toolbar-controls">
                      <div className="search-input-wrap">
                        <Search size={15} className="search-icon" />
                        <input
                          ref={searchInputRef}
                          type="text"
                          className="input search-input"
                          placeholder="Search IP, payload, threat (Press /)..."
                          value={searchQuery}
                          onChange={(e) => setSearchQuery(e.target.value)}
                        />
                      </div>

                      {(threatFilter || severityFilter || searchQuery) && (
                        <button
                          type="button"
                          className="button button-secondary"
                          style={{ padding: "8px 12px", fontSize: 12 }}
                          onClick={() => {
                            setThreatFilter("");
                            setSeverityFilter("");
                            setSearchQuery("");
                          }}
                        >
                          <Filter size={13} style={{ marginRight: 4 }} /> Reset Filters
                        </button>
                      )}

                      <button
                        type="button"
                        className="button button-secondary"
                        style={{ padding: "8px 12px", fontSize: 12, display: "flex", alignItems: "center", gap: 5 }}
                        onClick={exportCSV}
                        title="Export filtered incidents as CSV"
                      >
                        <Download size={13} /> CSV
                      </button>

                      <button
                        type="button"
                        className="button button-secondary"
                        style={{ padding: "8px 12px", fontSize: 12, display: "flex", alignItems: "center", gap: 5 }}
                        onClick={exportJSON}
                        title="Export filtered incidents as JSON"
                      >
                        <FileJson size={13} /> JSON
                      </button>
                    </div>
                  </div>

                  <div className="table-wrap">
                    <table>
                      <thead>
                        <tr>
                          <th>Time</th>
                          <th>Severity</th>
                          <th>Threat Vector</th>
                          <th>Source IP</th>
                          <th>Origin</th>
                          <th>Telemetry Payload / Details</th>
                        </tr>
                      </thead>
                      <tbody>
                        {paginatedAlerts.length === 0 ? (
                          <tr className="empty-row">
                            <td colSpan={6}>
                              <AlertOctagon
                                size={22}
                                style={{ display: "block", margin: "0 auto 8px", opacity: 0.5 }}
                              />
                              No security incidents match your current filter criteria.
                            </td>
                          </tr>
                        ) : (
                          paginatedAlerts.map((alert, idx) => {
                            const sev = severityFor(alert.Type);
                            const cls = sev.toLowerCase();
                            const isSelected =
                              selectedAlert &&
                              selectedAlert.Timestamp === alert.Timestamp &&
                              selectedAlert["Source IP"] === alert["Source IP"] &&
                              selectedAlert.Type === alert.Type;
                            return (
                              <tr
                                key={`${alert.Timestamp}-${alert["Source IP"]}-${idx}`}
                                className={isSelected ? "selected-row" : ""}
                                onClick={() => setSelectedAlert(alert)}
                                style={{ cursor: "pointer" }}
                              >
                                <td className="mono">{formatTime(alert.Timestamp)}</td>
                                <td>
                                  <span className={`severity-pill ${cls}`}>{sev}</span>
                                </td>
                                <td style={{ fontWeight: 600, color: "#f8fafc" }}>{alert.Type}</td>
                                <td className="mono">{alert["Source IP"]}</td>
                                <td>{alert.Location}</td>
                                <td className="details-cell" title={alert.Details}>
                                  {alert.Details}
                                </td>
                              </tr>
                            );
                          })
                        )}
                      </tbody>
                    </table>
                  </div>

                  {/* Pagination Footer */}
                  {totalPages > 1 && (
                    <div className="pagination-bar">
                      <span className="mono text-dim" style={{ fontSize: 12 }}>
                        Page {currentPage} of {totalPages} ({filteredAlerts.length} total records)
                      </span>
                      <div style={{ display: "flex", gap: 8 }}>
                        <button
                          type="button"
                          className="button button-secondary"
                          style={{ padding: "6px 12px", fontSize: 12 }}
                          disabled={currentPage <= 1}
                          onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                        >
                          <ChevronLeft size={14} /> Prev
                        </button>
                        <button
                          type="button"
                          className="button button-secondary"
                          style={{ padding: "6px 12px", fontSize: 12 }}
                          disabled={currentPage >= totalPages}
                          onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                        >
                          Next <ChevronRight size={14} />
                        </button>
                      </div>
                    </div>
                  )}
                </section>
              </div>
            )}

            {/* ==========================================
                TAB 2: MITRE ATT&CK & THREAT INTEL
                ========================================== */}
            {activeTab === "intel" && (
              <ThreatIntelPage
                apiBase={apiBase}
                authHeaders={authHeaders}
                user={user}
                onUnblockIP={handleUnblockIP}
                notify={notify}
              />
            )}

            {/* ==========================================
                TAB 3: LOG ATTACK SANDBOX (ADMIN)
                ========================================== */}
            {activeTab === "ingestion" && user.role === "ADMIN" && (
              <LogIngestionPage
                apiBase={apiBase}
                authHeaders={authHeaders}
                onRefresh={refreshData}
                notify={notify}
              />
            )}

            {/* ==========================================
                TAB 4: ML BRAIN ANALYTICS
                ========================================== */}
            {activeTab === "brains" && (
              <ModelAnalyticsPage apiBase={apiBase} authHeaders={authHeaders} />
            )}
          </main>
        </div>
      )}

      {/* Sliding 4-Agent Triage Drawer */}
      <TriageDrawer
        alert={selectedAlert}
        onClose={() => setSelectedAlert(null)}
        apiBase={apiBase}
        user={user}
        authHeaders={authHeaders}
        onRefresh={refreshData}
        notify={notify}
      />
    </>
  );
};
