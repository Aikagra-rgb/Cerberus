const severityMap = {
  "SQL Injection": "CRITICAL",
  "SQL Injection (Union)": "CRITICAL",
  "SQL Injection (Boolean)": "CRITICAL",
  "SQL Injection (Sleep/Time)": "CRITICAL",
  "XSS Attack": "HIGH",
  "XSS (Script Tag)": "MEDIUM",
  "XSS (Javascript)": "MEDIUM",
  "XSS (Event Handler)": "MEDIUM",
  "Path Traversal": "CRITICAL",
  "Directory Traversal (LFI)": "HIGH",
  "Password File Access": "HIGH",
  "Shadow File Access": "CRITICAL",
  "File Tampering": "CRITICAL",
  "Command Injection": "CRITICAL",
  "SSH Brute Force": "HIGH",
  "Invalid User Login": "MEDIUM",
  "Sudo Abuse": "HIGH",
  "Log4Shell Exploit": "CRITICAL",
  "Git Config Exposure": "HIGH",
  "Env File Exposure": "HIGH",
  "SSH Key Scan": "CRITICAL",
  "Nmap Scanner": "LOW",
  "Nikto Scanner": "MEDIUM",
  "Sqlmap Tool": "HIGH",
  "WordPress Login Bruteforce": "MEDIUM",
  "WordPress XMLRPC Attack": "MEDIUM",
  "PHP Info Leak": "LOW",
  "Remote File Inclusion (RFI)": "HIGH",
  "Null Byte Injection": "HIGH",
  "AWS Metadata Hack": "CRITICAL",
  "Shellshock Vulnerability": "CRITICAL",
  "Masscan": "LOW",
  "Python Bot": "LOW",
  "Base64 Encoded Payload": "CRITICAL",
  "AI-WEB": "HIGH",
  "AI-AUTH": "HIGH",
  "AI-DOS": "CRITICAL",
  "AI-DDOS": "CRITICAL",
  "AI-RECON": "MEDIUM",
  "AI-BOTNET": "HIGH",
  "AI-INFILTRATION": "CRITICAL",
};

const severityOrder = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const severityClass = {
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
};

// ── Application States ──
let allAlerts = [];
let refreshTimer = null;
let activeToken = localStorage.getItem("logsentry_token") || null;
let currentUser = null; // { username, role }

const $ = (id) => document.getElementById(id);

function apiBase() {
  return $("apiUrl").value.replace(/\/$/, "");
}

function severityFor(type) {
  return severityMap[type] || "MEDIUM";
}

function setStatus(online, text) {
  const status = $("apiStatus");
  status.textContent = text;
  status.className = `status-pill ${online ? "status-online" : "status-offline"}`;
}

function formatClock(value) {
  if (!value) return "--";
  const date = new Date(value.replace(" ", "T"));
  if (Number.isNaN(date.getTime())) {
    return String(value).split(" ").pop() || "--";
  }
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function countBy(items, keyFn) {
  return items.reduce((acc, item) => {
    const key = keyFn(item);
    acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {});
}

// ── Authentication Headers Injection ──
function authHeaders() {
  const headers = { "Content-Type": "application/json" };
  if (activeToken) {
    headers["Authorization"] = `Bearer ${activeToken}`;
  }
  return headers;
}

// ── Role-Based Auth UI Injections ──
function checkAuthResponse(status) {
  if (status === 401) {
    // Session token expired or got rejected — log out immediately
    handleLogout();
  }
}

// ── Search & Filter Mappings ──
function filteredAlerts() {
  const threat = $("threatFilter").value;
  const severity = $("severityFilter").value;
  return allAlerts.filter((alert) => {
    const matchesThreat = !threat || alert.Type === threat;
    const matchesSeverity = !severity || severityFor(alert.Type) === severity;
    return matchesThreat && matchesSeverity;
  });
}

function renderThreatFilter() {
  const select = $("threatFilter");
  const current = select.value;
  const threatTypes = [...new Set(allAlerts.map((alert) => alert.Type))].sort();
  select.innerHTML = '<option value="">All threats</option>';
  for (const type of threatTypes) {
    const option = document.createElement("option");
    option.value = type;
    option.textContent = type;
    select.appendChild(option);
  }
  select.value = threatTypes.includes(current) ? current : "";
}

function renderBrains(health) {
  const container = $("brainList");
  if (!container) return;
  const brains = health.active_brains || [];
  if (!brains.length) {
    container.innerHTML = '<div class="brain-row"><span class="brain-name">No models loaded</span></div>';
    return;
  }
  container.innerHTML = brains
    .map(
      (brain) => `
        <div class="brain-row">
          <span class="brain-name">${escapeHtml(brain)}</span>
          <span class="dot" aria-label="online"></span>
        </div>
      `,
    )
    .join("");
}

function renderMetrics(alerts, blockedCount = 0) {
  const severityCounts = countBy(alerts, (alert) => severityFor(alert.Type));
  const typeCounts = countBy(alerts, (alert) => alert.Type);
  const topThreat = Object.entries(typeCounts).sort((a, b) => b[1] - a[1])[0];

  $("totalAlerts").textContent = String(alerts.length);
  $("criticalAlerts").textContent = String(severityCounts.CRITICAL || 0);
  $("uniqueSources").textContent = String(blockedCount);
  $("topThreat").textContent = topThreat ? topThreat[0] : "None";
  $("totalAlertsHint").textContent = alerts.length === allAlerts.length ? "All records" : "Filtered records";
  $("alertCountLabel").textContent = `${alerts.length} visible (Click any row to open AI Triage)`;
}

function renderSeverityBars(alerts) {
  const counts = countBy(alerts, (alert) => severityFor(alert.Type));
  const max = Math.max(1, ...severityOrder.map((severity) => counts[severity] || 0));
  $("severityBars").innerHTML = severityOrder
    .map((severity) => {
      const value = counts[severity] || 0;
      const width = Math.max(4, Math.round((value / max) * 100));
      const cls = severityClass[severity];
      return `
        <div class="severity-row">
          <span class="${cls}">${severity}</span>
          <span class="bar-track"><span class="bar-fill bg-${cls}" style="width:${width}%"></span></span>
          <strong>${value}</strong>
        </div>
      `;
    })
    .join("");
}

function renderRows(alerts) {
  const body = $("alertRows");
  if (!alerts.length) {
    body.innerHTML = '<tr class="empty-row"><td colspan="6">No alerts match the current view.</td></tr>';
    return;
  }
  body.innerHTML = alerts
    .slice(0, 100)
    .map((alert, index) => {
      const severity = severityFor(alert.Type);
      const cls = severityClass[severity];
      return `
        <tr data-index="${index}" style="cursor: pointer;">
          <td class="mono">${escapeHtml(formatClock(alert.Timestamp))}</td>
          <td><span class="severity-pill ${cls}">${severity}</span></td>
          <td>${escapeHtml(alert.Type)}</td>
          <td class="mono">${escapeHtml(alert["Source IP"])}</td>
          <td>${escapeHtml(alert.Location)}</td>
          <td>${escapeHtml(alert.Details)}</td>
        </tr>
      `;
    })
    .join("");
}

function render(blockedCount = 0) {
  renderThreatFilter();
  const alerts = filteredAlerts();
  renderMetrics(alerts, blockedCount);
  renderSeverityBars(alerts);
  renderRows(alerts);
}

// ── API Operations ──
async function refreshData() {
  if (!activeToken) return;
  try {
    const [healthResponse, alertsResponse, blockedResponse] = await Promise.all([
      fetch(`${apiBase()}/health`, { headers: authHeaders() }),
      fetch(`${apiBase()}/api/alerts?limit=500&newest_first=true`, { headers: authHeaders() }),
      fetch(`${apiBase()}/api/blocked-ips`, { headers: authHeaders() }),
    ]);

    checkAuthResponse(healthResponse.status);
    checkAuthResponse(alertsResponse.status);
    checkAuthResponse(blockedResponse.status);

    if (!healthResponse.ok || !alertsResponse.ok || !blockedResponse.ok) {
      throw new Error("API returned an error");
    }

    const health = await healthResponse.json();
    const alertPayload = await alertsResponse.json();
    const blockedList = await blockedResponse.json();
    allAlerts = alertPayload.alerts || [];

    setStatus(true, health.ai_ready ? "Online" : "API Online");
    renderBrains(health);
    renderBlockedIPs(blockedList);
    render(blockedList.length);
    $("lastUpdated").textContent = `Updated ${new Date().toLocaleTimeString()}`;
  } catch (error) {
    setStatus(false, "Offline");
    $("lastUpdated").textContent = "Unable to reach API";
  }
}

function renderBlockedIPs(blockedList) {
  const body = $("blockedRows");
  if (!body) return;
  
  const label = $("ipsActiveLabel");
  if (label) {
    label.textContent = `${blockedList.length} IP${blockedList.length === 1 ? "" : "s"} blocked`;
  }
  
  if (!blockedList.length) {
    body.innerHTML = '<tr class="empty-row"><td colspan="4">No IPs blacklisted in active IPS.</td></tr>';
    return;
  }
  
  body.innerHTML = blockedList
    .map((row) => `
      <tr>
        <td class="mono font-bold">${escapeHtml(row.ip)}</td>
        <td><span class="mono critical font-bold">${Number(row.score).toFixed(0)}</span></td>
        <td class="mono text-muted" style="font-size: 11.5px;">${escapeHtml(row.updated_at || "--")}</td>
        <td>
          <button class="button button-secondary unblock-btn" style="padding: 4px 10px; font-size: 11px;" data-ip="${escapeHtml(row.ip)}" type="button">
            Unblock
          </button>
        </td>
      </tr>
    `)
    .join("");
}

async function submitLog() {
  const line = $("logLine").value.trim();
  if (!line) {
    $("ingestResult").textContent = "Enter a log line";
    return;
  }

  $("sendLogBtn").disabled = true;
  $("ingestResult").textContent = "Submitting";
  try {
    const response = await fetch(`${apiBase()}/api/logs`, {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({ line, source: "frontend" }),
    });

    checkAuthResponse(response.status);

    if (response.status === 403) {
      $("ingestResult").textContent = "Access Denied: Admin role required";
      return;
    }

    if (!response.ok) {
      throw new Error("Submit failed");
    }
    const payload = await response.json();
    $("ingestResult").textContent = `${payload.alert_count} alert${payload.alert_count === 1 ? "" : "s"}`;
    await refreshData();
  } catch (error) {
    $("ingestResult").textContent = "Submit failed";
  } finally {
    $("sendLogBtn").disabled = false;
  }
}

// ── Tab Router Logic ──
// ── Global Incident and Analytics State ──
let activeTriageAlert = null;
let modelAnalyticsData = null;

function switchTab(targetTab) {
  const tabs = ["dashboard", "ingestion", "brains"];
  for (const tab of tabs) {
    const btn = $(`tab-${tab}`);
    const page = $(`page-${tab}`);
    if (tab === targetTab) {
      btn.classList.add("active");
      page.style.display = "block";
    } else {
      btn.classList.remove("active");
      page.style.display = "none";
    }
  }
  
  if (targetTab === "dashboard") {
    refreshData();
  } else if (targetTab === "brains") {
    loadModelAnalytics();
  }
}

function openTriageConsole(alert) {
  activeTriageAlert = alert;
  
  // Set basic info fields
  $("triageThreatType").textContent = alert.Type;
  $("triageThreatType").className = severityClass[severityFor(alert.Type)] || "";
  $("triageSourceIP").textContent = alert["Source IP"];
  
  // Reset firewall action logs and hints
  if (currentUser && currentUser.role === "ADMIN") {
    $("deployFirewallBtn").disabled = false;
    $("deployResult").textContent = "Ready to deploy rule.";
    $("deployResult").className = "deploy-note";
  } else {
    $("deployFirewallBtn").disabled = true;
    $("deployResult").textContent = "Only Administrators can deploy firewalls";
    $("deployResult").className = "deploy-note";
  }
  
  // Parse and display AI Report parameters
  let report = alert.ai_report;
  if (typeof report === "string") {
    try {
      report = JSON.parse(report);
    } catch (e) {
      report = null;
    }
  }
  
  if (report) {
    $("triageProbability").textContent = report.probability || "100.0%";
    $("triageAnalysis").textContent = report.analysis || "No threat details parsed yet.";
    
    // Mitigations List
    const mitigations = report.mitigations || [];
    if (mitigations.length) {
      $("triageMitigations").innerHTML = mitigations
        .map((mit) => `<li>${escapeHtml(mit)}</li>`)
        .join("");
    } else {
      $("triageMitigations").innerHTML = "<li>No specific mitigations recommended.</li>";
    }
    
    // Commands
    $("triageCmdWin").textContent = report.firewall_cmd_windows || `New-NetFirewallRule -DisplayName "Block Cerberus Attacker ${alert["Source IP"]}" -Direction Inbound -Action Block -RemoteAddress ${alert["Source IP"]}`;
    $("triageCmdLin").textContent = report.firewall_cmd_linux || `sudo iptables -A INPUT -s ${alert["Source IP"]} -j DROP`;
  } else {
    // Standard signature fallback state
    $("triageProbability").textContent = "100.0%";
    $("triageAnalysis").textContent = alert.Details || "No further details available for this signature match.";
    $("triageMitigations").innerHTML = `
      <li>Block the attacker's IP address globally at the perimeter firewall.</li>
      <li>Verify all log headers and inputs to prevent parameter tampering.</li>
    `;
    $("triageCmdWin").textContent = `New-NetFirewallRule -DisplayName "Block Cerberus Attacker ${alert["Source IP"]}" -Direction Inbound -Action Block -RemoteAddress ${alert["Source IP"]}`;
    $("triageCmdLin").textContent = `sudo iptables -A INPUT -s ${alert["Source IP"]} -j DROP`;
  }
  
  // Slide in panel
  $("triageConsole").classList.add("open");
}

async function loadModelAnalytics() {
  if (!activeToken) return;
  try {
    const response = await fetch(`${apiBase()}/api/model-analytics`, {
      headers: authHeaders(),
    });
    checkAuthResponse(response.status);
    if (!response.ok) {
      throw new Error("Failed to fetch model analytics");
    }
    
    const payload = await response.json();
    modelAnalyticsData = payload.analytics || {};
    renderModelAnalytics();
  } catch (error) {
    console.error("Error loading model analytics:", error);
  }
}

function renderModelAnalytics() {
  if (!modelAnalyticsData) return;
  
  const modelType = $("modelSelect").value;
  const metrics = modelAnalyticsData[modelType];
  
  if (!metrics || !metrics.trained) {
    // Empty state fields
    $("modelAccuracy").textContent = "0.0%";
    $("modelPrecision").textContent = "0.0%";
    $("modelRecall").textContent = "0.0%";
    $("modelF1").textContent = "0.0%";
    $("matrixTN").textContent = "0";
    $("matrixFP").textContent = "0";
    $("matrixFN").textContent = "0";
    $("matrixTP").textContent = "0";
    
    $("featureImportanceBars").innerHTML = `
      <div class="empty-row" style="padding: 20px;">
        ⚠️ Model brain '${escapeHtml(modelType)}' has not been trained yet.<br>
        <span style="font-size: 11px; font-weight: normal; color: var(--text-muted);">
          Run <code>python trainer.py --type ${escapeHtml(modelType)}</code> to compile this brain and generate full analytics.
        </span>
      </div>
    `;
    return;
  }
  
  const formatPercent = (val) => `${(val * 100).toFixed(1)}%`;
  
  // Set accuracy and f1 tags colors
  const setPerfClass = (el, val) => {
    el.className = val >= 0.85 ? "low" : (val >= 0.70 ? "medium" : "critical");
  };
  
  $("modelAccuracy").textContent = formatPercent(metrics.accuracy || 0);
  $("modelPrecision").textContent = formatPercent(metrics.precision || 0);
  $("modelRecall").textContent = formatPercent(metrics.recall || 0);
  $("modelF1").textContent = formatPercent(metrics.f1_score || 0);
  
  setPerfClass($("modelAccuracy"), metrics.accuracy || 0);
  setPerfClass($("modelPrecision"), metrics.precision || 0);
  setPerfClass($("modelRecall"), metrics.recall || 0);
  setPerfClass($("modelF1"), metrics.f1_score || 0);
  
  // Confusion Matrix Counts
  const cm = metrics.confusion_matrix || { tn: 0, fp: 0, fn: 0, tp: 0 };
  $("matrixTN").textContent = String(cm.tn || 0).replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  $("matrixFP").textContent = String(cm.fp || 0).replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  $("matrixFN").textContent = String(cm.fn || 0).replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  $("matrixTP").textContent = String(cm.tp || 0).replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  
  // Feature Importances Progress Bars
  const importanceDict = metrics.feature_importances || {};
  const sortedFeatures = Object.entries(importanceDict).sort((a, b) => b[1] - a[1]);
  
  if (!sortedFeatures.length) {
    $("featureImportanceBars").innerHTML = `
      <div class="empty-row" style="padding: 20px;">
        ⚠️ Feature weights not generated yet.<br>
        <span style="font-size: 11px; font-weight: normal; color: var(--text-muted);">
          Re-compile this model using the training pipeline.
        </span>
      </div>
    `;
    return;
  }
  
  const maxVal = Math.max(0.0001, ...sortedFeatures.map((f) => f[1]));
  
  $("featureImportanceBars").innerHTML = sortedFeatures
    .map(([feature, weight]) => {
      const percentage = (weight * 100).toFixed(1) + "%";
      const fillWidth = Math.max(4, Math.round((weight / maxVal) * 100));
      return `
        <div class="severity-row">
          <span style="width: 155px; font-size: 11px; text-transform: none; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" class="mono text-dim" title="${escapeHtml(feature)}">
            ${escapeHtml(feature)}
          </span>
          <span class="bar-track">
            <span class="bar-fill" style="width: ${fillWidth}%; background: linear-gradient(90deg, var(--cyan), var(--purple)); box-shadow: 0 0 10px var(--cyan);"></span>
          </span>
          <strong style="width: 55px; text-align: right; font-size: 11.5px;" class="mono">${percentage}</strong>
        </div>
      `;
    })
    .join("");
}

// ==========================================
// AUTHENTICATION LOGIC
// ==========================================
async function handleLogin(e) {
  e.preventDefault();
  const username = $("loginUser").value.trim();
  const password = $("loginPass").value;
  const loginError = $("loginError");
  const loginBtn = $("loginBtn");

  if (!username || !password) {
    loginError.textContent = "Please fill in all fields";
    return;
  }

  loginError.textContent = "";
  loginBtn.disabled = true;
  loginBtn.textContent = "Signing In...";

  try {
    const response = await fetch(`${apiBase()}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });

    if (!response.ok) {
      throw new Error("Invalid username or password");
    }

    const payload = await response.json();
    activeToken = payload.token;
    currentUser = { username: payload.username, role: payload.role };

    localStorage.setItem("logsentry_token", activeToken);
    localStorage.setItem("logsentry_username", currentUser.username);
    localStorage.setItem("logsentry_role", currentUser.role);

    // Bootstrap dashboard view
    bootstrapConsole();
  } catch (error) {
    loginError.textContent = error.message;
  } finally {
    loginBtn.disabled = false;
    loginBtn.textContent = "Sign In";
  }
}

async function handleLogout() {
  try {
    // Attempt graceful revocation from backend
    if (activeToken) {
      await fetch(`${apiBase()}/api/auth/logout`, {
        method: "POST",
        headers: authHeaders(),
      });
    }
  } catch (err) {
    // Ignore graceful logout failures
  }

  // Purge local storage
  activeToken = null;
  currentUser = null;
  localStorage.removeItem("logsentry_token");
  localStorage.removeItem("logsentry_username");
  localStorage.removeItem("logsentry_role");

  if (refreshTimer) {
    clearInterval(refreshTimer);
    refreshTimer = null;
  }

  // Clear visual tables
  allAlerts = [];
  $("alertRows").innerHTML = "";

  // Switch display back to login
  $("loginOverlay").style.display = "flex";
  $("appShell").style.display = "none";
  $("loginPass").value = "";
}

async function verifySession() {
  if (!activeToken) {
    handleLogout();
    return;
  }

  try {
    const response = await fetch(`${apiBase()}/api/auth/me`, {
      headers: authHeaders(),
    });

    if (!response.ok) {
      throw new Error("Invalid Session");
    }

    const payload = await response.json();
    currentUser = { username: payload.username, role: payload.role };
    bootstrapConsole();
  } catch (err) {
    handleLogout();
  }
}

function bootstrapConsole() {
  if (!currentUser) return;

  // Render Topbar user profile badge
  $("userBadgeName").textContent = currentUser.username;
  
  const roleBadge = $("userBadgeRole");
  roleBadge.textContent = currentUser.role;
  roleBadge.className = `role-badge ${currentUser.role === "ADMIN" ? "role-admin" : "role-analyst"}`;

  // Enforce role constraints (ANALYST is completely locked out of Log Ingestions)
  if (currentUser.role === "ANALYST") {
    $("tab-ingestion").style.display = "none";
    switchTab("dashboard");
  } else {
    $("tab-ingestion").style.display = "block";
  }

  // Switch views
  $("loginOverlay").style.display = "none";
  $("appShell").style.display = "grid";

  // Bootstrap data loop
  resetTimer();
  refreshData();
}

function resetTimer() {
  if (refreshTimer) {
    clearInterval(refreshTimer);
  }
  const seconds = Number($("refreshInterval").value);
  if (seconds > 0) {
    refreshTimer = setInterval(refreshData, seconds * 1000);
  }
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

// ── Event Handlers ──
$("refreshBtn").addEventListener("click", refreshData);
$("sendLogBtn").addEventListener("click", submitLog);
$("sampleLogBtn").addEventListener("click", () => {
  $("logLine").value = "192.168.1.5 - GET /login?dport=80&dur=1500&fpkts=85&bpkts=60&byte_rate=750.0 HTTP/1.1";
});

$("threatFilter").addEventListener("change", () => render(Number($("uniqueSources").textContent)));
$("severityFilter").addEventListener("change", () => render(Number($("uniqueSources").textContent)));
$("refreshInterval").addEventListener("change", resetTimer);
$("apiUrl").addEventListener("change", refreshData);

$("tab-dashboard").addEventListener("click", () => switchTab("dashboard"));
$("tab-ingestion").addEventListener("click", () => switchTab("ingestion"));
$("tab-brains").addEventListener("click", () => switchTab("brains"));

$("loginForm").addEventListener("submit", handleLogin);
$("logoutBtn").addEventListener("click", handleLogout);

// Alert row click selection -> Open slide-out triage overlay
$("alertRows").addEventListener("click", (e) => {
  const tr = e.target.closest("tr");
  if (!tr || tr.classList.contains("empty-row")) return;
  const index = parseInt(tr.getAttribute("data-index"), 10);
  const alert = filteredAlerts().slice(0, 100)[index];
  if (alert) {
    openTriageConsole(alert);
  }
});

// Close triage panel click
$("closeTriageBtn").addEventListener("click", () => {
  $("triageConsole").classList.remove("open");
  activeTriageAlert = null;
});

// Active IPS Table click unblock action
$("blockedRows").addEventListener("click", async (e) => {
  const btn = e.target.closest(".unblock-btn");
  if (!btn) return;
  const ip = btn.getAttribute("data-ip");
  if (!ip) return;
  
  btn.disabled = true;
  btn.textContent = "Unblocking...";
  
  try {
    const response = await fetch(`${apiBase()}/api/ips/unblock`, {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({ ip }),
    });
    checkAuthResponse(response.status);
    
    if (response.status === 403) {
      alert("Access Denied: Admin role required to unblock IPs.");
      btn.disabled = false;
      btn.textContent = "Unblock";
      return;
    }
    
    if (response.ok) {
      await refreshData();
    } else {
      alert("Failed to unblock IP address.");
      btn.disabled = false;
      btn.textContent = "Unblock";
    }
  } catch (err) {
    console.error("Error unblocking IP:", err);
    alert("Connection error occurred.");
    btn.disabled = false;
    btn.textContent = "Unblock";
  }
});

// Deploy Kernel OS-Level Firewall block rule click trigger
$("deployFirewallBtn").addEventListener("click", async () => {
  if (!activeTriageAlert) return;
  const ip = activeTriageAlert["Source IP"];
  if (!ip) return;
  
  $("deployFirewallBtn").disabled = true;
  $("deployResult").textContent = "Deploying kernel firewall block rule...";
  $("deployResult").style.color = "var(--medium)";
  
  try {
    const response = await fetch(`${apiBase()}/api/ips/deploy-firewall`, {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({ ip }),
    });
    checkAuthResponse(response.status);
    
    if (response.status === 403) {
      $("deployResult").textContent = "Access Denied: Admin role required";
      $("deployResult").style.color = "var(--critical)";
      return;
    }
    
    const payload = await response.json();
    if (response.ok && payload.success) {
      $("deployResult").textContent = `SUCCESS: Firewall rule deployed.`;
      $("deployResult").style.color = "var(--low)";
      await refreshData();
    } else {
      $("deployResult").textContent = `FAILED: ${payload.message || "Execution error"}`;
      $("deployResult").style.color = "var(--critical)";
    }
  } catch (err) {
    console.error("Error deploying firewall:", err);
    $("deployResult").textContent = "API connection error occurred.";
    $("deployResult").style.color = "var(--critical)";
  } finally {
    $("deployFirewallBtn").disabled = false;
  }
});

// Model selection dropdown changed
$("modelSelect").addEventListener("change", renderModelAnalytics);

// Bootstrap Session Validation on load
if (activeToken) {
  verifySession();
} else {
  handleLogout();
}
