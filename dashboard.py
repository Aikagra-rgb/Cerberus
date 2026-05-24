import os
import time
import glob
from html import escape

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from src.alert_store import ALERT_COLUMNS, list_alerts, migrate_legacy_csv
from src.config import DATA_DIR, MODELS_DIR, MODEL_CONFIGS

# ==========================================
# CONFIGURATION
# ==========================================
LEGACY_EVIDENCE_FILE = os.path.join(DATA_DIR, "hids_alerts.csv")
PAGE_TITLE = "Cerberus SOC"
PAGE_ICON = "🛡️"

# Threat severity classification
SEVERITY_MAP = {
    "SQL Injection": "CRITICAL",
    "XSS Attack": "HIGH",
    "Path Traversal": "CRITICAL",
    "File Tampering": "CRITICAL",
    "AI-WEB": "HIGH",
    "AI-AUTH": "HIGH",
    "AI-DOS": "CRITICAL",
    "AI-DDOS": "CRITICAL",
    "AI-RECON": "MEDIUM",
    "AI-BOTNET": "HIGH",
    "AI-INFILTRATION": "CRITICAL",
}

SEVERITY_COLORS = {
    "CRITICAL": "#ff1744",
    "HIGH": "#ff9100",
    "MEDIUM": "#ffd600",
    "LOW": "#00e676",
}

# Brain display metadata
BRAIN_META = {
    "web":          {"icon": "🌐", "label": "Web Attacks"},
    "auth":         {"icon": "🔑", "label": "Brute Force"},
    "dos":          {"icon": "💥", "label": "DoS Floods"},
    "recon":        {"icon": "🔍", "label": "Port Scans"},
    "ddos":         {"icon": "🌊", "label": "DDoS LOIC"},
    "botnet":       {"icon": "🤖", "label": "Botnet C2"},
    "infiltration": {"icon": "🕵️", "label": "Infiltration"},
}

# ==========================================
# PAGE CONFIG
# ==========================================
st.set_page_config(
    page_title=PAGE_TITLE,
    page_icon=PAGE_ICON,
    layout="wide",
    initial_sidebar_state="expanded"
)

# ==========================================
# PREMIUM CSS
# ==========================================
st.markdown("""
<style>
    /* ── Import Google Font ── */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');

    /* ── Global ── */
    .stApp {
        background: linear-gradient(135deg, #0a0e17 0%, #0d1321 40%, #111827 100%);
        font-family: 'Inter', sans-serif;
    }
    
    /* Hide default Streamlit elements */
    #MainMenu, footer, header {visibility: hidden;}

    /* ── Header Banner ── */
    .soc-header {
        background: linear-gradient(135deg, rgba(6,182,212,0.12) 0%, rgba(139,92,246,0.10) 50%, rgba(236,72,153,0.08) 100%);
        border: 1px solid rgba(6,182,212,0.2);
        border-radius: 16px;
        padding: 20px 32px;
        margin-bottom: 24px;
        backdrop-filter: blur(12px);
    }
    .soc-header h1 {
        font-size: 28px;
        font-weight: 800;
        background: linear-gradient(135deg, #06b6d4, #8b5cf6, #ec4899);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin: 0;
        letter-spacing: -0.5px;
    }
    .soc-header p {
        color: #94a3b8;
        font-size: 13px;
        margin: 4px 0 0 0;
        font-weight: 400;
    }

    /* ── KPI Cards ── */
    .kpi-card {
        background: linear-gradient(145deg, rgba(30,41,59,0.7) 0%, rgba(15,23,42,0.9) 100%);
        border: 1px solid rgba(100,116,139,0.2);
        border-radius: 14px;
        padding: 20px;
        text-align: center;
        backdrop-filter: blur(8px);
        transition: all 0.3s ease;
        min-height: 120px;
    }
    .kpi-card:hover {
        border-color: rgba(6,182,212,0.4);
        box-shadow: 0 0 20px rgba(6,182,212,0.1);
        transform: translateY(-2px);
    }
    .kpi-icon { font-size: 28px; margin-bottom: 6px; }
    .kpi-value {
        font-size: 32px;
        font-weight: 800;
        color: #f1f5f9;
        line-height: 1.2;
    }
    .kpi-label {
        font-size: 11px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 1.2px;
        color: #64748b;
        margin-top: 4px;
    }
    .kpi-value.critical { color: #ff1744; }
    .kpi-value.warning  { color: #ff9100; }
    .kpi-value.info     { color: #06b6d4; }
    .kpi-value.success  { color: #00e676; }

    /* ── Section Panels ── */
    .glass-panel {
        background: linear-gradient(145deg, rgba(30,41,59,0.5) 0%, rgba(15,23,42,0.7) 100%);
        border: 1px solid rgba(100,116,139,0.15);
        border-radius: 14px;
        padding: 24px;
        margin-bottom: 16px;
        backdrop-filter: blur(8px);
    }
    .panel-title {
        font-size: 15px;
        font-weight: 700;
        color: #e2e8f0;
        margin-bottom: 16px;
        display: flex;
        align-items: center;
        gap: 8px;
    }
    .panel-title .dot {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        display: inline-block;
        animation: pulse-dot 2s ease-in-out infinite;
    }
    .dot-red    { background: #ff1744; box-shadow: 0 0 8px #ff1744; }
    .dot-green  { background: #00e676; box-shadow: 0 0 8px #00e676; }
    .dot-cyan   { background: #06b6d4; box-shadow: 0 0 8px #06b6d4; }
    .dot-purple { background: #8b5cf6; box-shadow: 0 0 8px #8b5cf6; }

    @keyframes pulse-dot {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.4; }
    }

    /* ── Brain Status Grid ── */
    .brain-grid {
        display: grid;
        grid-template-columns: repeat(auto-fill, minmax(130px, 1fr));
        gap: 10px;
    }
    .brain-chip {
        background: rgba(15,23,42,0.8);
        border: 1px solid rgba(100,116,139,0.2);
        border-radius: 10px;
        padding: 10px 12px;
        text-align: center;
        font-size: 12px;
        transition: all 0.2s;
    }
    .brain-chip.online {
        border-color: rgba(0,230,118,0.3);
    }
    .brain-chip.offline {
        border-color: rgba(255,23,68,0.3);
        opacity: 0.5;
    }
    .brain-chip .brain-icon { font-size: 20px; }
    .brain-chip .brain-name {
        color: #94a3b8;
        font-weight: 600;
        font-size: 10px;
        text-transform: uppercase;
        letter-spacing: 0.8px;
        margin-top: 2px;
    }
    .brain-chip .brain-status {
        font-size: 9px;
        font-weight: 700;
        margin-top: 2px;
    }
    .brain-chip.online .brain-status { color: #00e676; }
    .brain-chip.offline .brain-status { color: #ff1744; }

    /* ── Severity Badge ── */
    .severity-badge {
        display: inline-block;
        padding: 2px 10px;
        border-radius: 20px;
        font-size: 10px;
        font-weight: 700;
        letter-spacing: 0.8px;
    }
    .sev-critical { background: rgba(255,23,68,0.15); color: #ff1744; border: 1px solid rgba(255,23,68,0.3); }
    .sev-high     { background: rgba(255,145,0,0.15); color: #ff9100; border: 1px solid rgba(255,145,0,0.3); }
    .sev-medium   { background: rgba(255,214,0,0.15); color: #ffd600; border: 1px solid rgba(255,214,0,0.3); }
    .sev-low      { background: rgba(0,230,118,0.15); color: #00e676; border: 1px solid rgba(0,230,118,0.3); }

    /* ── Alert Feed ── */
    .alert-row {
        background: rgba(15,23,42,0.6);
        border: 1px solid rgba(100,116,139,0.1);
        border-radius: 10px;
        padding: 12px 16px;
        margin-bottom: 8px;
        display: flex;
        align-items: center;
        gap: 16px;
        transition: all 0.2s;
    }
    .alert-row:hover {
        border-color: rgba(6,182,212,0.3);
        background: rgba(30,41,59,0.6);
    }
    .alert-row .alert-time {
        color: #475569;
        font-size: 11px;
        font-weight: 500;
        min-width: 65px;
    }
    .alert-row .alert-type {
        font-weight: 700;
        font-size: 13px;
        min-width: 160px;
    }
    .alert-row .alert-ip {
        color: #06b6d4;
        font-size: 12px;
        font-family: 'Courier New', monospace;
        font-weight: 600;
        min-width: 120px;
    }
    .alert-row .alert-detail {
        color: #64748b;
        font-size: 11px;
        flex: 1;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
    }

    /* ── Empty State ── */
    .empty-state {
        text-align: center;
        padding: 60px 20px;
        color: #334155;
    }
    .empty-state .empty-icon { font-size: 48px; margin-bottom: 12px; }
    .empty-state p { font-size: 14px; color: #475569; }

    /* ── Sidebar ── */
    section[data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0f172a 0%, #0a0e17 100%);
        border-right: 1px solid rgba(100,116,139,0.15);
    }
    section[data-testid="stSidebar"] .stMarkdown h2 {
        color: #e2e8f0;
        font-size: 16px;
    }

    /* ── Streamlit Metric Override ── */
    div[data-testid="stMetric"] { display: none; }

    /* ── Dataframe Override ── */
    div[data-testid="stDataFrame"] {
        border: 1px solid rgba(100,116,139,0.15);
        border-radius: 12px;
        overflow: hidden;
    }
</style>
""", unsafe_allow_html=True)


# ==========================================
# HELPER FUNCTIONS
# ==========================================
def load_data():
    """Reads alerts from SQLite, importing the legacy CSV once if present."""
    try:
        migrate_legacy_csv(LEGACY_EVIDENCE_FILE)
        df = pd.DataFrame(list_alerts(), columns=ALERT_COLUMNS)
        df.dropna(how='all', inplace=True)
        return df
    except Exception:
        return pd.DataFrame(columns=ALERT_COLUMNS)


def get_severity(threat_type):
    """Maps threat type to severity level."""
    return SEVERITY_MAP.get(threat_type, "MEDIUM")


def get_brain_status():
    """Checks which AI brains have trained models on disk."""
    status = {}
    for name in MODEL_CONFIGS:
        path = os.path.join(MODELS_DIR, f"{name}_classifier.pkl")
        status[name] = os.path.exists(path)
    return status


def count_by_severity(df):
    """Counts alerts grouped by severity."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    if 'Type' in df.columns:
        for t in df['Type']:
            sev = get_severity(t)
            counts[sev] = counts.get(sev, 0) + 1
    return counts


def extract_confidence(detail_str):
    """Extracts confidence % from alert detail string."""
    if pd.isna(detail_str):
        return None
    if "Confidence:" in str(detail_str):
        try:
            part = str(detail_str).split("Confidence:")[1].split("%")[0].strip()
            return float(part)
        except (ValueError, IndexError):
            return None
    return None


def html_escape(value):
    """Escapes alert values before rendering custom HTML blocks."""
    if pd.isna(value):
        return ""
    return escape(str(value), quote=True)


# ==========================================
# SIDEBAR
# ==========================================
with st.sidebar:
    # Logo area
    st.markdown("""
    <div style="text-align:center; padding: 16px 0 8px 0;">
        <div style="font-size:36px;">🛡️</div>
        <div style="font-size:18px; font-weight:800; 
             background: linear-gradient(135deg, #06b6d4, #8b5cf6);
             -webkit-background-clip: text; -webkit-text-fill-color: transparent;
             letter-spacing: -0.5px;">Cerberus</div>
        <div style="font-size:10px; color:#475569; font-weight:600; 
             letter-spacing:2px; text-transform:uppercase; margin-top:2px;">
             SOC DASHBOARD v5.0</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")

    # System status
    st.markdown("## ⚙️ Controls")
    refresh_rate = st.slider("Refresh Rate (sec)", 1, 10, 2, key="refresh_slider")

    st.markdown("---")

    # Filters
    st.markdown("## 🔎 Filters")
    initial_df = load_data()
    threat_types = ["All"]
    if 'Type' in initial_df.columns and not initial_df.empty:
        threat_types.extend(sorted(initial_df['Type'].unique().tolist()))
    filter_type = st.selectbox("Threat Type", threat_types, key='filter_select')

    severity_options = ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"]
    filter_severity = st.selectbox("Severity", severity_options, key='sev_filter')

    st.markdown("---")

    # Brain status
    st.markdown("## 🧠 AI Brains")
    brain_status = get_brain_status()
    brain_html = '<div class="brain-grid">'
    for name, is_online in brain_status.items():
        meta = BRAIN_META.get(name, {"icon": "🔬", "label": name})
        css_class = "online" if is_online else "offline"
        status_text = "ONLINE" if is_online else "OFFLINE"
        brain_html += f"""
        <div class="brain-chip {css_class}">
            <div class="brain-icon">{meta['icon']}</div>
            <div class="brain-name">{meta['label']}</div>
            <div class="brain-status">● {status_text}</div>
        </div>"""
    brain_html += '</div>'
    st.markdown(brain_html, unsafe_allow_html=True)

    online_count = sum(1 for v in brain_status.values() if v)
    total_count = len(brain_status)
    st.markdown(f"""
    <div style="text-align:center; margin-top:12px; font-size:11px; color:#64748b;">
        {online_count}/{total_count} Brains Active
    </div>
    """, unsafe_allow_html=True)


# ==========================================
# MAIN HEADER
# ==========================================
st.markdown("""
<div class="soc-header">
    <h1>🛡️ Cerberus Security Operations Center</h1>
    <p>Real-time hybrid intrusion detection — Signature Engine + Multi-Brain AI Classifier + File Integrity Monitor</p>
</div>
""", unsafe_allow_html=True)

# ==========================================
# MAIN DASHBOARD LOOP
# ==========================================
dashboard_placeholder = st.empty()

while True:
    unique_key = time.time()

    with dashboard_placeholder.container():
        # 1. Load & Filter Data
        df = load_data()

        if filter_type != "All" and 'Type' in df.columns and not df.empty:
            df = df[df["Type"] == filter_type]

        if filter_severity != "All" and 'Type' in df.columns and not df.empty:
            df = df[df['Type'].apply(get_severity) == filter_severity]

        # 2. Calculate KPIs
        total_alerts = len(df)
        unique_attackers = df['Source IP'].nunique() if 'Source IP' in df.columns and not df.empty else 0

        if 'Type' in df.columns and not df.empty:
            most_common_threat = df['Type'].mode()[0] if not df['Type'].mode().empty else "None"
            last_seen = df.iloc[-1]['Timestamp'] if 'Timestamp' in df.columns else "--"
        else:
            most_common_threat = "None"
            last_seen = "--"

        sev_counts = count_by_severity(df)
        last_alert_time = str(last_seen).split(" ")[-1] if last_seen != "--" else "N/A"

        # 3. KPI Cards Row
        k1, k2, k3, k4, k5, k6 = st.columns(6)

        with k1:
            color_class = "critical" if total_alerts > 50 else ("warning" if total_alerts > 10 else "info")
            st.markdown(f"""
            <div class="kpi-card">
                <div class="kpi-icon">🚨</div>
                <div class="kpi-value {color_class}">{total_alerts}</div>
                <div class="kpi-label">Total Alerts</div>
            </div>""", unsafe_allow_html=True)

        with k2:
            st.markdown(f"""
            <div class="kpi-card">
                <div class="kpi-icon">👤</div>
                <div class="kpi-value info">{unique_attackers}</div>
                <div class="kpi-label">Unique Attackers</div>
            </div>""", unsafe_allow_html=True)

        with k3:
            st.markdown(f"""
            <div class="kpi-card">
                <div class="kpi-icon">⚠️</div>
                <div class="kpi-value critical">{sev_counts['CRITICAL']}</div>
                <div class="kpi-label">Critical</div>
            </div>""", unsafe_allow_html=True)

        with k4:
            st.markdown(f"""
            <div class="kpi-card">
                <div class="kpi-icon">🔶</div>
                <div class="kpi-value warning">{sev_counts['HIGH']}</div>
                <div class="kpi-label">High</div>
            </div>""", unsafe_allow_html=True)

        with k5:
            st.markdown(f"""
            <div class="kpi-card">
                <div class="kpi-icon">🔥</div>
                <div class="kpi-value" style="font-size:16px; color:#e2e8f0;">{most_common_threat}</div>
                <div class="kpi-label">Top Threat</div>
            </div>""", unsafe_allow_html=True)

        with k6:
            st.markdown(f"""
            <div class="kpi-card">
                <div class="kpi-icon">🕒</div>
                <div class="kpi-value" style="font-size:18px; color:#94a3b8;">{last_alert_time}</div>
                <div class="kpi-label">Last Incident</div>
            </div>""", unsafe_allow_html=True)

        st.markdown("<div style='height:20px'></div>", unsafe_allow_html=True)

        # 4. Charts Row
        if not df.empty:
            chart1, chart2 = st.columns(2)

            with chart1:
                st.markdown("""
                <div class="panel-title">
                    <span class="dot dot-purple"></span> Threat Distribution
                </div>""", unsafe_allow_html=True)

                if 'Type' in df.columns:
                    type_counts = df['Type'].value_counts().reset_index()
                    type_counts.columns = ['Type', 'Count']

                    fig_donut = go.Figure(go.Pie(
                        labels=type_counts['Type'],
                        values=type_counts['Count'],
                        hole=0.55,
                        marker=dict(
                            colors=['#ff1744', '#ff9100', '#ffd600', '#00e676',
                                    '#06b6d4', '#8b5cf6', '#ec4899', '#f97316'],
                            line=dict(color='#0f172a', width=2)
                        ),
                        textinfo='label+percent',
                        textfont=dict(size=11, color='#e2e8f0'),
                        hovertemplate='<b>%{label}</b><br>Count: %{value}<br>Share: %{percent}<extra></extra>'
                    ))
                    fig_donut.update_layout(
                        paper_bgcolor='rgba(0,0,0,0)',
                        plot_bgcolor='rgba(0,0,0,0)',
                        font=dict(color='#94a3b8', family='Inter'),
                        showlegend=False,
                        margin=dict(t=10, l=10, r=10, b=10),
                        height=320,
                        annotations=[dict(
                            text=f'<b>{total_alerts}</b><br><span style="font-size:10px">ALERTS</span>',
                            x=0.5, y=0.5, font_size=24, font_color='#e2e8f0',
                            showarrow=False
                        )]
                    )
                    st.plotly_chart(fig_donut, use_container_width=True, key=f"donut_{unique_key}")

            with chart2:
                st.markdown("""
                <div class="panel-title">
                    <span class="dot dot-red"></span> Top Attacker IPs
                </div>""", unsafe_allow_html=True)

                if 'Source IP' in df.columns:
                    ip_counts = df['Source IP'].value_counts().head(8).reset_index()
                    ip_counts.columns = ['IP', 'Count']

                    fig_bar = go.Figure(go.Bar(
                        x=ip_counts['Count'],
                        y=ip_counts['IP'],
                        orientation='h',
                        marker=dict(
                            color=ip_counts['Count'],
                            colorscale=[[0, '#1e3a5f'], [0.5, '#06b6d4'], [1, '#ff1744']],
                            line=dict(width=0),
                            cornerradius=6,
                        ),
                        hovertemplate='<b>%{y}</b><br>Alerts: %{x}<extra></extra>',
                        text=ip_counts['Count'],
                        textposition='outside',
                        textfont=dict(color='#94a3b8', size=11),
                    ))
                    fig_bar.update_layout(
                        paper_bgcolor='rgba(0,0,0,0)',
                        plot_bgcolor='rgba(0,0,0,0)',
                        font=dict(color='#94a3b8', family='Inter'),
                        margin=dict(t=10, l=10, r=40, b=10),
                        height=320,
                        yaxis=dict(
                            autorange='reversed',
                            gridcolor='rgba(100,116,139,0.08)',
                            tickfont=dict(family='Courier New', size=11, color='#06b6d4'),
                        ),
                        xaxis=dict(
                            gridcolor='rgba(100,116,139,0.08)',
                            showticklabels=False,
                        ),
                        bargap=0.25,
                    )
                    st.plotly_chart(fig_bar, use_container_width=True, key=f"bar_{unique_key}")

            # 5. Severity Breakdown + Timeline Row
            sev_col, timeline_col = st.columns([1, 2])

            with sev_col:
                st.markdown("""
                <div class="panel-title">
                    <span class="dot dot-cyan"></span> Severity Breakdown
                </div>""", unsafe_allow_html=True)

                sev_data = pd.DataFrame([
                    {"Severity": k, "Count": v, "Color": SEVERITY_COLORS[k]}
                    for k, v in sev_counts.items() if v > 0
                ])

                if not sev_data.empty:
                    fig_sev = go.Figure(go.Bar(
                        x=sev_data['Severity'],
                        y=sev_data['Count'],
                        marker=dict(
                            color=sev_data['Color'].tolist(),
                            cornerradius=8,
                            line=dict(width=0),
                        ),
                        text=sev_data['Count'],
                        textposition='outside',
                        textfont=dict(color='#e2e8f0', size=14, family='Inter'),
                        hovertemplate='<b>%{x}</b><br>Count: %{y}<extra></extra>',
                    ))
                    fig_sev.update_layout(
                        paper_bgcolor='rgba(0,0,0,0)',
                        plot_bgcolor='rgba(0,0,0,0)',
                        font=dict(color='#94a3b8', family='Inter'),
                        margin=dict(t=10, l=10, r=10, b=10),
                        height=250,
                        xaxis=dict(gridcolor='rgba(0,0,0,0)', tickfont=dict(size=10, color='#94a3b8')),
                        yaxis=dict(gridcolor='rgba(100,116,139,0.08)', showticklabels=False),
                        bargap=0.35,
                    )
                    st.plotly_chart(fig_sev, use_container_width=True, key=f"sev_{unique_key}")

            with timeline_col:
                st.markdown("""
                <div class="panel-title">
                    <span class="dot dot-green"></span> Alert Timeline
                </div>""", unsafe_allow_html=True)

                if 'Timestamp' in df.columns and not df.empty:
                    df_timeline = df.copy()
                    df_timeline['Timestamp'] = pd.to_datetime(df_timeline['Timestamp'], errors='coerce')
                    df_timeline = df_timeline.dropna(subset=['Timestamp'])

                    if not df_timeline.empty:
                        df_timeline['Severity'] = df_timeline['Type'].apply(get_severity)
                        color_map = SEVERITY_COLORS

                        fig_timeline = px.scatter(
                            df_timeline,
                            x='Timestamp',
                            y='Type',
                            color='Severity',
                            color_discrete_map=color_map,
                            hover_data=['Source IP', 'Details'],
                        )
                        fig_timeline.update_traces(marker=dict(size=10, opacity=0.85, line=dict(width=1, color='#0f172a')))
                        fig_timeline.update_layout(
                            paper_bgcolor='rgba(0,0,0,0)',
                            plot_bgcolor='rgba(0,0,0,0)',
                            font=dict(color='#94a3b8', family='Inter'),
                            margin=dict(t=10, l=10, r=10, b=10),
                            height=250,
                            xaxis=dict(gridcolor='rgba(100,116,139,0.08)'),
                            yaxis=dict(gridcolor='rgba(100,116,139,0.08)', tickfont=dict(size=10)),
                            showlegend=True,
                            legend=dict(
                                orientation='h', yanchor='bottom', y=1.02,
                                font=dict(size=10, color='#94a3b8'),
                                bgcolor='rgba(0,0,0,0)',
                            ),
                        )
                        st.plotly_chart(fig_timeline, use_container_width=True, key=f"timeline_{unique_key}")
                    else:
                        st.markdown('<div class="empty-state"><p>Waiting for timestamped data...</p></div>',
                                    unsafe_allow_html=True)

        # 6. Live Alert Feed
        st.markdown("""
        <div class="panel-title" style="margin-top:8px;">
            <span class="dot dot-red"></span> Live Alert Feed
        </div>""", unsafe_allow_html=True)

        if not df.empty:
            # Show last 25 alerts, newest first
            recent = df.tail(25).iloc[::-1]

            feed_html = ""
            for _, row in recent.iterrows():
                ts = str(row.get('Timestamp', '')).split(' ')[-1] if pd.notna(row.get('Timestamp')) else '--'
                raw_alert_type = str(row.get('Type', 'Unknown'))
                alert_type = html_escape(raw_alert_type)
                ip = html_escape(row.get('Source IP', 'Unknown'))
                detail = html_escape(str(row.get('Details', ''))[:80])
                sev = get_severity(raw_alert_type)
                sev_lower = sev.lower()

                type_color = SEVERITY_COLORS.get(sev, '#94a3b8')

                feed_html += f"""
                <div class="alert-row">
                    <span class="alert-time">{ts}</span>
                    <span class="severity-badge sev-{sev_lower}">{sev}</span>
                    <span class="alert-type" style="color:{type_color};">{alert_type}</span>
                    <span class="alert-ip">{ip}</span>
                    <span class="alert-detail">{detail}</span>
                </div>"""

            st.markdown(feed_html, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div class="empty-state">
                <div class="empty-icon">🔒</div>
                <p>No threats detected. All systems nominal.<br>
                <span style="font-size:12px; color:#334155;">
                    Run <code>python sentinel_engine.py</code> to begin monitoring.
                </span></p>
            </div>
            """, unsafe_allow_html=True)

        # 7. Full Data Table (collapsible)
        with st.expander("📋 View Full Incident Table", expanded=False):
            if not df.empty:
                display_df = df.copy()
                display_df['Severity'] = display_df['Type'].apply(get_severity)
                display_df = display_df[['Timestamp', 'Severity', 'Type', 'Source IP', 'Location', 'Details']]
                st.dataframe(
                    display_df.sort_index(ascending=False),
                    use_container_width=True,
                    hide_index=True,
                    column_config={
                        "Severity": st.column_config.TextColumn(width="small"),
                        "Type": st.column_config.TextColumn(width="medium"),
                        "Source IP": st.column_config.TextColumn(width="small"),
                        "Details": st.column_config.TextColumn(width="large"),
                    }
                )
            else:
                st.info("No data available.")

        # 8. Sleep
        time.sleep(refresh_rate)
