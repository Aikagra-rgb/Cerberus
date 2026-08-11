import json
import os
import platform
import re
import subprocess
import time
from collections import defaultdict
from datetime import datetime
from typing import List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from src.alert_store import (
    authenticate_user,
    create_session,
    delete_session,
    get_session,
    init_db,
    is_ip_blocked,
    list_alerts,
    list_blocked_ips,
    migrate_legacy_csv,
    unblock_ip,
    list_all_reputations,
)
from src.config import DATA_DIR, MODELS_DIR, MODEL_CONFIGS
from src.detection_service import DetectionService
from src.agents.orchestrator import MultiAgentOrchestrator
from src.agents.rag_engine import get_rag_engine


LEGACY_EVIDENCE_FILE = os.path.join(DATA_DIR, "hids_alerts.csv")

app = FastAPI(
    title="Cerberus API",
    version="0.4.0",
    description="Backend API for Cerberus log ingestion, active IPS gatekeeping, and model analytics.",
)

# Enable CORS for the local Single Page Application
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5173",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://localhost:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

detector = DetectionService()
_orchestrator = MultiAgentOrchestrator()


# ==========================================
# PYDANTIC MODEL SCHEMAS
# ==========================================
class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)


class LogIngestRequest(BaseModel):
    line: str = Field(..., min_length=1)
    source: str = "api"


class BatchLogIngestRequest(BaseModel):
    lines: List[str] = Field(..., min_length=1)
    source: str = "api"


# Strict IPv4 validation pattern
_IPV4_RE = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$")


def _validate_ipv4(ip: str) -> str:
    """Validates and returns a safe IPv4 address string, or raises ValueError."""
    ip = ip.strip()
    if not _IPV4_RE.match(ip):
        raise ValueError(f"Invalid IPv4 address: {ip}")
    return ip


# Simple in-memory rate limiter for login attempts
_login_attempts: dict[str, list[float]] = defaultdict(list)
LOGIN_RATE_LIMIT = 5        # max attempts
LOGIN_RATE_WINDOW = 300.0   # per 5-minute window


class UnblockIPRequest(BaseModel):
    ip: str = Field(..., min_length=7, max_length=15)


class DeployFirewallRequest(BaseModel):
    ip: str = Field(..., min_length=7, max_length=15)


class MultiAgentTriageRequest(BaseModel):
    threat_type: str = Field(..., min_length=1)
    source_ip:   str = Field(..., min_length=7, max_length=15)
    details:     str = Field(default="")
    log_line:    str = Field(default="")


# ==========================================
# AUTHENTICATION DEPENDENCIES (MIDDLEWARE)
# ==========================================
async def get_current_user(authorization: Optional[str] = Header(None)) -> dict:
    """Dependency validator for active Bearer token session headers."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid session token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    token = authorization.split(" ")[1].strip()
    session_data = get_session(token)
    if not session_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired or invalid",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return session_data


async def require_admin(user: dict = Depends(get_current_user)) -> dict:
    """Dependency validator restricting endpoint strictly to ADMINISTRATOR role."""
    if user["role"] != "ADMIN":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Action restricted to Administrator role"
        )
    return user


# ==========================================
# STARTUP EVENT
# ==========================================
@app.on_event("startup")
def startup():
    init_db()
    migrate_legacy_csv(LEGACY_EVIDENCE_FILE)


# ==========================================
# HEALTH & UTILITIES
# ==========================================
@app.get("/health")
def health():
    return {
        "status": "ok",
        "ai_ready": detector.ai_engine.ready,
        "active_brains": list(detector.ai_engine.models.keys()),
        "signature_count": len(detector.signature_engine.signatures),
    }


# ==========================================
# AUTHENTICATION ROUTES
# ==========================================
@app.post("/api/auth/login")
def login(payload: LoginRequest):
    """Authenticates credentials and issues a secure session token."""
    # Rate limiting: block after 5 failed attempts in 5 minutes
    key = payload.username.lower().strip()
    now = time.time()
    _login_attempts[key] = [t for t in _login_attempts[key] if now - t < LOGIN_RATE_WINDOW]
    if len(_login_attempts[key]) >= LOGIN_RATE_LIMIT:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Try again in 5 minutes."
        )

    user = authenticate_user(payload.username, payload.password)
    if not user:
        _login_attempts[key].append(now)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )
    
    # Clear failed attempts on successful login
    _login_attempts.pop(key, None)
    token = create_session(user["username"])
    return {
        "token": token,
        "username": user["username"],
        "role": user["role"]
    }


@app.post("/api/auth/logout")
def logout(authorization: Optional[str] = Header(None)):
    """Revokes / destroys the active session token."""
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ")[1].strip()
        delete_session(token)
    return {"message": "Logged out successfully"}


@app.get("/api/auth/me")
def get_profile(user: dict = Depends(get_current_user)):
    """Retrieves session details of the currently authenticated user."""
    return user


# ==========================================
# SECURITY ALERTS & LOGS INGESTION
# ==========================================
@app.post("/api/logs")
def ingest_log(payload: LogIngestRequest, user: dict = Depends(require_admin)):
    """Ingests a new log line. Restricted to ADMIN users."""
    alerts = detector.process_log_line(payload.line, persist=True)
    return {"source": payload.source, "alert_count": len(alerts), "alerts": alerts}


@app.post("/api/logs/batch")
def ingest_logs(payload: BatchLogIngestRequest, user: dict = Depends(require_admin)):
    """Ingests a batch of log lines. Restricted to ADMIN users."""
    results = []
    total_alerts = 0
    for line in payload.lines:
        alerts = detector.process_log_line(line, persist=True)
        total_alerts += len(alerts)
        results.append({"line": line, "alert_count": len(alerts), "alerts": alerts})
    return {
        "source": payload.source,
        "line_count": len(payload.lines),
        "alert_count": total_alerts,
        "results": results,
    }


@app.get("/api/alerts")
def get_alerts(
    limit: int = Query(100, ge=1, le=1000),
    newest_first: bool = True,
    threat_type: Optional[str] = None,
    source_ip: Optional[str] = None,
    user: dict = Depends(get_current_user),
):
    """Retrieves threat alerts. Open to authenticated ANALYST or ADMIN users."""
    alerts = list_alerts(limit=limit, newest_first=newest_first)
    if threat_type:
        alerts = [alert for alert in alerts if alert["Type"] == threat_type]
    if source_ip:
        alerts = [alert for alert in alerts if alert["Source IP"] == source_ip]
        
    # Unpack JSON string stored in alerts db schema
    for alert in alerts:
        if alert.get("ai_report"):
            try:
                alert["ai_report"] = json.loads(alert["ai_report"])
            except Exception:
                pass
    return {"count": len(alerts), "alerts": alerts}


# ==========================================
# ACTIVE IPS & FIREWALL ENDPOINTS
# ==========================================
@app.get("/api/blocked-ips")
def get_blocked(user: dict = Depends(get_current_user)):
    """Lists all blacklisted attacker IPs. Open to authenticated users."""
    return list_blocked_ips()


@app.post("/api/ips/unblock")
def post_unblock(payload: UnblockIPRequest, user: dict = Depends(require_admin)):
    """Unblocks a blacklisted IP address. Restricted to ADMIN users."""
    unblock_ip(payload.ip)
    return {"message": f"IP {payload.ip} unblocked successfully", "ip": payload.ip}


@app.get("/api/threat-intel")
def get_reputations(user: dict = Depends(get_current_user)):
    """Retrieves all cumulative IP threat reputation scores."""
    return list_all_reputations()


@app.post("/api/ips/deploy-firewall")
def deploy_firewall(payload: DeployFirewallRequest, user: dict = Depends(require_admin)):
    """Executes a host OS-level firewall blocking rule. Restricted to ADMIN users."""
    # SECURITY FIX: Validate IP format strictly to prevent command injection
    try:
        ip = _validate_ipv4(payload.ip)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid IPv4 address format: '{payload.ip}'"
        )

    system_os = platform.system().upper()
    
    # SECURITY FIX: Use argument lists instead of shell=True to prevent injection
    if "WINDOWS" in system_os:
        cmd_args = [
            "powershell", "-NoProfile", "-Command",
            f"New-NetFirewallRule -DisplayName 'Block Cerberus Attacker {ip}' "
            f"-Direction Inbound -Action Block -RemoteAddress {ip}"
        ]
        cmd_display = f"New-NetFirewallRule -DisplayName 'Block Cerberus Attacker {ip}' -Direction Inbound -Action Block -RemoteAddress {ip}"
    else:
        cmd_args = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
        cmd_display = f"sudo iptables -A INPUT -s {ip} -j DROP"
        
    try:
        # SECURITY FIX: shell=False with argument list — no injection possible
        result = subprocess.run(cmd_args, capture_output=True, text=True, timeout=15.0)
        if result.returncode == 0:
            return {"success": True, "message": f"Firewall rule deployed to block {ip}", "command": cmd_display}
        else:
            stderr_msg = result.stderr.strip()
            if "Access is denied" in stderr_msg or "PermissionDenied" in stderr_msg or "System Error 5" in stderr_msg:
                stderr_msg += " | TIP: Run your backend FastAPI server in an elevated (Administrator) command prompt to allow Windows Defender Firewall modifications."
            return {"success": False, "message": f"Deployment failed: {stderr_msg}", "command": cmd_display}
    except subprocess.TimeoutExpired:
        return {"success": False, "message": "Deployment failed: Command timed out. PowerShell took too long to load security modules.", "command": cmd_display}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Firewall execution failed: {str(e)}")


# ==========================================
# MODEL ANALYTICS & STATISTICAL METRICS
# ==========================================
@app.get("/api/model-analytics")
def get_model_analytics(user: dict = Depends(get_current_user)):
    """Compiles training statistics and feature importances for all models."""
    analytics = {}
    for model_type, config in MODEL_CONFIGS.items():
        metrics_file = os.path.join(MODELS_DIR, f"{model_type}_metrics.json")
        model_file = os.path.join(MODELS_DIR, f"{model_type}_classifier.pkl")
        
        # Base placeholders in case model hasn't been recompiled yet
        model_data = {
            "model_type": model_type,
            "trained": False,
            "trained_at": None,
            "accuracy": 0.0,
            "precision": 0.0,
            "recall": 0.0,
            "f1_score": 0.0,
            "confusion_matrix": {"tn": 0, "fp": 0, "fn": 0, "tp": 0},
            "feature_importances": {}
        }
        
        if os.path.exists(model_file):
            model_data["trained"] = True
            model_data["trained_at"] = datetime.fromtimestamp(os.path.getmtime(model_file)).strftime("%Y-%m-%d %H:%M:%S")
            
        if os.path.exists(metrics_file):
            try:
                with open(metrics_file, "r") as f:
                    metrics_payload = json.load(f)
                model_data.update(metrics_payload)
            except Exception:
                pass
                
        analytics[model_type] = model_data
        
    return {
        "brains_loaded": len(detector.ai_engine.models),
        "analytics": analytics
    }


# ==========================================
# MULTI-AGENT DEVSECOPS PIPELINE
# ==========================================
@app.post("/api/triage/multi-agent")
def multi_agent_triage(
    payload: MultiAgentTriageRequest,
    user: dict = Depends(get_current_user),
):
    """
    Runs the full Cerberus 4-agent DevSecOps pipeline:
    Triage (DeepSeek) -> Research (MITRE RAG + DeepSeek) ->
    Remediation (Nemotron) -> Guardrail (DeepSeek) -> Verified Output.
    """
    try:
        result = _orchestrator.run(
            threat_type=payload.threat_type,
            source_ip=payload.source_ip,
            details=payload.details,
            log_line=payload.log_line,
        )
        return result
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Multi-agent pipeline failed: {str(exc)}"
        )


@app.get("/api/threat-intel/mitre")
def mitre_search(
    q: str = Query(..., min_length=2, description="Search query for MITRE ATT&CK techniques"),
    top_k: int = Query(5, ge=1, le=20),
    user: dict = Depends(get_current_user),
):
    """
    Performs a direct semantic search over the MITRE ATT&CK Enterprise
    knowledge base (709 techniques) and returns the top-K matches.
    """
    rag = get_rag_engine()
    if not rag.ready:
        raise HTTPException(status_code=503, detail="MITRE RAG engine not ready. Check data/mitre_attack.json.")
    results = rag.search(q, top_k=top_k)
    return {
        "query":           q,
        "total_techniques": rag.technique_count,
        "results":         results,
    }


# ==========================================
# WEB SOCKETS
# ==========================================
@app.websocket("/api/live-alerts")
async def live_alerts(websocket: WebSocket, token: Optional[str] = Query(None)):
    """WebSocket stream for real-time alerts. Authenticates via token query parameter."""
    await websocket.accept()
    
    if not token:
        await websocket.send_json({"error": "Unauthorized: Missing token query parameter"})
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
        
    session_data = get_session(token)
    if not session_data:
        await websocket.send_json({"error": "Unauthorized: Invalid or expired session token"})
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
        
    try:
        while True:
            line = await websocket.receive_text()
            if session_data["role"] == "ADMIN":
                alerts = detector.process_log_line(line, persist=True)
                for alert in alerts:
                    # Unpack JSON strings if present in detail
                    if alert.get("ai_report") and isinstance(alert["ai_report"], str):
                        try: alert["ai_report"] = json.loads(alert["ai_report"])
                        except Exception: pass
                await websocket.send_json({"alert_count": len(alerts), "alerts": alerts})
            else:
                await websocket.send_json({"error": "Permission denied: Log ingestion restricted to Admin"})
    except WebSocketDisconnect:
        return
