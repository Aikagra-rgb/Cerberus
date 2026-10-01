import json
import os
import platform
import re
import subprocess
import time
from collections import defaultdict
from datetime import datetime

from fastapi import (
    Depends,
    FastAPI,
    Header,
    HTTPException,
    Query,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest
from pydantic import BaseModel, Field
from src.agents.orchestrator import MultiAgentOrchestrator
from src.agents.rag_engine import get_rag_engine
from src.alert_store import (
    authenticate_user,
    create_session,
    delete_session,
    get_session,
    init_db,
    list_alerts,
    list_all_reputations,
    list_blocked_ips,
    migrate_legacy_csv,
    unblock_ip,
)
from src.config import DATA_DIR, MODEL_CONFIGS, MODELS_DIR
from src.detection_service import DetectionService
from src.logging_config import configure_logging, get_logger
from starlette.responses import Response

LEGACY_EVIDENCE_FILE = os.path.join(DATA_DIR, "hids_alerts.csv")

# Configure structured logging
configure_logging(level=os.getenv("LOG_LEVEL", "INFO"))
log = get_logger(__name__)

# Prometheus metrics
REQUEST_COUNT = Counter(
    "cerberus_http_requests_total", "Total HTTP requests", ["method", "endpoint", "status"]
)
REQUEST_LATENCY = Histogram(
    "cerberus_http_request_duration_seconds",
    "HTTP request latency in seconds",
    ["method", "endpoint"],
)
ACTIVE_ALERTS = Gauge("cerberus_active_alerts", "Current number of active alerts")
BLOCKED_IPS = Gauge("cerberus_blocked_ips", "Current number of blocked IPs")
AI_BRAINS_LOADED = Gauge("cerberus_ai_brains_loaded", "Number of AI models loaded")
PIPELINE_LATENCY = Histogram(
    "cerberus_pipeline_duration_seconds", "Multi-agent pipeline latency in seconds", ["agent"]
)
PIPELINE_STATUS = Counter(
    "cerberus_pipeline_status_total", "Multi-agent pipeline completion status", ["agent", "status"]
)

app = FastAPI(
    title="Cerberus API",
    version="0.4.0",
    description="Backend API for Cerberus log ingestion, active IPS gatekeeping, and model analytics.",
)

# CORS: read from env var for cloud + keep localhost for dev
_raw_origins = os.getenv("ALLOWED_ORIGINS", "")
_cloud_origins = [o.strip() for o in _raw_origins.split(",") if o.strip()]
_default_origins = [
    "http://127.0.0.1:5173",
    "http://localhost:5173",
    "http://127.0.0.1:3000",
    "http://localhost:3000",
]
_allowed_origins = list(set(_default_origins + _cloud_origins))

# Only allow specific Vercel domains from env, not all subdomains
_vercel_domains = os.getenv("VERCEL_DOMAINS", "")
_vercel_origins = [o.strip() for o in _vercel_domains.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins + _vercel_origins,
    # allow_origin_regex removed - use VERCEL_DOMAINS env var for specific domains
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Prometheus metrics middleware
@app.middleware("http")
async def metrics_middleware(request, call_next):
    import time

    start_time = time.time()
    response = await call_next(request)
    duration = time.time() - start_time

    # Record metrics
    REQUEST_COUNT.labels(
        method=request.method, endpoint=request.url.path, status=response.status_code
    ).inc()
    REQUEST_LATENCY.labels(method=request.method, endpoint=request.url.path).observe(duration)

    return response


@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint."""
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


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
    lines: list[str] = Field(..., min_length=1)
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
LOGIN_RATE_LIMIT = 5  # max attempts
LOGIN_RATE_WINDOW = 300.0  # per 5-minute window


class UnblockIPRequest(BaseModel):
    ip: str = Field(..., min_length=7, max_length=15)


class DeployFirewallRequest(BaseModel):
    ip: str = Field(..., min_length=7, max_length=15)


class MultiAgentTriageRequest(BaseModel):
    threat_type: str = Field(..., min_length=1)
    source_ip: str = Field(..., min_length=7, max_length=15)
    details: str = Field(default="")
    log_line: str = Field(default="")


# ==========================================
# AUTHENTICATION DEPENDENCIES (MIDDLEWARE)
# ==========================================
async def get_current_user(authorization: str | None = Header(None)) -> dict:
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
            status_code=status.HTTP_403_FORBIDDEN, detail="Action restricted to Administrator role"
        )
    return user


# ==========================================
# STARTUP / SHUTDOWN EVENTS
# ==========================================
@app.on_event("startup")
async def startup():
    log.info("cerberus_startup", version="0.4.0")
    init_db()
    migrate_legacy_csv(LEGACY_EVIDENCE_FILE)
    # Update gauges on startup
    AI_BRAINS_LOADED.set(len(detector.ai_engine.models))
    blocked_list = list_blocked_ips()
    BLOCKED_IPS.set(len(blocked_list))
    log.info(
        "cerberus_ready", ai_brains=len(detector.ai_engine.models), blocked_ips=len(blocked_list)
    )


@app.on_event("shutdown")
async def shutdown():
    log.info("cerberus_shutdown")


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


@app.get("/ready")
async def ready():
    """Kubernetes readiness probe - checks if service can handle requests."""
    # Check DB connectivity
    try:
        list_alerts(limit=1)
        db_ok = True
    except Exception:
        db_ok = False

    # Check AI engine
    ai_ok = detector.ai_engine.ready

    if db_ok and ai_ok:
        return {"status": "ready", "database": "ok", "ai": "ok"}
    else:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "status": "not_ready",
                "database": "ok" if db_ok else "failed",
                "ai": "ok" if ai_ok else "failed",
            },
        )


@app.get("/live")
async def live():
    """Kubernetes liveness probe - checks if process is alive."""
    return {"status": "alive"}


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
        log.warning("login_rate_limited", username=key)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Try again in 5 minutes.",
        )

    user = authenticate_user(payload.username, payload.password)
    if not user:
        _login_attempts[key].append(now)
        log.warning("login_failed", username=key)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password"
        )

    # Clear failed attempts on successful login
    _login_attempts.pop(key, None)
    token = create_session(user["username"])
    log.info("login_success", username=user["username"], role=user["role"])
    return {"token": token, "username": user["username"], "role": user["role"]}


@app.post("/api/auth/logout")
def logout(authorization: str | None = Header(None)):
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
    log.info("log_ingest_single", source=payload.source, user=user["username"])
    alerts = detector.process_log_line(payload.line, persist=True)
    if alerts:
        ACTIVE_ALERTS.inc(len(alerts))
        log.warning("alerts_generated", count=len(alerts), types=[a["Type"] for a in alerts])
    return {"source": payload.source, "alert_count": len(alerts), "alerts": alerts}


@app.post("/api/logs/batch")
def ingest_logs(payload: BatchLogIngestRequest, user: dict = Depends(require_admin)):
    """Ingests a batch of log lines. Restricted to ADMIN users."""
    log.info(
        "log_ingest_batch",
        source=payload.source,
        line_count=len(payload.lines),
        user=user["username"],
    )
    results = []
    total_alerts = 0
    for line in payload.lines:
        alerts = detector.process_log_line(line, persist=True)
        total_alerts += len(alerts)
        results.append({"line": line, "alert_count": len(alerts), "alerts": alerts})
    if total_alerts > 0:
        ACTIVE_ALERTS.inc(total_alerts)
        log.warning("alerts_generated_batch", count=total_alerts)
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
    threat_type: str | None = None,
    source_ip: str | None = None,
    user: dict = Depends(get_current_user),
):
    """Retrieves threat alerts. Open to authenticated ANALYST or ADMIN users."""
    log.debug(
        "alerts_list",
        user=user["username"],
        limit=limit,
        threat_type=threat_type,
        source_ip=source_ip,
    )
    alerts = list_alerts(limit=limit, newest_first=newest_first)
    ACTIVE_ALERTS.set(len(alerts))
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
    blocked = list_blocked_ips()
    BLOCKED_IPS.set(len(blocked))
    return blocked


@app.post("/api/ips/unblock")
def post_unblock(payload: UnblockIPRequest, user: dict = Depends(require_admin)):
    """Unblocks a blacklisted IP address. Restricted to ADMIN users."""
    log.info("ip_unblock", ip=payload.ip, admin=user["username"])
    unblock_ip(payload.ip)
    blocked = list_blocked_ips()
    BLOCKED_IPS.set(len(blocked))
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
            detail=f"Invalid IPv4 address format: '{payload.ip}'",
        )

    system_os = platform.system().upper()

    # SECURITY FIX: Use argument lists instead of shell=True to prevent injection
    if "WINDOWS" in system_os:
        cmd_args = [
            "powershell",
            "-NoProfile",
            "-Command",
            f"New-NetFirewallRule -DisplayName 'Block Cerberus Attacker {ip}' "
            f"-Direction Inbound -Action Block -RemoteAddress {ip}",
        ]
        cmd_display = f"New-NetFirewallRule -DisplayName 'Block Cerberus Attacker {ip}' -Direction Inbound -Action Block -RemoteAddress {ip}"
    else:
        cmd_args = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
        cmd_display = f"sudo iptables -A INPUT -s {ip} -j DROP"

    try:
        # SECURITY FIX: shell=False with argument list — no injection possible
        result = subprocess.run(cmd_args, capture_output=True, text=True, timeout=15.0)
        if result.returncode == 0:
            return {
                "success": True,
                "message": f"Firewall rule deployed to block {ip}",
                "command": cmd_display,
            }
        else:
            stderr_msg = result.stderr.strip()
            if (
                "Access is denied" in stderr_msg
                or "PermissionDenied" in stderr_msg
                or "System Error 5" in stderr_msg
            ):
                stderr_msg += " | TIP: Run your backend FastAPI server in an elevated (Administrator) command prompt to allow Windows Defender Firewall modifications."
            return {
                "success": False,
                "message": f"Deployment failed: {stderr_msg}",
                "command": cmd_display,
            }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "message": "Deployment failed: Command timed out. PowerShell took too long to load security modules.",
            "command": cmd_display,
        }
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
            "feature_importances": {},
        }

        if os.path.exists(model_file):
            model_data["trained"] = True
            model_data["trained_at"] = datetime.fromtimestamp(
                os.path.getmtime(model_file)
            ).strftime("%Y-%m-%d %H:%M:%S")

        if os.path.exists(metrics_file):
            try:
                with open(metrics_file) as f:
                    metrics_payload = json.load(f)
                model_data.update(metrics_payload)
            except Exception:
                pass

        analytics[model_type] = model_data

    return {"brains_loaded": len(detector.ai_engine.models), "analytics": analytics}


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
    log.info(
        "pipeline_start",
        threat_type=payload.threat_type,
        source_ip=payload.source_ip,
        user=user["username"],
    )
    pipeline_start = time.time()
    try:
        result = _orchestrator.run(
            threat_type=payload.threat_type,
            source_ip=payload.source_ip,
            details=payload.details,
            log_line=payload.log_line,
        )
        total_ms = int((time.time() - pipeline_start) * 1000)

        # Record per-agent metrics
        for step in result.get("steps", []):
            agent_name = step.get("agent", "unknown").lower().replace(" ", "_")
            agent_status = step.get("status", "unknown")
            latency_ms = step.get("latency_ms", 0)
            PIPELINE_LATENCY.labels(agent=agent_name).observe(latency_ms / 1000.0)
            PIPELINE_STATUS.labels(agent=agent_name, status=agent_status).inc()

        log.info(
            "pipeline_complete",
            threat_type=payload.threat_type,
            source_ip=payload.source_ip,
            total_latency_ms=total_ms,
            approved=result.get("approved", False),
            verdict=result.get("final_verdict", "UNKNOWN"),
        )
        return result
    except Exception as exc:
        log.error("pipeline_failed", threat_type=payload.threat_type, error=str(exc))
        raise HTTPException(status_code=500, detail=f"Multi-agent pipeline failed: {str(exc)}")


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
        raise HTTPException(
            status_code=503, detail="MITRE RAG engine not ready. Check data/mitre_attack.json."
        )
    results = rag.search(q, top_k=top_k)
    return {
        "query": q,
        "total_techniques": rag.technique_count,
        "results": results,
    }


# ==========================================
# WEB SOCKETS
# ==========================================
@app.websocket("/api/live-alerts")
async def live_alerts(
    websocket: WebSocket,
    token: str | None = Query(None),
    authorization: str | None = Header(None),
):
    """
    WebSocket stream for real-time alerts.
    Authenticates via Authorization header (preferred) or token query parameter (legacy).
    """
    await websocket.accept()

    # Prefer Authorization header (Bearer token) over query param
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ")[1].strip()

    if not token:
        await websocket.send_json(
            {"error": "Unauthorized: Missing token (use Authorization header or token query param)"}
        )
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
                        try:
                            alert["ai_report"] = json.loads(alert["ai_report"])
                        except Exception:
                            pass
                await websocket.send_json({"alert_count": len(alerts), "alerts": alerts})
            else:
                await websocket.send_json(
                    {"error": "Permission denied: Log ingestion restricted to Admin"}
                )
    except WebSocketDisconnect:
        return
