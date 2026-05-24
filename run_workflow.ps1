param (
    [string]$Task = "all",
    [string]$Python = "python",
    [string]$Node = "node"
)

$ModelFiles = @{
    web = "data/cic_thursday.csv"
    auth = "data/cic_tuesday.csv"
    dos = "data/cic_wednesday.csv"
    recon = "data/cic_friday_portscan.csv"
    ddos = "data/cic_friday_ddos.csv"
    botnet = "data/cic_friday_morning.csv"
    infiltration = "data/cic_thursday_infiltration.csv"
}

function Train-Model {
    param (
        [string]$Name,
        [string]$Dataset
    )

    if (Test-Path $Dataset) {
        Write-Host "   [+] Training $($Name.ToUpper()) model..." -ForegroundColor Yellow
        & $Python trainer.py --type $Name
    } else {
        Write-Host "   [-] Skipping $($Name.ToUpper()) ($Dataset not found)" -ForegroundColor DarkGray
    }
}

# ---------------------------------------------------------
# TASK: TRAIN (Updates each configured AI brain)
# ---------------------------------------------------------
if ($Task -eq "train" -or $Task -eq "all") {
    Write-Host "`n[Workflow] Starting training sequence..." -ForegroundColor Cyan

    foreach ($Name in $ModelFiles.Keys) {
        Train-Model -Name $Name -Dataset $ModelFiles[$Name]
    }
}

# ---------------------------------------------------------
# TASK: TRAIN-ALL (One-command full retrain via trainer.py)
# ---------------------------------------------------------
if ($Task -eq "train-all") {
    Write-Host "`n[Workflow] Training all models via trainer.py --type all..." -ForegroundColor Cyan
    & $Python trainer.py --type all
}

# ---------------------------------------------------------
# TASK: TEST (Runs unit tests)
# ---------------------------------------------------------
if ($Task -eq "test" -or $Task -eq "all") {
    Write-Host "`n[Workflow] Running unit tests..." -ForegroundColor Cyan
    & $Python -m pytest tests/
}

# ---------------------------------------------------------
# TASK: ENGINE (Starts the backend engine)
# ---------------------------------------------------------
if ($Task -eq "engine") {
    Write-Host "`n[Workflow] Starting Sentinel Engine..." -ForegroundColor Cyan
    & $Python sentinel_engine.py
}

# ---------------------------------------------------------
# TASK: API (Starts the FastAPI backend)
# ---------------------------------------------------------
if ($Task -eq "api") {
    Write-Host "`n[Workflow] Starting FastAPI backend..." -ForegroundColor Cyan
    & $Python -m uvicorn api:app --reload
}

# ---------------------------------------------------------
# TASK: FRONTEND (Starts the modern analyst UI)
# ---------------------------------------------------------
if ($Task -eq "frontend") {
    Write-Host "`n[Workflow] Starting frontend..." -ForegroundColor Cyan
    & $Node frontend/server.mjs
}

# ---------------------------------------------------------
# TASK: DASHBOARD (Starts the UI)
# ---------------------------------------------------------
if ($Task -eq "dashboard") {
    Write-Host "`n[Workflow] Starting legacy Streamlit dashboard..." -ForegroundColor Cyan
    streamlit run dashboard.py
}

# ---------------------------------------------------------
# TASK: ALL (Demo mode)
# ---------------------------------------------------------
if ($Task -eq "all") {
    Write-Host "`n[Workflow] Launching full system..." -ForegroundColor Green

    Start-Process $Python -ArgumentList "sentinel_engine.py"
    Start-Process $Python -ArgumentList "-m uvicorn api:app --host 127.0.0.1 --port 8000"
    & $Node frontend/server.mjs
}
