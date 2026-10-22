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
# TASK: FRONTEND (Starts the modern React + Vite analyst UI)
# ---------------------------------------------------------
if ($Task -eq "frontend" -or $Task -eq "dashboard") {
    Write-Host "`n[Workflow] Starting React + Vite SOC Console..." -ForegroundColor Cyan
    Push-Location frontend
    npm run dev
    Pop-Location
}

# ---------------------------------------------------------
# TASK: DEV / ALL (Single-terminal concurrent launcher)
# ---------------------------------------------------------
if ($Task -eq "dev") {
    & $Python run.py
}

if ($Task -eq "all") {
    & $Python run.py --with-engine
}

