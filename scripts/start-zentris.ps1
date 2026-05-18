$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$Root = Split-Path -Parent $PSScriptRoot
$Logs = Join-Path $Root "logs"
$Dashboard = Join-Path $Root "ui\litellm-dashboard"
$DashboardLogs = Join-Path $Dashboard "logs"
$PgBin = "C:\Program Files\PostgreSQL\18\bin"
$PgData = Join-Path $Root ".local\postgres-data"
$PgLog = Join-Path $Logs "local-postgres.log"
$ProxyDatabaseName = "zentris_dev"
$DatabaseUrl = "postgresql://llmproxy:dbpassword9090@127.0.0.1:55432/$ProxyDatabaseName"
$JwtSecret = "local-dev-only-jwt-secret-change-before-production-0123456789"
$ConfirmationSecret = "local-dev-only-confirmation-secret-change-before-production-0123456789"

New-Item -ItemType Directory -Force -Path $Logs | Out-Null
New-Item -ItemType Directory -Force -Path $DashboardLogs | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $Root ".local") | Out-Null

function Test-Port([int]$Port) {
  return [bool](Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.LocalPort -eq $Port } | Select-Object -First 1)
}

function Stop-PortProcess([int]$Port) {
  Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
    Where-Object { $_.LocalPort -eq $Port } |
    ForEach-Object {
      $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
      if ($process -and $process.ProcessName -in @("node", "python", "pythonw", "litellm")) {
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
      }
    }
}

function Invoke-NativeCommand([string]$FilePath, [string[]]$ArgumentList) {
  & $FilePath @ArgumentList
  if ($LASTEXITCODE -ne 0) {
    throw "$FilePath failed with exit code $LASTEXITCODE."
  }
}

function Start-ProcessLogged([string]$FilePath, [string[]]$ArgumentList, [string]$WorkingDirectory, [string]$OutLog, [string]$ErrLog) {
  return Start-Process -FilePath $FilePath `
    -ArgumentList $ArgumentList `
    -WorkingDirectory $WorkingDirectory `
    -RedirectStandardOutput $OutLog `
    -RedirectStandardError $ErrLog `
    -PassThru `
    -WindowStyle Hidden
}

function Test-ProcessRunning([System.Diagnostics.Process]$Process, [string]$Name, [string]$ErrLog) {
  if ($null -eq $Process) {
    Write-Warning "$Name did not start. Check $ErrLog"
    return $false
  }

  $Process.Refresh()
  if ($Process.HasExited) {
    Write-Warning "$Name exited with code $($Process.ExitCode). Check $ErrLog"
    return $false
  }

  return $true
}

function Open-DashboardUrl([string]$Url) {
  try {
    Start-Process -FilePath "explorer.exe" -ArgumentList $Url -ErrorAction Stop
  } catch {
    Write-Warning "Could not open dashboard automatically: $($_.Exception.Message)"
    Write-Host "Open this URL manually: $Url"
  }
}

function Get-DashboardLaunchUrl() {
  $loginUrl = "http://localhost:4000/v2/login"
  $fallbackUrl = "http://localhost:3001/login"
  try {
    $body = @{ username = "admin"; password = "sk-1234" } | ConvertTo-Json -Compress
    $response = Invoke-WebRequest -UseBasicParsing -Uri $loginUrl -Method Post -ContentType "application/json" -Body $body -TimeoutSec 10
    $setCookie = $response.Headers["Set-Cookie"]
    if ($setCookie -and $setCookie -match "token=([^;]+)") {
      $encodedToken = [System.Uri]::EscapeDataString($Matches[1])
      return "http://localhost:3001/login?token=$encodedToken"
    }
  } catch {
    Write-Warning "Could not create local dashboard login session automatically: $($_.Exception.Message)"
  }

  return $fallbackUrl
}

Write-Host "Starting Zentris local services..."

if (-not (Test-Path (Join-Path $PgBin "pg_ctl.exe"))) {
  throw "PostgreSQL tools not found at $PgBin. Install PostgreSQL 18 or update PgBin in scripts\start-zentris.ps1."
}

if (-not (Test-Path (Join-Path $PgData "PG_VERSION"))) {
  Write-Host "Initializing project-local Postgres data directory..."
  Invoke-NativeCommand (Join-Path $PgBin "initdb.exe") @("-D", $PgData, "-U", "postgres", "-A", "trust")
}

if (-not (Test-Port 55432)) {
  Write-Host "Starting project-local Postgres on port 55432..."
  
  # Remove stale postmaster.pid if postgres is not actually running
  $pidFile = Join-Path $PgData "postmaster.pid"
  if (Test-Path $pidFile) {
    Write-Host "Removing stale postmaster.pid..."
    Remove-Item $pidFile -Force -ErrorAction SilentlyContinue
  }
  
  # Port 55432 is set in postgresql.conf. Avoid piping pg_ctl output on Windows because
  # the launcher can appear stuck after pg_ctl prints "server started".
  Invoke-NativeCommand (Join-Path $PgBin "pg_ctl.exe") @("-D", $PgData, "-l", $PgLog, "-w", "-t", "30", "start")
  
  # Wait for Postgres to be ready (up to 30 seconds)
  $pgReady = $false
  for ($i = 0; $i -lt 30; $i++) {
    Start-Sleep -Seconds 1
    & (Join-Path $PgBin "pg_isready.exe") -h 127.0.0.1 -p 55432 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
      $pgReady = $true
      Write-Host "Postgres is ready after $($i+1) seconds."
      break
    }
    Write-Host "Waiting for Postgres... ($($i+1)s)"
  }
  if (-not $pgReady) {
    Write-Warning "Postgres did not become ready in 30 seconds. Proceeding anyway..."
  }
} else {
  Write-Host "Postgres already running on port 55432."
}

Write-Host "Ensuring proxy database and role exist..."
& (Join-Path $PgBin "psql.exe") -h 127.0.0.1 -p 55432 -U postgres -d postgres -v ON_ERROR_STOP=1 -c "DO `$`$ BEGIN IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'llmproxy') THEN CREATE ROLE llmproxy LOGIN PASSWORD 'dbpassword9090' SUPERUSER; END IF; END `$`$;"
$dbCheckOutput = & (Join-Path $PgBin "psql.exe") -h 127.0.0.1 -p 55432 -U postgres -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname = '$ProxyDatabaseName'"
$dbExists = if ($dbCheckOutput) { $dbCheckOutput.Trim() } else { "" }
if ($dbExists -ne "1") {
  & (Join-Path $PgBin "createdb.exe") -h 127.0.0.1 -p 55432 -U postgres -O llmproxy $ProxyDatabaseName
}

if (-not (Test-Port 6379)) {
  $redis = Get-Command redis-server -ErrorAction SilentlyContinue
  if ($redis) {
    Write-Host "Starting Redis on port 6379..."
    Start-Process -FilePath $redis.Source -ArgumentList @("--port", "6379") -WindowStyle Hidden
    Start-Sleep -Seconds 3
  } else {
    Write-Warning "Redis is not listening on 6379 and redis-server was not found in PATH. Replay/rate-limit features may fail."
  }
}

Write-Host "Syncing proxy database schema..."
$env:DATABASE_URL = $DatabaseUrl
prisma db push --schema (Join-Path $Root "schema.prisma")

Write-Host "Restarting app processes..."
Stop-PortProcess 3000
Stop-PortProcess 3001
Stop-PortProcess 4000
Start-Sleep -Seconds 2

$env:PYTHONIOENCODING = "utf-8"
$env:PYTHONUTF8 = "1"
$env:JWT_SECRET = $JwtSecret
$env:CONFIRMATION_TOKEN_SECRET = $ConfirmationSecret
$env:REDIS_HOST = "localhost"
$env:REDIS_PORT = "6379"
$env:REDIS_PASSWORD = ""
$env:DATABASE_URL = $DatabaseUrl
$ProxyProcess = Start-Process -FilePath "C:\Users\ASAD AHMAD\miniconda3\pythonw.exe" `
  -ArgumentList @("-m", "litellm.proxy.proxy_cli", "--config", "proxy_server_config.yaml", "--port", "4000", "--host", "0.0.0.0", "--use_prisma_db_push") `
  -WorkingDirectory $Root `
  -RedirectStandardOutput (Join-Path $Logs "litellm-proxy.out.log") `
  -RedirectStandardError (Join-Path $Logs "litellm-proxy.err.log") `
  -PassThru `
  -WindowStyle Hidden

$env:REDIS_URL = "redis://localhost:6379"
$env:LITELLM_BASE_URL = "http://localhost:4000"
$env:LITELLM_API_KEY = "sk-1234"
$env:MAX_SESSION_MESSAGES = "20"
$env:CIRCUIT_BREAKER_ENABLED = "true"
$env:LOG_LEVEL = "info"
$env:PORT = "3000"
$env:JWT_SECRET = $JwtSecret
$env:CONFIRMATION_TOKEN_SECRET = $ConfirmationSecret
$BackendProcess = Start-ProcessLogged "npm.cmd" @("run", "dev") $Root (Join-Path $Logs "backend-dev.out.log") (Join-Path $Logs "backend-dev.err.log")

$DashboardProcess = Start-ProcessLogged "npm.cmd" @("run", "dev", "--", "-p", "3001") $Dashboard (Join-Path $DashboardLogs "dashboard-dev.out.log") (Join-Path $DashboardLogs "dashboard-dev.err.log")

Write-Host "Waiting for services to become ready..."

# Wait for proxy (port 4000) - up to 90 seconds
Write-Host "  Waiting for LiteLLM proxy on port 4000..."
$proxyReady = $false
for ($i = 0; $i -lt 90; $i++) {
  Start-Sleep -Seconds 1
  if (-not (Test-ProcessRunning $ProxyProcess "LiteLLM proxy" (Join-Path $Logs "litellm-proxy.err.log"))) { break }
  if (Test-Port 4000) {
    # Port is open, now check health endpoint
    try {
      $r = Invoke-WebRequest -UseBasicParsing "http://localhost:4000/health/liveliness" -TimeoutSec 3 -ErrorAction Stop
      if ($r.StatusCode -eq 200) {
        $proxyReady = $true
        Write-Host "  Proxy ready after $($i+1) seconds."
        break
      }
    } catch { }
  }
  if ($i % 10 -eq 9) { Write-Host "  Still waiting for proxy... ($($i+1)s)" }
}
if (-not $proxyReady) {
  Write-Warning "LiteLLM proxy did not become ready. Dashboard may redirect to login. Check logs\litellm-proxy.err.log"
}

# Wait for backend (port 3000) - up to 30 seconds
Write-Host "  Waiting for backend on port 3000..."
for ($i = 0; $i -lt 30; $i++) {
  Start-Sleep -Seconds 1
  if (-not (Test-ProcessRunning $BackendProcess "Zentris backend" (Join-Path $Logs "backend-dev.err.log"))) { break }
  try {
    $r = Invoke-WebRequest -UseBasicParsing "http://localhost:3000/health" -TimeoutSec 3 -ErrorAction Stop
    if ($r.StatusCode -eq 200) { Write-Host "  Backend ready after $($i+1) seconds."; break }
  } catch { }
}

# Wait for dashboard (port 3001) - up to 60 seconds
Write-Host "  Waiting for dashboard on port 3001..."
for ($i = 0; $i -lt 60; $i++) {
  Start-Sleep -Seconds 1
  if (-not (Test-ProcessRunning $DashboardProcess "Zentris dashboard" (Join-Path $DashboardLogs "dashboard-dev.err.log"))) { break }
  try {
    $r = Invoke-WebRequest -UseBasicParsing "http://localhost:3001" -TimeoutSec 3 -ErrorAction Stop
    if ($r.StatusCode -eq 200) { Write-Host "  Dashboard ready after $($i+1) seconds."; break }
  } catch { }
}

$checks = @(
  @{ Name = "Zentris backend"; Url = "http://localhost:3000/health" },
  @{ Name = "Zentris dashboard"; Url = "http://localhost:3001" },
  @{ Name = "Zentris proxy"; Url = "http://localhost:4000/health/liveliness" }
)

foreach ($check in $checks) {
  try {
    $response = Invoke-WebRequest -UseBasicParsing $check.Url -TimeoutSec 15
    Write-Host "$($check.Name): $($response.StatusCode)"
  } catch {
    Write-Warning "$($check.Name) did not respond: $($_.Exception.Message)"
  }
}

$DashboardUrl = Get-DashboardLaunchUrl
Open-DashboardUrl $DashboardUrl
Write-Host ""
Write-Host "Zentris is ready:"
Write-Host "  Dashboard: http://localhost:3001"
Write-Host "  Backend:   http://localhost:3000/health"
Write-Host "  Proxy:     http://localhost:4000"
Write-Host ""
Write-Host "Proxy admin fallback credentials: username admin, password sk-1234"
