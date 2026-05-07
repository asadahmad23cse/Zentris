$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$Root = Split-Path -Parent $PSScriptRoot
$Logs = Join-Path $Root "logs"
$PgBin = "C:\Program Files\PostgreSQL\18\bin"
$PgData = Join-Path $Root ".local\postgres-data"
$PgLog = Join-Path $Logs "local-postgres.log"
$ProxyDatabaseName = "zentris_dev"
$DatabaseUrl = "postgresql://llmproxy:dbpassword9090@localhost:55432/$ProxyDatabaseName"
$JwtSecret = "local-dev-only-jwt-secret-change-before-production-0123456789"
$ConfirmationSecret = "local-dev-only-confirmation-secret-change-before-production-0123456789"

New-Item -ItemType Directory -Force -Path $Logs | Out-Null
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

function Start-ProcessLogged([string]$FilePath, [string[]]$ArgumentList, [string]$WorkingDirectory, [string]$OutLog, [string]$ErrLog) {
  Start-Process -FilePath $FilePath `
    -ArgumentList $ArgumentList `
    -WorkingDirectory $WorkingDirectory `
    -RedirectStandardOutput $OutLog `
    -RedirectStandardError $ErrLog `
    -WindowStyle Hidden
}

Write-Host "Starting Zentris local services..."

if (-not (Test-Path (Join-Path $PgBin "pg_ctl.exe"))) {
  throw "PostgreSQL tools not found at $PgBin. Install PostgreSQL 18 or update PgBin in scripts\start-zentris.ps1."
}

if (-not (Test-Path (Join-Path $PgData "PG_VERSION"))) {
  Write-Host "Initializing project-local Postgres data directory..."
  & (Join-Path $PgBin "initdb.exe") -D $PgData -U postgres -A trust | Out-Host
}

if (-not (Test-Port 55432)) {
  Write-Host "Starting project-local Postgres on port 55432..."
  & (Join-Path $PgBin "pg_ctl.exe") -D $PgData -l $PgLog -o "-p 55432" start | Out-Host
  Start-Sleep -Seconds 5
}

Write-Host "Ensuring proxy database and role exist..."
& (Join-Path $PgBin "psql.exe") -h localhost -p 55432 -U postgres -d postgres -v ON_ERROR_STOP=1 -c "DO `$`$ BEGIN IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'llmproxy') THEN CREATE ROLE llmproxy LOGIN PASSWORD 'dbpassword9090' SUPERUSER; END IF; END `$`$;" | Out-Host
$dbCheckOutput = & (Join-Path $PgBin "psql.exe") -h localhost -p 55432 -U postgres -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname = '$ProxyDatabaseName'"
$dbExists = if ($dbCheckOutput) { $dbCheckOutput.Trim() } else { "" }
if ($dbExists -ne "1") {
  & (Join-Path $PgBin "createdb.exe") -h localhost -p 55432 -U postgres -O llmproxy $ProxyDatabaseName | Out-Host
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
prisma db push --schema (Join-Path $Root "schema.prisma") | Out-Host

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
Start-Process -FilePath "C:\Users\ASAD AHMAD\miniconda3\pythonw.exe" `
  -ArgumentList @("-m", "litellm.proxy.proxy_cli", "--config", "proxy_server_config.yaml", "--port", "4000", "--host", "0.0.0.0", "--use_prisma_db_push") `
  -WorkingDirectory $Root `
  -RedirectStandardOutput (Join-Path $Logs "litellm-proxy.out.log") `
  -RedirectStandardError (Join-Path $Logs "litellm-proxy.err.log") `
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
Start-ProcessLogged "npm.cmd" @("run", "dev") $Root (Join-Path $Logs "backend-dev.out.log") (Join-Path $Logs "backend-dev.err.log")

$Dashboard = Join-Path $Root "ui\litellm-dashboard"
Start-ProcessLogged "npm.cmd" @("run", "dev", "--", "-p", "3001") $Dashboard (Join-Path $Dashboard "logs\dashboard-dev.out.log") (Join-Path $Dashboard "logs\dashboard-dev.err.log")

Write-Host "Waiting for services..."
Start-Sleep -Seconds 45

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

Start-Process "http://localhost:3001"
Write-Host ""
Write-Host "Zentris is ready:"
Write-Host "  Dashboard: http://localhost:3001"
Write-Host "  Backend:   http://localhost:3000/health"
Write-Host "  Proxy:     http://localhost:4000"
Write-Host ""
Write-Host "Proxy admin fallback credentials: username admin, password sk-1234"
