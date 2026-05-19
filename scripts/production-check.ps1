param(
  [switch]$SkipDashboard,
  [switch]$SkipAudit
)

$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $RepoRoot

function Invoke-Step {
  param(
    [Parameter(Mandatory = $true)][string]$Name,
    [Parameter(Mandatory = $true)][scriptblock]$Command
  )

  Write-Host "==> $Name"
  & $Command
  if ($LASTEXITCODE -ne 0) {
    throw "Step failed: $Name"
  }
}

function Assert-FileExists {
  param([Parameter(Mandatory = $true)][string]$Path)

  if (-not (Test-Path -LiteralPath $Path)) {
    throw "Required file missing: $Path"
  }
}

Assert-FileExists "package.json"
Assert-FileExists "proxy_server_config.yaml"
Assert-FileExists ".env.production.example"
Assert-FileExists "docker-compose.yml"

Invoke-Step "Root TypeScript build" { npm run build }
Invoke-Step "Root test suite" { npm test }

Invoke-Step "Python security tests" {
  python -m pytest `
    tests/test_zentris_security_pipeline.py `
    tests/test_zentris_security_detectors.py `
    tests/test_zentris_security_audit_simulator.py `
    tests/test_prompt_injection_detection.py `
    tests/test_litellm_proxy_responses_config.py `
    -q
}

Invoke-Step "YAML config parse" {
  python -c "import yaml; yaml.safe_load(open('proxy_server_config.yaml', encoding='utf-8'))"
}

Invoke-Step "Compose config renders with injected secrets" {
  $env:POSTGRES_PASSWORD = "check-postgres-password"
  $env:LITELLM_MASTER_KEY = "check-master-key"
  $env:JWT_SECRET = "check-jwt-secret-12345678901234567890"
  $env:CONFIRMATION_TOKEN_SECRET = "check-confirmation-secret-12345678901234567890"
  $env:GRAFANA_ADMIN_PASSWORD = "check-grafana-password"
  docker compose -f docker-compose.yml config --quiet
}

Invoke-Step "Hardcoded secret scan for deployment files" {
  $matches = rg "sk-1234|dbpassword9090|change-me-in-production|GF_SECURITY_ADMIN_PASSWORD:\s*admin" `
    proxy_server_config.yaml docker-compose.yml scripts/start-zentris.ps1 .env.production.example
  if ($LASTEXITCODE -eq 0) {
    throw "Hardcoded secret pattern found"
  }
  if ($LASTEXITCODE -ne 1) {
    throw "Secret scan command failed"
  }
  $global:LASTEXITCODE = 0
}

if (-not $SkipDashboard) {
  Invoke-Step "Dashboard build" {
    Push-Location "ui/litellm-dashboard"
    try {
      npm run build
    } finally {
      Pop-Location
    }
  }
}

if (-not $SkipAudit) {
  Invoke-Step "Root npm audit high+" { npm run audit:prod }
}

Write-Host "Production check completed successfully."
