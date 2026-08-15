param(
  [string]$BaseUrl = "http://localhost:3000",
  [string]$JwtToken = $env:ZENTRIS_SMOKE_JWT,
  [string]$SessionId = "smoke-test"
)

$ErrorActionPreference = "Stop"

function Join-Url {
  param(
    [Parameter(Mandatory = $true)][string]$Root,
    [Parameter(Mandatory = $true)][string]$Path
  )

  return "$($Root.TrimEnd('/'))/$($Path.TrimStart('/'))"
}

function Invoke-Json {
  param(
    [Parameter(Mandatory = $true)][string]$Method,
    [Parameter(Mandatory = $true)][string]$Url,
    [hashtable]$Headers = @{},
    [object]$Body = $null
  )

  $params = @{
    Method = $Method
    Uri = $Url
    Headers = $Headers
    TimeoutSec = 15
  }

  if ($null -ne $Body) {
    $params.ContentType = "application/json"
    $params.Body = ($Body | ConvertTo-Json -Depth 10)
  }

  Invoke-RestMethod @params
}

Write-Host "Checking Zentris smoke target: $BaseUrl"

$liveness = Invoke-Json -Method "GET" -Url (Join-Url $BaseUrl "/health/liveness")
if ($liveness.status -ne "ok") {
  throw "Liveness check failed"
}
Write-Host "Liveness: ok"

$readiness = Invoke-Json -Method "GET" -Url (Join-Url $BaseUrl "/health/readiness")
if ($readiness.status -ne "ready") {
  throw "Readiness check failed"
}
Write-Host "Readiness: ready"

if ([string]::IsNullOrWhiteSpace($JwtToken)) {
  Write-Host "Skipping authenticated chat smoke check because JwtToken/ZENTRIS_SMOKE_JWT was not provided."
  exit 0
}

$headers = @{ Authorization = "Bearer $JwtToken" }
$chat = Invoke-Json -Method "POST" -Url (Join-Url $BaseUrl "/v1/chat") -Headers $headers -Body @{
  sessionId = $SessionId
  message = "Return a short health confirmation."
}

if ([string]::IsNullOrWhiteSpace($chat.response)) {
  throw "Chat smoke check did not return a response"
}

Write-Host "Authenticated chat: ok"
Write-Host "Smoke test completed successfully."
