param(
  [string]$LiteLlmBaseUrl = "http://127.0.0.1:4000",
  [string]$MasterKey = "sk-1234",
  [string]$OllamaModel = "qwen2.5:1.5b",
  [string]$PublicModelName = "zentris-local-qwen"
)

$ErrorActionPreference = "Stop"

function Write-Step($Message) {
  Write-Host "==> $Message"
}

function Invoke-JsonPost($Uri, $Body, $Headers = @{}) {
  $json = $Body | ConvertTo-Json -Depth 20
  Invoke-RestMethod -Method Post -Uri $Uri -Headers $Headers -ContentType "application/json" -Body $json
}

Write-Step "Checking Ollama CLI"
if (-not (Get-Command ollama -ErrorAction SilentlyContinue)) {
  throw "Ollama is not installed or not on PATH. Install Ollama first, then rerun this script."
}

Write-Step "Checking Ollama server"
Invoke-RestMethod -Uri "http://127.0.0.1:11434/api/tags" | Out-Null

Write-Step "Ensuring local model exists: $OllamaModel"
$modelList = ollama list | Out-String
if ($modelList -notmatch [regex]::Escape($OllamaModel)) {
  ollama pull $OllamaModel
}

Write-Step "Testing direct Ollama chat"
$ollamaBody = @{
  model = $OllamaModel
  stream = $false
  messages = @(
    @{ role = "user"; content = "Reply with exactly: Ollama is connected." }
  )
}
Invoke-JsonPost "http://127.0.0.1:11434/api/chat" $ollamaBody | Out-Null

$headers = @{
  Authorization = "Bearer $MasterKey"
}

Write-Step "Checking LiteLLM readiness"
Invoke-RestMethod -Uri "$LiteLlmBaseUrl/health/readiness" | Out-Null

Write-Step "Removing stale local demo models from LiteLLM"
$modelInfo = Invoke-RestMethod -Uri "$LiteLlmBaseUrl/model/info" -Headers $headers
$staleNames = @("zentris-security-demo", "zentris-local-llama3")
foreach ($model in $modelInfo.data) {
  if ($staleNames -contains $model.model_name) {
    $id = $model.model_info.id
    if ($id) {
      Invoke-JsonPost "$LiteLlmBaseUrl/model/delete" @{ id = $id } $headers | Out-Null
    }
  }
}

Write-Step "Registering LiteLLM Ollama model: $PublicModelName"
$modelInfo = Invoke-RestMethod -Uri "$LiteLlmBaseUrl/model/info" -Headers $headers
$existing = $modelInfo.data | Where-Object { $_.model_name -eq $PublicModelName } | Select-Object -First 1
if (-not $existing) {
  $newModelBody = @{
    model_name = $PublicModelName
    litellm_params = @{
      model = "ollama/$OllamaModel"
      api_base = "http://host.docker.internal:11434"
    }
    model_info = @{
      description = "Free local Ollama model for Zentris"
      mode = "chat"
      provider = "ollama"
      free = "true"
      recommended = "true"
    }
  }
  Invoke-JsonPost "$LiteLlmBaseUrl/model/new" $newModelBody $headers | Out-Null
}

Write-Step "Verifying LiteLLM chat completions"
$chatBody = @{
  model = $PublicModelName
  stream = $false
  messages = @(
    @{ role = "user"; content = "Say exactly: Zentris local model is functional." }
  )
}
$chatResponse = Invoke-JsonPost "$LiteLlmBaseUrl/v1/chat/completions" $chatBody $headers

Write-Step "Verifying LiteLLM responses endpoint"
$responsesBody = @{
  model = $PublicModelName
  stream = $false
  input = "Return JSON with path='responses' and working=true."
}
Invoke-JsonPost "$LiteLlmBaseUrl/v1/responses" $responsesBody $headers | Out-Null

Write-Step "Current LiteLLM models"
Invoke-RestMethod -Uri "$LiteLlmBaseUrl/v1/models" -Headers $headers | ConvertTo-Json -Depth 10

Write-Step "Setup complete"
Write-Host "Use model: $PublicModelName"
Write-Host "Chat verification reply: $($chatResponse.choices[0].message.content)"
