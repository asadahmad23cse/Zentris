# Free Local Ollama Setup

This setup makes Zentris usable without paid OpenAI, Anthropic, or hosted model keys.

## Model

Use the small local model:

```powershell
ollama pull qwen2.5:1.5b
```

`llama3:latest` can work on larger machines, but it may fail on low-memory Windows systems. `qwen2.5:1.5b` is the default because it is small enough for local development.

## Register With LiteLLM

Run:

```powershell
.\scripts\setup_ollama_litellm.ps1
```

The script:

- Verifies Ollama is running on `127.0.0.1:11434`
- Pulls `qwen2.5:1.5b` if it is missing
- Registers `zentris-local-qwen` in LiteLLM
- Removes stale local demo models
- Verifies `/v1/chat/completions`
- Verifies `/v1/responses`

## UI Usage

Open:

```text
http://localhost:4000/ui/
```

In Playground:

- Select model `zentris-local-qwen`
- Use normal chat mode
- Leave MCP Servers empty unless an MCP server has been configured

## API Usage

```powershell
$body = @{
  model = "zentris-local-qwen"
  messages = @(@{ role = "user"; content = "Say hello from local Ollama" })
} | ConvertTo-Json -Depth 10

Invoke-RestMethod `
  -Method Post `
  -Uri http://127.0.0.1:4000/v1/chat/completions `
  -Headers @{ Authorization = "Bearer sk-1234"; "Content-Type" = "application/json" } `
  -Body $body
```
