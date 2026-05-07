# Zentris AI Security Runtime

Zentris now includes a local, dependency-free AI security runtime package under `zentris_security/`.
It is designed to sit in front of LiteLLM, Ollama, RAG retrieval, MCP servers, and agent tool calls.

## Runtime Stages

1. `input`: direct prompt injection detection through the existing Zentris hook adapter.
2. `retrieval`: indirect injection and RAG poisoning checks for external documents.
3. `tool_call`: runtime enforcement for shell, file, network, and environment access.
4. `mcp`: MCP server trust, auth, endpoint, and powerful-tool exposure checks.
5. `output`: response leakage and unsafe output scoring.

## CLI

Scan one request:

```powershell
python -m zentris_security.cli scan payload.json
```

Run the red-team simulator:

```powershell
python -m zentris_security.cli simulate zentris_security/data/red_team_attacks.json
```

## Free Local Stack

The current working stack uses only free local components:

- LiteLLM proxy and UI on `http://localhost:4000/ui/`
- Local Postgres on port `55432`
- Ollama on `http://127.0.0.1:11434`
- `qwen2.5:1.5b` exposed as `zentris-local-qwen`

## What Is Implemented

- Advanced direct prompt injection detection.
- Indirect injection checks for retrieved content.
- RAG poisoning risk scoring.
- Agent tool-call enforcement.
- MCP exposure checks.
- Output secret and system-prompt leakage scoring.
- Latency-aware multi-stage inspection.
- JSONL audit logging and replay.
- OWASP LLM Top 10 and MITRE ATLAS mappings.
- Red-team simulator and regression tests.

## What Still Needs Production Hardening

- Inline proxy enforcement hooks inside LiteLLM request middleware.
- Streaming token-by-token inspection inside live completions.
- Persistent SOC dashboard fed from audit events.
- Multi-model consensus validation using more than one local/remote model.
- Larger benchmark corpus with false-positive/false-negative tracking.
