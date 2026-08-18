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

## Canonical Local Stack

Docker Compose mirrors the production trust boundary with:

- Nginx as the only host-facing entry point.
- The TypeScript security gateway as the only public model API.
- LiteLLM, PostgreSQL, Redis, and the telemetry worker on the private Compose network.
- The Next.js dashboard served through Nginx and configured by environment variables.
- A mock provider only in the explicit E2E profile; production provider configuration remains separate.

## What Is Implemented

- Advanced direct prompt injection detection.
- Indirect injection checks for retrieved content.
- RAG poisoning risk scoring.
- Agent tool-call enforcement.
- MCP exposure checks.
- Output secret and system-prompt leakage scoring.
- Latency-aware multi-stage inspection.
- Metadata-only operational logging plus admin-protected, expiring database history and streamed JSONL training exports.
- OWASP LLM Top 10 and MITRE ATLAS mappings.
- Red-team simulator and regression tests.

## Production Architecture

The production request, trust-boundary, persistence, failure, and operations design is maintained in [`ARCHITECTURE.md`](../ARCHITECTURE.md). Prompt injection is deterministic sanitize-and-warn behavior; authentication, tool authorization, abuse controls, malformed requests, and upstream failures remain independently enforceable.
