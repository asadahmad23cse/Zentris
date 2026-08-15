# Zentris Interview Demo

## Objective in one sentence

Zentris is an AI security gateway that inspects requests before they reach an LLM, then blocks unsafe traffic, masks sensitive data, requires human approval for high-impact actions, and records an explainable decision trail.

## Run it locally

From the repository root:

```powershell
python demo/zentris_demo.py --serve
```

Open `http://127.0.0.1:8080` and select **Run security scenarios**. No API key, database, Docker service, or internet connection is needed. On Windows, `Start-Interview-Demo.bat` starts the same walkthrough.

When the actual Zentris gateway is running in development mode, use `http://127.0.0.1:3000/demo` instead. That page calls the real TypeScript guard pipeline, RAG guard, tool-policy engine, and sensitive-data scanner; it does not use the standalone Python harness.

For a terminal-friendly proof of the decisions:

```powershell
python demo/zentris_demo.py --json
```

## Four-minute interview flow

1. **Problem (30 seconds):** “Teams use multiple LLMs, RAG sources, and agents. The security risk is that untrusted input can influence the model or trigger sensitive actions.”
2. **Solution (30 seconds):** “Zentris sits in front of the model gateway. It applies controls before the request is routed, so the security decision is provider-independent.”
3. **Live controls (2 minutes):** Run the scenarios and explain them in this order:
   - **Prompt injection:** dangerous instructions are blocked before the model is called.
   - **PII minimisation:** email and phone data is masked before forwarding.
   - **RAG poisoning:** untrusted retrieved content cannot replace system instructions or exfiltrate records.
   - **Agent tool action:** destructive production actions require a human approval step.
   - **Output leakage:** token-like strings are removed before the response is returned.
4. **Engineering decisions (45 seconds):** “I made the control path fail closed for high-confidence threats, kept the security layer provider-agnostic, and attached OWASP LLM / MITRE ATLAS mappings so SOC teams can understand each decision.”
5. **Close (15 seconds):** “The next production step is wiring the runtime directly into live proxy middleware and sending the audit events to a persistent dashboard.”

## Architecture to draw

```text
Client / RAG / Agent
        |
        v
Zentris: normalise -> inspect -> enforce -> audit
        |                  |          |
        |                  |          +-- allow / redact / approval / block
        v
LiteLLM gateway -> selected model provider
```

## Honest positioning

Say that Zentris is built on a LiteLLM gateway foundation, and be precise about your contribution: the security runtime, policy controls, local red-team scenarios, deployment readiness scripts, and project-specific documentation. Do not claim that you created the upstream LiteLLM provider ecosystem.

## Likely questions

| Question | Strong short answer |
| --- | --- |
| Why put security before the model? | It stops unsafe traffic before provider cost, data exposure, tool execution, or prompt contamination. |
| Why not only use a classifier? | Deterministic policy controls make the outcome explainable and reliable; model-based scoring can complement them for ambiguous cases. |
| What happens when detection fails? | The control path should fail closed for security-critical checks and create an audit event for investigation. |
| How do you handle false positives? | Track allow/block outcomes on a labelled test set, tune thresholds by risk category, and keep approval as a middle path for destructive actions. |
| How will this scale? | Keep policy checks stateless where possible, use Redis for rate limits and short-lived state, and emit audit events asynchronously. |

## What the local screen proves

The screen is a deterministic interview harness, not a benchmark claim. It demonstrates the product decision model without external services. Production readiness and runtime scope are documented in `docs/production-readiness.md` and `docs/zentris-security-runtime.md`.
