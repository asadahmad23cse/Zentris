# Zentris Benchmarking Strategy

Zentris benchmarking is organized around OWASP LLM Top 10, MITRE ATLAS, and runtime enforcement outcomes.

## Current Regression Gates

- Unit tests for each detector family.
- End-to-end pipeline tests.
- Audit replay test.
- Red-team simulator against `zentris_security/data/red_team_attacks.json`.

## Metrics

- Attack block rate.
- Benign allow rate.
- Approval precision for risky tool and MCP operations.
- Sanitization rate for medium-confidence retrieved content.
- Pipeline latency in milliseconds.
- Stage coverage by OWASP and MITRE technique.

## Resume-Worthy Target

The project becomes top-tier when every release publishes:

- Reproducible benchmark report.
- OWASP LLM Top 10 coverage matrix.
- MITRE ATLAS coverage matrix.
- Latency and throughput profile.
- Attack replay bundle.
- Detector false-positive and false-negative deltas.
