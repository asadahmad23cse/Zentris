# Zentris Production Readiness

This checklist is the required release gate for running Zentris with real users.

## Required Gates

- `npm ci`
- `npm run build`
- `npm test`
- `python -m pytest tests/test_zentris_security_pipeline.py tests/test_zentris_security_detectors.py tests/test_zentris_security_audit_simulator.py tests/test_prompt_injection_detection.py tests/test_litellm_proxy_responses_config.py -q`
- `docker compose -f docker-compose.yml config --quiet` with real secrets injected
- `npm run build` inside `ui/litellm-dashboard`
- `scripts/smoke-test.ps1 -BaseUrl <deployed-url> -JwtToken <short-lived-test-jwt>`

On Windows, the full local production gate is:

```powershell
.\scripts\production-check.ps1
```

## Secret Requirements

Production deployments must set:

- `LITELLM_MASTER_KEY`
- `LITELLM_API_KEY`
- `JWT_SECRET`
- `CONFIRMATION_TOKEN_SECRET`
- `POSTGRES_PASSWORD`
- `GRAFANA_ADMIN_PASSWORD`

`JWT_SECRET` and `CONFIRMATION_TOKEN_SECRET` must be generated independently, must be at least 32 characters, and must never be reused across environments.

## Health Checks

- `/health/liveness` confirms the process can respond.
- `/health/readiness` confirms required dependencies are reachable.

Load balancers should use readiness for traffic routing and liveness only for restart decisions.

## Monitoring

Prometheus loads `monitoring/prometheus/zentris-alerts.yml` by default in compose. At minimum, alert on:

- LiteLLM proxy scrape failure for more than 2 minutes.
- Slow proxy scrape duration for more than 5 minutes.
- Deployment smoke test failure after every release.

## Rollback

Before deploying:

- Confirm the previous image or commit SHA is available.
- Confirm database backups are enabled and restorable.
- Keep the previous `.env`/secret version available in the secret manager.

If readiness fails after deploy:

1. Stop routing new traffic to the new version.
2. Roll back image or commit.
3. Restore previous secrets only if the release changed secret material.
4. Re-run `scripts/smoke-test.ps1` against the rollback target.
