import asyncio
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from prisma import Json

from zentris_security.telemetry_worker import TelemetryWorker


class _Delegate:
    def __init__(self, result=None):
        self.calls = []
        self.result = result

    async def upsert(self, **kwargs):
        self.calls.append(("upsert", kwargs))
        return self.result

    async def create_many(self, **kwargs):
        self.calls.append(("create_many", kwargs))
        return SimpleNamespace(count=len(kwargs.get("data", [])))

    async def update(self, **kwargs):
        self.calls.append(("update", kwargs))
        return self.result

    async def update_many(self, **kwargs):
        self.calls.append(("update_many", kwargs))
        return SimpleNamespace(count=1)

    async def find_many(self, **kwargs):
        self.calls.append(("find_many", kwargs))
        return [SimpleNamespace(id="history-id", request_id="request-id", metric_recorded=False)]


class _Transaction:
    def __init__(self):
        self.litellm_zentrisconversationhistory = _Delegate(
            SimpleNamespace(id="history-id", metric_recorded=False)
        )
        self.litellm_zentrissecurityevent = _Delegate()
        self.litellm_zentrisdailymetric = _Delegate()


class _TransactionContext:
    def __init__(self, transaction):
        self.transaction = transaction

    async def __aenter__(self):
        return self.transaction

    async def __aexit__(self, *_args):
        return False


class _Database:
    def __init__(self):
        self.transaction = _Transaction()

    def tx(self):
        return _TransactionContext(self.transaction)


def _envelope(status="failed"):
    now = datetime.now(timezone.utc)
    return {
        "requestId": "request-id",
        "sessionId": "session-id",
        "identity": {"userId": "principal", "tenantId": None, "orgId": None},
        "route": "/v1/chat/completions",
        "model": "e2e-model",
        "modelParameters": {"temperature": 0},
        "rawMessages": [{"role": "user", "content": "raw"}],
        "sanitizedMessages": [{"role": "user", "content": "safe"}],
        "status": status,
        "httpStatus": 503 if status == "failed" else 200,
        "failureCode": "upstream_unavailable" if status == "failed" else None,
        "failureMessage": "Upstream request failed" if status == "failed" else None,
        "latencyMs": 12,
        "security": {
            "injectionDetected": False,
            "dlpDetected": False,
            "risk": "none",
            "score": 0,
            "matchedRules": [],
            "findings": [],
        },
        "createdAt": now.isoformat(),
        "rawExpiresAt": (now + timedelta(days=30)).isoformat(),
        "eventExpiresAt": (now + timedelta(days=90)).isoformat(),
    }


def test_worker_wraps_json_and_omits_absent_failed_call_results():
    worker = object.__new__(TelemetryWorker)
    worker.db = _Database()

    asyncio.run(worker._persist(_envelope()))

    _, upsert = worker.db.transaction.litellm_zentrisconversationhistory.calls[0]
    create = upsert["data"]["create"]
    assert isinstance(create["model_parameters"], Json)
    assert isinstance(create["raw_messages"], Json)
    assert isinstance(create["sanitized_messages"], Json)
    assert isinstance(create["security_summary"], Json)
    assert "raw_result" not in create
    assert "sanitized_result" not in create

    _, event_create = worker.db.transaction.litellm_zentrissecurityevent.calls[0]
    assert isinstance(event_create["data"][0]["details"], Json)


def test_worker_batch_uses_bulk_conversation_and_metric_writes():
    worker = object.__new__(TelemetryWorker)
    worker.db = _Database()

    asyncio.run(worker._persist_batch([_envelope()]))

    history_calls = worker.db.transaction.litellm_zentrisconversationhistory.calls
    assert [name for name, _ in history_calls] == ["create_many", "find_many", "update_many"]
    _, create_many = history_calls[0]
    assert create_many["skip_duplicates"] is True
    assert isinstance(create_many["data"][0]["raw_messages"], Json)
    metric_calls = worker.db.transaction.litellm_zentrisdailymetric.calls
    assert [name for name, _ in metric_calls] == ["upsert"]
