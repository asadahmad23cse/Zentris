"""Durable Redis Stream -> Prisma telemetry worker for Zentris.

Run with: ``python -m zentris_security.telemetry_worker``.
The worker never logs prompt or completion content.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import time
from datetime import datetime, timezone
from typing import Any

from prisma import Json, Prisma
from redis.asyncio import Redis
from redis.exceptions import ResponseError

STREAM = "zentris:telemetry:v1"
GROUP = "zentris-telemetry-workers"
DEAD_LETTER_STREAM = "zentris:telemetry:dead-letter:v1"
LOGGER = logging.getLogger("zentris.telemetry")


def _dt(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _safe_error_code(error: Exception) -> str:
    return type(error).__name__[:80]


class TelemetryWorker:
    def __init__(self) -> None:
        redis_url = os.environ.get("REDIS_URL")
        if not redis_url:
            raise RuntimeError("REDIS_URL is required")
        self.redis = Redis.from_url(redis_url, decode_responses=True)
        self.db = Prisma()
        self.consumer = f"{socket.gethostname()}-{os.getpid()}"
        self.last_retention_sweep = 0.0

    async def start(self) -> None:
        await self.db.connect()
        try:
            await self.redis.xgroup_create(STREAM, GROUP, id="0", mkstream=True)
        except ResponseError as error:
            if "BUSYGROUP" not in str(error):
                raise

        LOGGER.info("telemetry_worker_started consumer=%s", self.consumer)
        try:
            await self._claim_stale()
            while True:
                batches = await self.redis.xreadgroup(
                    GROUP,
                    self.consumer,
                    streams={STREAM: ">"},
                    count=50,
                    block=5000,
                )
                if not batches:
                    await self._claim_stale()
                    if time.monotonic() - self.last_retention_sweep >= 3600:
                        await self._retention_sweep()
                        self.last_retention_sweep = time.monotonic()
                    continue
                for _, entries in batches:
                    await self._handle_batch(entries)
        finally:
            await self.db.disconnect()
            await self.redis.aclose()

    async def _handle(self, entry_id: str, fields: dict[str, str]) -> None:
        try:
            envelope = json.loads(fields.get("payload", ""))
            if envelope.get("version") != 1 or envelope.get("kind") != "conversation":
                raise ValueError("unsupported_telemetry_envelope")
            await self._persist(envelope["conversation"])
        except (ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
            await self.redis.xadd(
                DEAD_LETTER_STREAM,
                {"source_id": entry_id, "error_code": _safe_error_code(error)},
                maxlen=10000,
                approximate=True,
            )
            LOGGER.warning("telemetry_message_dead_lettered id=%s error=%s", entry_id, _safe_error_code(error))
        except Exception as error:  # database/transient errors remain pending for operator recovery
            LOGGER.error("telemetry_persist_failed id=%s error=%s", entry_id, _safe_error_code(error))
            return

        await self.redis.xack(STREAM, GROUP, entry_id)
        await self.redis.xdel(STREAM, entry_id)

    async def _handle_batch(self, entries: list[tuple[str, dict[str, str]]]) -> None:
        """Validate and commit a Redis delivery batch with bounded DB calls."""
        valid: list[tuple[str, dict[str, Any]]] = []
        terminal_ids: list[str] = []
        for entry_id, fields in entries:
            try:
                envelope = json.loads(fields.get("payload", ""))
                if envelope.get("version") != 1 or envelope.get("kind") != "conversation":
                    raise ValueError("unsupported_telemetry_envelope")
                valid.append((entry_id, envelope["conversation"]))
            except (ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
                await self.redis.xadd(
                    DEAD_LETTER_STREAM,
                    {"source_id": entry_id, "error_code": _safe_error_code(error)},
                    maxlen=10000,
                    approximate=True,
                )
                terminal_ids.append(entry_id)
                LOGGER.warning("telemetry_message_dead_lettered id=%s error=%s", entry_id, _safe_error_code(error))

        if valid:
            try:
                await self._persist_batch([item for _, item in valid])
                terminal_ids.extend(entry_id for entry_id, _ in valid)
            except Exception as error:  # leave the complete valid batch pending for recovery
                LOGGER.error("telemetry_batch_persist_failed count=%s error=%s", len(valid), _safe_error_code(error))

        if terminal_ids:
            pipeline = self.redis.pipeline(transaction=False)
            for entry_id in terminal_ids:
                pipeline.xack(STREAM, GROUP, entry_id)
                pipeline.xdel(STREAM, entry_id)
            await pipeline.execute()

    async def _claim_stale(self) -> None:
        """Recover records abandoned by a crashed worker after a bounded idle period."""
        next_id = "0-0"
        while True:
            claimed = await self.redis.xautoclaim(
                STREAM, GROUP, self.consumer, min_idle_time=60_000, start_id=next_id, count=50
            )
            next_id, entries = claimed[0], claimed[1]
            if entries:
                await self._handle_batch(entries)
            if not entries or next_id == "0-0":
                return

    async def _persist(self, item: dict[str, Any]) -> None:
        identity = item.get("identity") or {}
        security = item.get("security") or {}
        create_data = {
            "request_id": item["requestId"],
            "session_id": item["sessionId"],
            "user_id": identity.get("userId"),
            "tenant_id": identity.get("tenantId"),
            "organization_id": identity.get("orgId"),
            "route": item["route"],
            "model": item.get("model"),
            "model_parameters": Json(item.get("modelParameters") or {}),
            "raw_messages": Json(item.get("rawMessages") or []),
            "sanitized_messages": Json(item.get("sanitizedMessages") or []),
            "status": item["status"],
            "http_status": item.get("httpStatus"),
            "failure_code": item.get("failureCode"),
            "failure_message": item.get("failureMessage"),
            "latency_ms": int(item.get("latencyMs") or 0),
            "security_summary": Json(security),
            "expires_at": _dt(item["rawExpiresAt"]),
        }
        # Prisma Client Python treats ``None`` for nullable JSON as an omitted
        # required-union value.  Failed calls legitimately have no result, so
        # leave those optional keys out instead of passing Python None.
        if item.get("rawResult") is not None:
            create_data["raw_result"] = Json(item["rawResult"])
        if item.get("sanitizedResult") is not None:
            create_data["sanitized_result"] = Json(item["sanitizedResult"])
        events: list[dict[str, Any]] = []
        for index, finding in enumerate(security.get("findings") or []):
            events.append(
                {
                    "event_key": f'{item["requestId"]}:finding:{index}:{finding.get("ruleId", "unknown")}',
                    "request_id": item["requestId"],
                    "session_id": item["sessionId"],
                    "user_id": identity.get("userId"),
                    "tenant_id": identity.get("tenantId"),
                    "event_type": finding.get("kind", "security"),
                    "stage": finding.get("stage", "input"),
                    "risk": finding.get("risk", "low"),
                    "score": int(finding.get("score") or 0),
                    "action": finding.get("action", "warn"),
                    "rule_ids": [finding.get("ruleId")] if finding.get("ruleId") else [],
                    "details": Json({"category": finding.get("category", "unknown")}),
                    "model": item.get("model"),
                    "route": item["route"],
                    "latency_ms": int(item.get("latencyMs") or 0),
                    "expires_at": _dt(item["eventExpiresAt"]),
                }
            )
        if item["status"] == "failed":
            events.append(
                {
                    "event_key": f'{item["requestId"]}:failed_call',
                    "request_id": item["requestId"],
                    "session_id": item["sessionId"],
                    "user_id": identity.get("userId"),
                    "tenant_id": identity.get("tenantId"),
                    "event_type": "failed_call",
                    "stage": "output",
                    "risk": "low",
                    "score": 0,
                    "action": "allow",
                    "rule_ids": [],
                    "details": Json({"failure_code": item.get("failureCode", "unknown")}),
                    "model": item.get("model"),
                    "route": item["route"],
                    "latency_ms": int(item.get("latencyMs") or 0),
                    "expires_at": _dt(item["eventExpiresAt"]),
                }
            )
        day = _dt(item["createdAt"]).replace(hour=0, minute=0, second=0, microsecond=0)
        success = 1 if item["status"] == "success" else 0
        failure = 1 if item["status"] == "failed" else 0
        injection = 1 if security.get("injectionDetected") else 0
        dlp = 1 if security.get("dlpDetected") else 0
        latency = int(item.get("latencyMs") or 0)
        async with self.db.tx() as tx:
            conversation = await tx.litellm_zentrisconversationhistory.upsert(
                where={"request_id": item["requestId"]},
                data={"create": create_data, "update": create_data},
            )
            if events:
                linked_events = [{**event, "conversation_id": conversation.id} for event in events]
                await tx.litellm_zentrissecurityevent.create_many(data=linked_events, skip_duplicates=True)
            if not conversation.metric_recorded:
                await tx.litellm_zentrisdailymetric.upsert(
                    where={"day": day},
                    data={
                        "create": {
                            "day": day,
                            "request_count": 1,
                            "success_count": success,
                            "failure_count": failure,
                            "injection_count": injection,
                            "dlp_count": dlp,
                            "latency_sum_ms": latency,
                            "latency_sample_count": 1,
                        },
                        "update": {
                            "request_count": {"increment": 1},
                            "success_count": {"increment": success},
                            "failure_count": {"increment": failure},
                            "injection_count": {"increment": injection},
                            "dlp_count": {"increment": dlp},
                            "latency_sum_ms": {"increment": latency},
                            "latency_sample_count": {"increment": 1},
                        },
                    },
                )
                await tx.litellm_zentrisconversationhistory.update(
                    where={"id": conversation.id}, data={"metric_recorded": True}
                )

    async def _persist_batch(self, items: list[dict[str, Any]]) -> None:
        conversation_rows: list[dict[str, Any]] = []
        event_rows_by_request: dict[str, list[dict[str, Any]]] = {}
        metric_values: dict[str, tuple[datetime, int, int, int, int, int]] = {}

        for item in items:
            identity = item.get("identity") or {}
            security = item.get("security") or {}
            create_data: dict[str, Any] = {
                "request_id": item["requestId"],
                "session_id": item["sessionId"],
                "user_id": identity.get("userId"),
                "tenant_id": identity.get("tenantId"),
                "organization_id": identity.get("orgId"),
                "route": item["route"],
                "model": item.get("model"),
                "model_parameters": Json(item.get("modelParameters") or {}),
                "raw_messages": Json(item.get("rawMessages") or []),
                "sanitized_messages": Json(item.get("sanitizedMessages") or []),
                "status": item["status"],
                "http_status": item.get("httpStatus"),
                "failure_code": item.get("failureCode"),
                "failure_message": item.get("failureMessage"),
                "latency_ms": int(item.get("latencyMs") or 0),
                "security_summary": Json(security),
                "expires_at": _dt(item["rawExpiresAt"]),
            }
            if item.get("rawResult") is not None:
                create_data["raw_result"] = Json(item["rawResult"])
            if item.get("sanitizedResult") is not None:
                create_data["sanitized_result"] = Json(item["sanitizedResult"])
            conversation_rows.append(create_data)

            events: list[dict[str, Any]] = []
            for index, finding in enumerate(security.get("findings") or []):
                events.append(
                    {
                        "event_key": f'{item["requestId"]}:finding:{index}:{finding.get("ruleId", "unknown")}',
                        "request_id": item["requestId"],
                        "session_id": item["sessionId"],
                        "user_id": identity.get("userId"),
                        "tenant_id": identity.get("tenantId"),
                        "event_type": finding.get("kind", "security"),
                        "stage": finding.get("stage", "input"),
                        "risk": finding.get("risk", "low"),
                        "score": int(finding.get("score") or 0),
                        "action": finding.get("action", "warn"),
                        "rule_ids": [finding.get("ruleId")] if finding.get("ruleId") else [],
                        "details": Json({"category": finding.get("category", "unknown")}),
                        "model": item.get("model"),
                        "route": item["route"],
                        "latency_ms": int(item.get("latencyMs") or 0),
                        "expires_at": _dt(item["eventExpiresAt"]),
                    }
                )
            if item["status"] == "failed":
                events.append(
                    {
                        "event_key": f'{item["requestId"]}:failed_call',
                        "request_id": item["requestId"],
                        "session_id": item["sessionId"],
                        "user_id": identity.get("userId"),
                        "tenant_id": identity.get("tenantId"),
                        "event_type": "failed_call",
                        "stage": "output",
                        "risk": "low",
                        "score": 0,
                        "action": "allow",
                        "rule_ids": [],
                        "details": Json({"failure_code": item.get("failureCode", "unknown")}),
                        "model": item.get("model"),
                        "route": item["route"],
                        "latency_ms": int(item.get("latencyMs") or 0),
                        "expires_at": _dt(item["eventExpiresAt"]),
                    }
                )
            event_rows_by_request[item["requestId"]] = events
            metric_values[item["requestId"]] = (
                _dt(item["createdAt"]).replace(hour=0, minute=0, second=0, microsecond=0),
                1 if item["status"] == "success" else 0,
                1 if item["status"] == "failed" else 0,
                1 if security.get("injectionDetected") else 0,
                1 if security.get("dlpDetected") else 0,
                int(item.get("latencyMs") or 0),
            )

        request_ids = [row["request_id"] for row in conversation_rows]
        async with self.db.tx() as tx:
            await tx.litellm_zentrisconversationhistory.create_many(data=conversation_rows, skip_duplicates=True)
            conversations = await tx.litellm_zentrisconversationhistory.find_many(
                where={"request_id": {"in": request_ids}}
            )
            events: list[dict[str, Any]] = []
            unrecorded = []
            daily: dict[datetime, list[int]] = {}
            for conversation in conversations:
                events.extend(
                    {**event, "conversation_id": conversation.id}
                    for event in event_rows_by_request.get(conversation.request_id, [])
                )
                if not conversation.metric_recorded:
                    unrecorded.append(conversation.id)
                    day, success, failure, injection, dlp, latency = metric_values[conversation.request_id]
                    totals = daily.setdefault(day, [0, 0, 0, 0, 0, 0])
                    totals[0] += 1
                    totals[1] += success
                    totals[2] += failure
                    totals[3] += injection
                    totals[4] += dlp
                    totals[5] += latency
            if events:
                await tx.litellm_zentrissecurityevent.create_many(data=events, skip_duplicates=True)
            for day, totals in daily.items():
                requests, successes, failures, injections, dlp_count, latency_sum = totals
                await tx.litellm_zentrisdailymetric.upsert(
                    where={"day": day},
                    data={
                        "create": {
                            "day": day,
                            "request_count": requests,
                            "success_count": successes,
                            "failure_count": failures,
                            "injection_count": injections,
                            "dlp_count": dlp_count,
                            "latency_sum_ms": latency_sum,
                            "latency_sample_count": requests,
                        },
                        "update": {
                            "request_count": {"increment": requests},
                            "success_count": {"increment": successes},
                            "failure_count": {"increment": failures},
                            "injection_count": {"increment": injections},
                            "dlp_count": {"increment": dlp_count},
                            "latency_sum_ms": {"increment": latency_sum},
                            "latency_sample_count": {"increment": requests},
                        },
                    },
                )
            if unrecorded:
                await tx.litellm_zentrisconversationhistory.update_many(
                    where={"id": {"in": unrecorded}}, data={"metric_recorded": True}
                )

    async def _retention_sweep(self) -> None:
        now = datetime.now(timezone.utc)
        await self.db.litellm_zentrisconversationhistory.delete_many(where={"expires_at": {"lt": now}})
        await self.db.litellm_zentrissecurityevent.delete_many(where={"expires_at": {"lt": now}})


async def main() -> None:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO").upper())
    # Prisma's local query-engine client uses httpx internally. Per-query INFO
    # logs multiply each telemetry record into several log writes and can become
    # an I/O bottleneck without adding operationally useful information.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    await TelemetryWorker().start()


if __name__ == "__main__":
    asyncio.run(main())
