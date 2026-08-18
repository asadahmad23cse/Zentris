"""Admin-only Zentris telemetry, history, review, and JSONL export API."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Any, AsyncIterator, Literal, Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from prisma.errors import PrismaError

from litellm.proxy._types import UserAPIKeyAuth
from litellm.proxy.auth.user_api_key_auth import user_api_key_auth

router = APIRouter(prefix="/v1/zentris", tags=["zentris security"])
LOGGER = logging.getLogger("zentris.admin")
MAX_PAGE_SIZE = 100
TELEMETRY_STREAM = "zentris:telemetry:v1"
TELEMETRY_GROUP = "zentris-telemetry-workers"


class ReviewUpdate(BaseModel):
    review_status: Literal["unreviewed", "approved", "rejected"]
    dataset_targets: list[Literal["assistant", "security"]] = Field(default_factory=list)
    security_label: Optional[str] = Field(default=None, max_length=80)
    notes: Optional[str] = Field(default=None, max_length=2000)


class BulkReviewUpdate(ReviewUpdate):
    ids: list[str] = Field(min_length=1, max_length=500)


class ExportRequest(BaseModel):
    dataset: Literal["assistant", "security"]
    content: Literal["sanitized", "raw"] = "sanitized"
    ids: list[str] = Field(default_factory=list, max_length=10000)


def _role_value(auth: UserAPIKeyAuth) -> str:
    role = getattr(auth, "user_role", None)
    return str(getattr(role, "value", role or ""))


@router.get("/auth/introspect", include_in_schema=False)
async def auth_introspect(auth: UserAPIKeyAuth = Depends(user_api_key_auth)) -> dict[str, Any]:
    """Return only the authenticated principal needed by the private Zentris gateway."""
    user_id = getattr(auth, "user_id", None)
    hashed_key = getattr(auth, "api_key", None)
    if not user_id and isinstance(hashed_key, str):
        user_id = f"key:{hashed_key[-16:]}"
    return {
        "user_id": user_id or "unknown",
        "user_role": _role_value(auth),
        "team_id": getattr(auth, "team_id", None),
        "organization_id": getattr(auth, "org_id", None),
    }


def _require_proxy_admin(auth: UserAPIKeyAuth = Depends(user_api_key_auth)) -> UserAPIKeyAuth:
    if _role_value(auth) not in {"proxy_admin", "Admin"}:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="proxy_admin_required")
    return auth


def _db() -> Any:
    from litellm.proxy.proxy_server import prisma_client

    if prisma_client is None or prisma_client.db is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="database_unavailable")
    return prisma_client.db


def _database_failures_as_unavailable(handler: Any) -> Any:
    """Keep database outages distinct from application and validation errors."""

    @wraps(handler)
    async def wrapped(*args: Any, **kwargs: Any) -> Any:
        try:
            return await handler(*args, **kwargs)
        except HTTPException:
            raise
        except (httpx.TransportError, PrismaError) as error:
            LOGGER.warning("zentris_database_unavailable error=%s", type(error).__name__)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="database_unavailable",
            ) from error

    return wrapped


def _dump(row: Any) -> dict[str, Any]:
    if hasattr(row, "model_dump"):
        return row.model_dump(mode="json")
    if hasattr(row, "dict"):
        value = row.dict()
        return json.loads(json.dumps(value, default=str))
    return json.loads(json.dumps(row, default=str))


def _cursor(row: Any) -> str:
    payload = json.dumps({"created_at": row.created_at.isoformat(), "id": row.id}, separators=(",", ":"))
    return base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")


def _decode_cursor(value: Optional[str]) -> Optional[dict[str, Any]]:
    if not value:
        return None
    try:
        padded = value + "=" * (-len(value) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded).decode())
        return {"created_at": datetime.fromisoformat(payload["created_at"]), "id": payload["id"]}
    except (ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise HTTPException(status_code=400, detail="invalid_cursor") from error


def _window(from_time: Optional[datetime], to_time: Optional[datetime]) -> tuple[datetime, datetime]:
    now = datetime.now(timezone.utc)
    start = from_time or now - timedelta(days=30)
    end = to_time or now
    if start >= end or end - start > timedelta(days=90):
        raise HTTPException(status_code=400, detail="invalid_time_window")
    return start, end


def _daily_bounds(start: datetime, end: datetime) -> tuple[datetime, datetime]:
    """Return Prisma-serializable bounds for the database DATE aggregate key."""
    return (
        start.replace(hour=0, minute=0, second=0, microsecond=0),
        end.replace(hour=0, minute=0, second=0, microsecond=0),
    )


def _query_timestamp(value: datetime) -> str:
    """Serialize an aware instant for Prisma raw SQL against timestamp columns."""
    return value.astimezone(timezone.utc).replace(tzinfo=None).isoformat()


async def _summary_aggregates(start: datetime, end: datetime) -> dict[str, int]:
    """Compute summary values in PostgreSQL without loading retained content."""
    rows = await _db().query_raw(
        '''
        SELECT
          COUNT(*)::int AS requests,
          (COUNT(*) FILTER (WHERE status = 'success'))::int AS success,
          (COUNT(*) FILTER (WHERE status = 'failed'))::int AS failed,
          (COUNT(*) FILTER (WHERE security_summary->>'injectionDetected' = 'true'))::int AS injection,
          (COUNT(*) FILTER (WHERE security_summary->>'dlpDetected' = 'true'))::int AS dlp,
          COALESCE(percentile_disc(0.50) WITHIN GROUP (ORDER BY latency_ms), 0)::int AS p50,
          COALESCE(percentile_disc(0.95) WITHIN GROUP (ORDER BY latency_ms), 0)::int AS p95,
          COALESCE(percentile_disc(0.99) WITHIN GROUP (ORDER BY latency_ms), 0)::int AS p99
        FROM "LiteLLM_ZentrisConversationHistory"
        WHERE created_at >= $1::timestamp AND created_at < $2::timestamp
        ''',
        _query_timestamp(start),
        _query_timestamp(end),
    )
    return rows[0] if rows else {}


async def _event_breakdowns(start: datetime, end: datetime) -> list[dict[str, Any]]:
    """Return bounded rule/category/model counts without materializing events."""
    return await _db().query_raw(
        '''
        WITH filtered AS (
          SELECT event_type, rule_ids, details, model
          FROM "LiteLLM_ZentrisSecurityEvent"
          WHERE created_at >= $1::timestamp AND created_at < $2::timestamp
        ), ranked AS (
          SELECT 'rule'::text AS kind, rule_id AS name, COUNT(*)::int AS count
          FROM filtered CROSS JOIN LATERAL unnest(rule_ids) AS rule_id
          GROUP BY rule_id
          UNION ALL
          SELECT 'category', COALESCE(details->>'category', event_type), COUNT(*)::int
          FROM filtered
          GROUP BY COALESCE(details->>'category', event_type)
          UNION ALL
          SELECT 'model', COALESCE(model, 'unknown'), COUNT(*)::int
          FROM filtered
          GROUP BY COALESCE(model, 'unknown')
        )
        SELECT kind, name, count
        FROM (
          SELECT kind, name, count,
                 row_number() OVER (PARTITION BY kind ORDER BY count DESC, name ASC) AS position
          FROM ranked
        ) ordered
        WHERE position <= 20
        ORDER BY kind, count DESC, name ASC
        ''',
        _query_timestamp(start),
        _query_timestamp(end),
    )


async def _telemetry_status() -> dict[str, Any]:
    redis_url = os.environ.get("REDIS_URL")
    if not redis_url:
        return {"available": False, "queued_entries": 0, "pending_entries": 0, "lag_seconds": None}
    try:
        from redis.asyncio import Redis

        client = Redis.from_url(redis_url, decode_responses=True)
        try:
            queued = int(await client.xlen(TELEMETRY_STREAM))
            pending_value = await client.xpending(TELEMETRY_STREAM, TELEMETRY_GROUP)
            pending = int(pending_value.get("pending", 0) if isinstance(pending_value, dict) else pending_value[0])
            oldest = await client.xrange(TELEMETRY_STREAM, min="-", max="+", count=1)
            lag = None
            if oldest:
                created_ms = int(str(oldest[0][0]).split("-", 1)[0])
                lag = max(0.0, (datetime.now(timezone.utc).timestamp() * 1000 - created_ms) / 1000)
            return {"available": True, "queued_entries": queued, "pending_entries": pending, "lag_seconds": lag}
        finally:
            await client.aclose()
    except Exception as error:
        LOGGER.warning("telemetry_status_unavailable error=%s", type(error).__name__)
        return {"available": False, "queued_entries": 0, "pending_entries": 0, "lag_seconds": None}


@router.get("/security/summary")
@_database_failures_as_unavailable
async def security_summary(
    from_time: Optional[datetime] = Query(default=None, alias="from"),
    to_time: Optional[datetime] = Query(default=None, alias="to"),
    _auth: UserAPIKeyAuth = Depends(_require_proxy_admin),
) -> dict[str, Any]:
    start, end = _window(from_time, to_time)
    # Prisma Client Python's serializer accepts datetime values for DateTime
    # filters even when @client.Date maps returned values to date objects.
    # Passing date instances here raises ``TypeError: Type date not serializable``.
    start_day, end_day = _daily_bounds(start, end)
    aggregates, breakdown_rows, daily_rows, telemetry = await asyncio.gather(
        _summary_aggregates(start, end),
        _event_breakdowns(start, end),
        _db().litellm_zentrisdailymetric.find_many(
            where={"day": {"gte": start_day, "lte": end_day}}, order={"day": "asc"}, take=91
        ),
        _telemetry_status(),
    )
    requests = int(aggregates.get("requests") or 0)
    success = int(aggregates.get("success") or 0)
    failed = int(aggregates.get("failed") or 0)
    breakdowns: dict[str, list[dict[str, Any]]] = {"rule": [], "category": [], "model": []}
    for row in breakdown_rows:
        kind = str(row.get("kind") or "")
        if kind in breakdowns:
            breakdowns[kind].append({"name": str(row.get("name") or "unknown"), "count": int(row.get("count") or 0)})
    return {
        "from": start,
        "to": end,
        "requests": requests,
        "success": success,
        "failed": failed,
        "success_rate": success / requests if requests else 0,
        "injection_attempts": int(aggregates.get("injection") or 0),
        "dlp_findings": int(aggregates.get("dlp") or 0),
        "latency_ms": {
            "p50": int(aggregates.get("p50") or 0),
            "p95": int(aggregates.get("p95") or 0),
            "p99": int(aggregates.get("p99") or 0),
        },
        "telemetry": telemetry,
        "time_series": [
            {
                "day": row.day,
                "requests": row.request_count,
                "success": row.success_count,
                "failed": row.failure_count,
                "injection": row.injection_count,
                "dlp": row.dlp_count,
                "average_latency_ms": int(row.latency_sum_ms / row.latency_sample_count) if row.latency_sample_count else 0,
            }
            for row in daily_rows
        ],
        "breakdowns": {
            "rules": breakdowns["rule"],
            "categories": breakdowns["category"],
            "models": breakdowns["model"],
        },
        "truncated": False,
    }


@router.get("/security/events")
@_database_failures_as_unavailable
async def security_events(
    cursor: Optional[str] = None,
    limit: int = Query(default=50, ge=1, le=MAX_PAGE_SIZE),
    event_type: Optional[str] = None,
    risk: Optional[str] = None,
    model: Optional[str] = None,
    from_time: Optional[datetime] = Query(default=None, alias="from"),
    to_time: Optional[datetime] = Query(default=None, alias="to"),
    _auth: UserAPIKeyAuth = Depends(_require_proxy_admin),
) -> dict[str, Any]:
    start, end = _window(from_time, to_time)
    decoded = _decode_cursor(cursor)
    filters: list[dict[str, Any]] = [{"created_at": {"gte": start, "lt": end}}]
    if event_type:
        filters.append({"event_type": event_type})
    if risk:
        filters.append({"risk": risk})
    if model:
        filters.append({"model": model})
    if decoded:
        filters.append({"OR": [{"created_at": {"lt": decoded["created_at"]}}, {"created_at": decoded["created_at"], "id": {"lt": decoded["id"]}}]})
    rows = await _db().litellm_zentrissecurityevent.find_many(
        where={"AND": filters}, order=[{"created_at": "desc"}, {"id": "desc"}], take=limit + 1
    )
    page = rows[:limit]
    return {"data": [_dump(row) for row in page], "next_cursor": _cursor(page[-1]) if len(rows) > limit and page else None}


@router.get("/security/events/{event_id}")
@_database_failures_as_unavailable
async def security_event(event_id: str, auth: UserAPIKeyAuth = Depends(_require_proxy_admin)) -> dict[str, Any]:
    row = await _db().litellm_zentrissecurityevent.find_unique(where={"id": event_id})
    if row is None:
        raise HTTPException(status_code=404, detail="event_not_found")
    item = _dump(row)
    conversation_id = item.get("conversation_id")
    if conversation_id:
        conversation = await _db().litellm_zentrisconversationhistory.find_unique(where={"id": conversation_id})
        if conversation is not None:
            conversation_item = _dump(conversation)
            item["conversation"] = {
                "id": conversation_item.get("id"),
                "request_id": conversation_item.get("request_id"),
                "raw_messages": conversation_item.get("raw_messages"),
                "sanitized_messages": conversation_item.get("sanitized_messages"),
                "raw_result": conversation_item.get("raw_result"),
                "sanitized_result": conversation_item.get("sanitized_result"),
            }
            LOGGER.info(
                "raw_security_event_viewed event_id=%s history_id=%s actor=%s",
                event_id,
                conversation_id,
                getattr(auth, "user_id", "unknown"),
            )
    return item


@router.get("/history")
@_database_failures_as_unavailable
async def history(
    cursor: Optional[str] = None,
    limit: int = Query(default=50, ge=1, le=MAX_PAGE_SIZE),
    review_status: Optional[str] = None,
    call_status: Optional[str] = Query(default=None, alias="status"),
    model: Optional[str] = None,
    _auth: UserAPIKeyAuth = Depends(_require_proxy_admin),
) -> dict[str, Any]:
    decoded = _decode_cursor(cursor)
    filters: list[dict[str, Any]] = []
    if review_status:
        filters.append({"review_status": review_status})
    if call_status:
        filters.append({"status": call_status})
    if model:
        filters.append({"model": model})
    if decoded:
        filters.append({"OR": [{"created_at": {"lt": decoded["created_at"]}}, {"created_at": decoded["created_at"], "id": {"lt": decoded["id"]}}]})
    rows = await _db().litellm_zentrisconversationhistory.find_many(
        where={"AND": filters} if filters else None,
        order=[{"created_at": "desc"}, {"id": "desc"}],
        take=limit + 1,
    )
    page = rows[:limit]
    data = []
    for row in page:
        item = _dump(row)
        item.pop("raw_messages", None)
        item.pop("raw_result", None)
        data.append(item)
    return {"data": data, "next_cursor": _cursor(page[-1]) if len(rows) > limit and page else None}


@router.get("/history/{history_id}")
@_database_failures_as_unavailable
async def history_detail(history_id: str, auth: UserAPIKeyAuth = Depends(_require_proxy_admin)) -> dict[str, Any]:
    row = await _db().litellm_zentrisconversationhistory.find_unique(where={"id": history_id})
    if row is None:
        raise HTTPException(status_code=404, detail="history_not_found")
    LOGGER.info("raw_history_viewed history_id=%s actor=%s", history_id, getattr(auth, "user_id", "unknown"))
    return _dump(row)


@router.patch("/history/{history_id}/review")
@_database_failures_as_unavailable
async def review_history(history_id: str, body: ReviewUpdate, auth: UserAPIKeyAuth = Depends(_require_proxy_admin)) -> dict[str, Any]:
    existing = await _db().litellm_zentrisconversationhistory.find_unique(where={"id": history_id})
    if existing is None:
        raise HTTPException(status_code=404, detail="history_not_found")
    if "assistant" in body.dataset_targets and existing.status != "success":
        raise HTTPException(status_code=400, detail="failed_calls_cannot_enter_assistant_dataset")
    row = await _db().litellm_zentrisconversationhistory.update(
        where={"id": history_id},
        data={
            "review_status": body.review_status,
            "dataset_targets": body.dataset_targets,
            "security_label": body.security_label,
            "review_notes": body.notes,
            "reviewed_by": str(getattr(auth, "user_id", "unknown")),
            "reviewed_at": datetime.now(timezone.utc),
        },
    )
    LOGGER.info("history_reviewed history_id=%s actor=%s state=%s", history_id, getattr(auth, "user_id", "unknown"), body.review_status)
    return _dump(row)


@router.post("/history/bulk-review")
@_database_failures_as_unavailable
async def bulk_review(body: BulkReviewUpdate, auth: UserAPIKeyAuth = Depends(_require_proxy_admin)) -> dict[str, Any]:
    if "assistant" in body.dataset_targets:
        failed = await _db().litellm_zentrisconversationhistory.count(where={"id": {"in": body.ids}, "status": {"not": "success"}})
        if failed:
            raise HTTPException(status_code=400, detail="failed_calls_cannot_enter_assistant_dataset")
    result = await _db().litellm_zentrisconversationhistory.update_many(
        where={"id": {"in": body.ids}},
        data={
            "review_status": body.review_status,
            "dataset_targets": body.dataset_targets,
            "security_label": body.security_label,
            "review_notes": body.notes,
            "reviewed_by": str(getattr(auth, "user_id", "unknown")),
            "reviewed_at": datetime.now(timezone.utc),
        },
    )
    updated = getattr(result, "count", result)
    LOGGER.info("history_bulk_reviewed count=%s actor=%s state=%s", updated, getattr(auth, "user_id", "unknown"), body.review_status)
    return {"updated": updated}


@router.delete("/history/{history_id}")
@_database_failures_as_unavailable
async def delete_history(history_id: str, auth: UserAPIKeyAuth = Depends(_require_proxy_admin)) -> dict[str, Any]:
    existing = await _db().litellm_zentrisconversationhistory.find_unique(where={"id": history_id})
    if existing is None:
        raise HTTPException(status_code=404, detail="history_not_found")
    await _db().litellm_zentrissecurityevent.delete_many(where={"conversation_id": history_id})
    await _db().litellm_zentrisconversationhistory.delete(where={"id": history_id})
    LOGGER.info("history_deleted history_id=%s actor=%s", history_id, getattr(auth, "user_id", "unknown"))
    return {"deleted": True, "id": history_id}


@router.post("/training-exports")
@_database_failures_as_unavailable
async def training_export(body: ExportRequest, auth: UserAPIKeyAuth = Depends(_require_proxy_admin)) -> StreamingResponse:
    filters: dict[str, Any] = {"review_status": "approved", "dataset_targets": {"has": body.dataset}}
    if body.ids:
        filters["id"] = {"in": body.ids}
    if body.dataset == "assistant":
        filters["status"] = "success"
    rows = await _db().litellm_zentrisconversationhistory.find_many(where=filters, order={"created_at": "asc"}, take=10000)

    async def lines() -> AsyncIterator[str]:
        for row in rows:
            item = _dump(row)
            prefix = "raw" if body.content == "raw" else "sanitized"
            messages = item.get(f"{prefix}_messages") or []
            result = item.get(f"{prefix}_result")
            if body.dataset == "assistant":
                if result:
                    yield json.dumps({"messages": [*messages, result]}, ensure_ascii=False, separators=(",", ":")) + "\n"
            else:
                security = item.get("security_summary") or {}
                label = item.get("security_label") or ("injection" if security.get("injectionDetected") else "benign")
                yield json.dumps(
                    {
                        "messages": [
                            {"role": "system", "content": "Classify the security risk in the supplied prompt."},
                            {"role": "user", "content": json.dumps(messages, ensure_ascii=False)},
                            {"role": "assistant", "content": json.dumps({"label": label, "risk": security.get("risk", "none"), "rules": security.get("matchedRules", [])})},
                        ]
                    },
                    ensure_ascii=False,
                    separators=(",", ":"),
                ) + "\n"

    LOGGER.info("training_export actor=%s dataset=%s content=%s count=%s", getattr(auth, "user_id", "unknown"), body.dataset, body.content, len(rows))
    filename = f"zentris-{body.dataset}-{datetime.now(timezone.utc).date().isoformat()}.jsonl"
    return StreamingResponse(lines(), media_type="application/x-ndjson", headers={"Content-Disposition": f'attachment; filename="{filename}"'})
