import asyncio
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import httpx
import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from zentris_security.admin_api import (
    ExportRequest,
    _cursor,
    _database_failures_as_unavailable,
    _daily_bounds,
    _decode_cursor,
    _require_proxy_admin,
    _window,
)


def test_database_transport_failures_are_reported_as_dependency_outages():
    @_database_failures_as_unavailable
    async def failing_endpoint():
        raise httpx.ReadError("database connection closed")

    with pytest.raises(HTTPException) as error:
        asyncio.run(failing_endpoint())

    assert error.value.status_code == 503
    assert error.value.detail == "database_unavailable"


def test_cursor_round_trip_and_invalid_cursor_rejection():
    created_at = datetime(2026, 8, 18, 12, 0, tzinfo=timezone.utc)
    encoded = _cursor(SimpleNamespace(id="history-1", created_at=created_at))
    assert _decode_cursor(encoded) == {"id": "history-1", "created_at": created_at}
    with pytest.raises(HTTPException) as error:
        _decode_cursor("not-a-valid-cursor")
    assert error.value.status_code == 400


def test_admin_role_is_required_for_raw_history_operations():
    admin = SimpleNamespace(user_role="proxy_admin")
    assert _require_proxy_admin(admin) is admin
    with pytest.raises(HTTPException) as error:
        _require_proxy_admin(SimpleNamespace(user_role="proxy_admin_viewer"))
    assert error.value.status_code == 403


def test_summary_window_is_bounded_to_ninety_days():
    end = datetime.now(timezone.utc)
    with pytest.raises(HTTPException) as error:
        _window(end - timedelta(days=91), end)
    assert error.value.status_code == 400


def test_daily_summary_bounds_remain_prisma_serializable_datetimes():
    start = datetime(2026, 8, 17, 15, 23, 17, 42, tzinfo=timezone.utc)
    end = datetime(2026, 8, 18, 2, 4, 9, 77, tzinfo=timezone.utc)

    start_day, end_day = _daily_bounds(start, end)

    assert isinstance(start_day, datetime)
    assert isinstance(end_day, datetime)
    assert start_day == datetime(2026, 8, 17, tzinfo=timezone.utc)
    assert end_day == datetime(2026, 8, 18, tzinfo=timezone.utc)


def test_export_contract_defaults_to_sanitized_and_rejects_unknown_dataset():
    assert ExportRequest(dataset="assistant").content == "sanitized"
    with pytest.raises(ValidationError):
        ExportRequest(dataset="unknown")
