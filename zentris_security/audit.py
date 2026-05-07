"""JSONL audit logging and replay for Zentris security decisions."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from zentris_security.pipeline import ZentrisSecurityPipeline
from zentris_security.types import DocumentChunk, SecurityContext, SecurityDecision, SecurityRequest, ToolCall


@dataclass(frozen=True)
class AuditEvent:
    event_id: str
    timestamp: str
    request: dict[str, Any]
    decision: dict[str, Any]
    tags: list[str] = field(default_factory=list)


def write_audit_event(path: str | Path, request: SecurityRequest, decision: SecurityDecision, tags: list[str] | None = None) -> AuditEvent:
    event = AuditEvent(
        event_id=f"{request.context.session_id}-{datetime.now(timezone.utc).timestamp()}",
        timestamp=datetime.now(timezone.utc).isoformat(),
        request=asdict(request),
        decision=asdict(decision),
        tags=tags or [],
    )
    audit_path = Path(path)
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    with audit_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(asdict(event), default=_json_default, sort_keys=True) + "\n")
    return event


def read_audit_events(path: str | Path) -> Iterable[AuditEvent]:
    audit_path = Path(path)
    if not audit_path.exists():
        return []
    events: list[AuditEvent] = []
    with audit_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                events.append(AuditEvent(**json.loads(line)))
    return events


def replay_audit(path: str | Path, pipeline: ZentrisSecurityPipeline | None = None) -> list[SecurityDecision]:
    runtime = pipeline or ZentrisSecurityPipeline()
    decisions: list[SecurityDecision] = []
    for event in read_audit_events(path):
        decisions.append(runtime.inspect(_request_from_dict(event.request)))
    return decisions


def _request_from_dict(payload: dict[str, Any]) -> SecurityRequest:
    return SecurityRequest(
        prompt=payload.get("prompt", ""),
        documents=[DocumentChunk(**item) for item in payload.get("documents", [])],
        tool_calls=[ToolCall(**item) for item in payload.get("tool_calls", [])],
        mcp_servers=payload.get("mcp_servers", []),
        output=payload.get("output", ""),
        context=SecurityContext(**payload.get("context", {})),
    )


def _json_default(value: Any) -> Any:
    if hasattr(value, "value"):
        return value.value
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")
