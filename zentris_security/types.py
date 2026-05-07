"""Shared security data structures for Zentris runtime enforcement."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Action(str, Enum):
    ALLOW = "allow"
    SANITIZE = "sanitize"
    REQUIRE_APPROVAL = "require_approval"
    BLOCK = "block"


class RiskLevel(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PipelineStage(str, Enum):
    INPUT = "input"
    RETRIEVAL = "retrieval"
    TOOL_CALL = "tool_call"
    MCP = "mcp"
    OUTPUT = "output"


@dataclass(frozen=True)
class DocumentChunk:
    content: str
    source: str = "unknown"
    chunk_id: str = "unknown"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ToolCall:
    name: str
    arguments: Dict[str, Any] = field(default_factory=dict)
    server: Optional[str] = None
    call_id: str = "unknown"


@dataclass(frozen=True)
class SecurityContext:
    user_id: str = "anonymous"
    session_id: str = "default"
    tenant_id: str = "default"
    model: str = "unknown"
    route: str = "chat"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SecurityRequest:
    prompt: str = ""
    documents: List[DocumentChunk] = field(default_factory=list)
    tool_calls: List[ToolCall] = field(default_factory=list)
    mcp_servers: List[Dict[str, Any]] = field(default_factory=list)
    output: str = ""
    context: SecurityContext = field(default_factory=SecurityContext)


@dataclass(frozen=True)
class SecurityFinding:
    rule_id: str
    title: str
    stage: PipelineStage
    risk: RiskLevel
    action: Action
    score: float
    evidence: str = ""
    owasp: List[str] = field(default_factory=list)
    mitre_atlas: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SecurityDecision:
    action: Action
    risk: RiskLevel
    score: float
    findings: List[SecurityFinding] = field(default_factory=list)
    latency_ms: float = 0.0
    stages_executed: List[PipelineStage] = field(default_factory=list)
    sanitized_prompt: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
