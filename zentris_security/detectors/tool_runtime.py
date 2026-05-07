"""Runtime tool-call enforcement for agentic workflows."""

from __future__ import annotations

import re
from typing import Any

from zentris_security.normalization import excerpt, normalize_text
from zentris_security.types import Action, PipelineStage, RiskLevel, SecurityFinding, ToolCall

DANGEROUS_ARGUMENT_PATTERNS = [
    (re.compile(r"(?i)\b(rm\s+-rf|del\s+/[sq]|format\s+[a-z]:|shutdown|reboot)\b"), "destructive command"),
    (re.compile(r"(?i)\b(curl|wget|Invoke-WebRequest|iwr)\b.*\b(token|secret|key|password|upload|webhook|http)\b"), "network exfiltration"),
    (re.compile(r"(?i)(\.\./|~/.ssh|/etc/passwd|id_rsa|\.env|AppData\\Roaming)"), "sensitive path access"),
    (re.compile(r"(?i)\b(printenv|Get-ChildItem\s+Env:|set\s*\|\s*findstr)"), "environment enumeration"),
]


def detect_tool_call_risks(tool_calls: list[ToolCall], allowed_tools: set[str] | None = None) -> list[SecurityFinding]:
    allowed_tools = allowed_tools or set()
    findings: list[SecurityFinding] = []
    for call in tool_calls:
        serialized = _serialize_arguments(call.arguments)
        normalized = normalize_text(serialized)
        signals = [name for pattern, name in DANGEROUS_ARGUMENT_PATTERNS if pattern.search(normalized)]
        unlisted = bool(allowed_tools and call.name not in allowed_tools)
        if not signals and not unlisted:
            continue
        score = min(1.0, 0.35 + 0.22 * len(signals) + (0.3 if unlisted else 0.0))
        risk = RiskLevel.CRITICAL if any("destructive" in signal for signal in signals) else RiskLevel.HIGH
        findings.append(
            SecurityFinding(
                rule_id="ZTR-001",
                title="Unsafe agent tool call",
                stage=PipelineStage.TOOL_CALL,
                risk=risk,
                action=Action.BLOCK if risk == RiskLevel.CRITICAL else Action.REQUIRE_APPROVAL,
                score=score,
                evidence=excerpt(f"{call.name} {serialized}"),
                owasp=["LLM02:2025", "LLM06:2025"],
                mitre_atlas=["AML.T0052", "AML.T0057"],
                metadata={
                    "tool": call.name,
                    "server": call.server,
                    "call_id": call.call_id,
                    "signals": signals,
                    "allowlist_miss": unlisted,
                },
            )
        )
    return findings


def _serialize_arguments(arguments: dict[str, Any]) -> str:
    return " ".join(f"{key}={value}" for key, value in sorted(arguments.items()))
