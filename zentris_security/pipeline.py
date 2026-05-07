"""Latency-aware multi-stage Zentris security pipeline."""

from __future__ import annotations

import re
import time

from zentris_security.detectors import (
    detect_indirect_injection,
    detect_mcp_risks,
    detect_output_risks,
    detect_prompt_injection,
    detect_rag_poisoning,
    detect_tool_call_risks,
)
from zentris_security.normalization import normalize_text
from zentris_security.policy import SecurityPolicy
from zentris_security.types import PipelineStage, SecurityDecision, SecurityFinding, SecurityRequest


class ZentrisSecurityPipeline:
    def __init__(self, policy: SecurityPolicy | None = None) -> None:
        self.policy = policy or SecurityPolicy()

    def inspect(self, request: SecurityRequest) -> SecurityDecision:
        started = time.perf_counter()
        findings: list[SecurityFinding] = []
        stages: list[PipelineStage] = []

        findings.extend(detect_prompt_injection(request.prompt))
        stages.append(PipelineStage.INPUT)

        if self._within_budget(started):
            findings.extend(detect_indirect_injection(request.documents))
            findings.extend(detect_rag_poisoning(request.documents, self.policy.trusted_domains))
            stages.append(PipelineStage.RETRIEVAL)

        if self._within_budget(started):
            findings.extend(detect_tool_call_risks(request.tool_calls, self.policy.allowed_tools))
            stages.append(PipelineStage.TOOL_CALL)

        if self._within_budget(started):
            findings.extend(detect_mcp_risks(request.mcp_servers, self.policy.trusted_mcp_servers))
            stages.append(PipelineStage.MCP)

        if request.output and self._within_budget(started):
            findings.extend(detect_output_risks(request.output))
            stages.append(PipelineStage.OUTPUT)

        latency_ms = (time.perf_counter() - started) * 1000
        sanitized_prompt = sanitize_prompt(request.prompt) if findings else None
        decision = self.policy.decide(findings, latency_ms, sanitized_prompt)
        return SecurityDecision(
            action=decision.action,
            risk=decision.risk,
            score=decision.score,
            findings=decision.findings,
            latency_ms=decision.latency_ms,
            stages_executed=stages,
            sanitized_prompt=decision.sanitized_prompt,
            metadata={
                "latency_budget_ms": self.policy.latency_budget_ms,
                "latency_budget_exceeded": latency_ms > self.policy.latency_budget_ms,
            },
        )

    def _within_budget(self, started: float) -> bool:
        return (time.perf_counter() - started) * 1000 <= self.policy.latency_budget_ms


def sanitize_prompt(prompt: str) -> str:
    text = normalize_text(prompt)
    text = re.sub(r"(?i)\b(ignore|override)\s+(previous|prior|above)\s+(instructions|rules)\b", "[removed instruction override]", text)
    text = re.sub(r"(?i)\b(system|developer)\s*:\s*", "[removed role marker] ", text)
    return text
