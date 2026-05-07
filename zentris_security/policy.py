"""Zentris policy engine for converting findings into enforcement actions."""

from __future__ import annotations

from dataclasses import dataclass, field

from zentris_security.types import Action, RiskLevel, SecurityDecision, SecurityFinding

ACTION_ORDER = {
    Action.ALLOW: 0,
    Action.SANITIZE: 1,
    Action.REQUIRE_APPROVAL: 2,
    Action.BLOCK: 3,
}

RISK_ORDER = {
    RiskLevel.NONE: 0,
    RiskLevel.LOW: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.HIGH: 3,
    RiskLevel.CRITICAL: 4,
}


@dataclass
class SecurityPolicy:
    block_threshold: float = 0.86
    approval_threshold: float = 0.68
    sanitize_threshold: float = 0.45
    latency_budget_ms: float = 60.0
    allowed_tools: set[str] = field(default_factory=set)
    trusted_domains: set[str] = field(default_factory=set)
    trusted_mcp_servers: set[str] = field(default_factory=set)

    def decide(self, findings: list[SecurityFinding], latency_ms: float, sanitized_prompt: str | None = None) -> SecurityDecision:
        if not findings:
            return SecurityDecision(
                action=Action.ALLOW,
                risk=RiskLevel.NONE,
                score=0.0,
                findings=[],
                latency_ms=latency_ms,
                sanitized_prompt=sanitized_prompt,
            )

        max_score = max(finding.score for finding in findings)
        risk = max((finding.risk for finding in findings), key=lambda item: RISK_ORDER[item])
        action = max((finding.action for finding in findings), key=lambda item: ACTION_ORDER[item])

        if max_score >= self.block_threshold or risk == RiskLevel.CRITICAL:
            action = Action.BLOCK
        elif max_score >= self.approval_threshold and action != Action.BLOCK:
            action = Action.REQUIRE_APPROVAL
        elif max_score >= self.sanitize_threshold and action == Action.ALLOW:
            action = Action.SANITIZE

        return SecurityDecision(
            action=action,
            risk=risk,
            score=round(max_score, 3),
            findings=sorted(findings, key=lambda finding: finding.score, reverse=True),
            latency_ms=latency_ms,
            sanitized_prompt=sanitized_prompt,
        )
