"""Prompt injection adapter around the Zentris hook detector."""

from __future__ import annotations

from hooks.prompt_injection_detection import detect_prompt_injection as hook_detect

from zentris_security.normalization import excerpt
from zentris_security.types import Action, PipelineStage, RiskLevel, SecurityFinding

RISK_MAP = {
    "none": RiskLevel.NONE,
    "low": RiskLevel.LOW,
    "medium": RiskLevel.MEDIUM,
    "high": RiskLevel.HIGH,
    "critical": RiskLevel.CRITICAL,
}

ACTION_MAP = {
    "allow": Action.ALLOW,
    "sanitize": Action.SANITIZE,
    "block": Action.BLOCK,
}


def detect_prompt_injection(prompt: str) -> list[SecurityFinding]:
    result = hook_detect(prompt)
    if result.action == "allow" and not result.matched_rules:
        return []
    risk = RISK_MAP.get(result.risk, RiskLevel.MEDIUM)
    action = ACTION_MAP.get(result.action, Action.REQUIRE_APPROVAL)
    return [
        SecurityFinding(
            rule_id="ZPI-001",
            title="Direct prompt injection detected",
            stage=PipelineStage.INPUT,
            risk=risk,
            action=action,
            score=min(1.0, result.score / 100),
            evidence=excerpt(prompt),
            owasp=["LLM01:2025"],
            mitre_atlas=["AML.T0051", "AML.T0054"],
            metadata={
                "confidence": result.confidence,
                "hook_rules": result.matched_rules,
                "reasons": result.reasons,
            },
        )
    ]
