"""Model output risk scoring and leakage detection."""

from __future__ import annotations

import re

from zentris_security.normalization import excerpt, normalize_text
from zentris_security.types import Action, PipelineStage, RiskLevel, SecurityFinding

OUTPUT_PATTERNS = [
    (re.compile(r"sk-[A-Za-z0-9_-]{12,}"), "api key pattern", RiskLevel.CRITICAL),
    (re.compile(r"(?i)\b(system|developer)\s+prompt\b.*\b(is|was)\b"), "system prompt leakage", RiskLevel.HIGH),
    (re.compile(r"(?i)\bBEGIN\s+(SYSTEM|DEVELOPER)\b"), "prompt boundary leakage", RiskLevel.HIGH),
    (re.compile(r"(?i)\b(password|secret|token)\s*[:=]\s*\S+"), "credential disclosure", RiskLevel.CRITICAL),
    (re.compile(r"(?i)\b(rm\s+-rf|format\s+[a-z]:|delete\s+all\s+files)\b"), "destructive instruction", RiskLevel.HIGH),
]


def detect_output_risks(output: str) -> list[SecurityFinding]:
    normalized = normalize_text(output)
    findings: list[SecurityFinding] = []
    for pattern, signal, risk in OUTPUT_PATTERNS:
        match = pattern.search(normalized)
        if not match:
            continue
        findings.append(
            SecurityFinding(
                rule_id="ZOR-001",
                title="Unsafe model output",
                stage=PipelineStage.OUTPUT,
                risk=risk,
                action=Action.BLOCK if risk == RiskLevel.CRITICAL else Action.SANITIZE,
                score=0.92 if risk == RiskLevel.CRITICAL else 0.78,
                evidence=excerpt(match.group(0)),
                owasp=["LLM02:2025", "LLM06:2025"],
                mitre_atlas=["AML.T0054", "AML.T0057"],
                metadata={"signal": signal},
            )
        )
    return findings
