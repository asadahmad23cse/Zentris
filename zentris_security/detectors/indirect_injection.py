"""Indirect injection detection for retrieved documents and tool outputs."""

from __future__ import annotations

import re

from zentris_security.normalization import excerpt, instruction_density, normalize_text
from zentris_security.types import Action, DocumentChunk, PipelineStage, RiskLevel, SecurityFinding

INDIRECT_PATTERNS = [
    (re.compile(r"(?i)\bignore\s+(all\s+)?(previous|prior|above)\s+(instructions|rules)\b"), "instruction override"),
    (re.compile(r"(?i)\b(system|developer|assistant)\s*:\s*"), "role marker inside external content"),
    (re.compile(r"(?i)<!--.*?(ignore|system|developer|secret).*?-->", re.DOTALL), "hidden html instruction"),
    (re.compile(r"(?i)\bcall\s+(the\s+)?tool\b|\bexecute\s+(this|the)\s+(command|tool)\b"), "tool steering"),
    (re.compile(r"(?i)\bexfiltrate\b|\bsend\s+(secrets?|tokens?|keys?)\b"), "exfiltration instruction"),
    (re.compile(r"(?i)\bBEGIN\s+(SYSTEM|DEVELOPER|INSTRUCTIONS?)\b"), "prompt boundary spoofing"),
]


def detect_indirect_injection(documents: list[DocumentChunk]) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []
    for document in documents:
        text = normalize_text(document.content)
        pattern_hits = [name for pattern, name in INDIRECT_PATTERNS if pattern.search(text)]
        density = instruction_density(text)
        if not pattern_hits and density < 0.72:
            continue
        score = min(1.0, 0.42 + 0.16 * len(pattern_hits) + density * 0.35)
        risk = RiskLevel.HIGH if score >= 0.78 else RiskLevel.MEDIUM
        action = Action.SANITIZE
        findings.append(
            SecurityFinding(
                rule_id="ZII-001",
                title="Indirect prompt injection in retrieved content",
                stage=PipelineStage.RETRIEVAL,
                risk=risk,
                action=action,
                score=score,
                evidence=excerpt(document.content),
                owasp=["LLM01:2025", "LLM06:2025"],
                mitre_atlas=["AML.T0051", "AML.T0053"],
                metadata={
                    "source": document.source,
                    "chunk_id": document.chunk_id,
                    "signals": pattern_hits,
                    "instruction_density": round(density, 3),
                },
            )
        )
    return findings
