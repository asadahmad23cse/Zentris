"""RAG poisoning and retrieval integrity checks."""

from __future__ import annotations

from urllib.parse import urlparse

from zentris_security.normalization import excerpt, instruction_density, normalize_text
from zentris_security.types import Action, DocumentChunk, PipelineStage, RiskLevel, SecurityFinding

LOW_TRUST_TLDS = {".zip", ".mov", ".click", ".country", ".gq", ".tk"}
POISON_MARKERS = [
    "ignore retrieval policy",
    "system prompt",
    "developer message",
    "hidden instruction",
    "credential",
    "api key",
    "BEGIN SYSTEM",
    "BEGIN DEVELOPER",
]


def detect_rag_poisoning(documents: list[DocumentChunk], trusted_domains: set[str] | None = None) -> list[SecurityFinding]:
    trusted_domains = trusted_domains or set()
    findings: list[SecurityFinding] = []
    for document in documents:
        text = normalize_text(document.content)
        lower = text.lower()
        markers = [marker for marker in POISON_MARKERS if marker.lower() in lower]
        domain_risk = _domain_risk(document.source, trusted_domains)
        density = instruction_density(text)
        score = min(1.0, 0.2 + 0.14 * len(markers) + 0.24 * domain_risk + 0.4 * density)
        if score < 0.55:
            continue
        risk = RiskLevel.HIGH if score >= 0.8 else RiskLevel.MEDIUM
        findings.append(
            SecurityFinding(
                rule_id="ZRP-001",
                title="Potential RAG poisoning artifact",
                stage=PipelineStage.RETRIEVAL,
                risk=risk,
                action=Action.SANITIZE,
                score=score,
                evidence=excerpt(document.content),
                owasp=["LLM08:2025", "LLM10:2025"],
                mitre_atlas=["AML.T0053", "AML.T0048"],
                metadata={
                    "source": document.source,
                    "chunk_id": document.chunk_id,
                    "markers": markers,
                    "domain_risk": domain_risk,
                    "instruction_density": round(density, 3),
                },
            )
        )
    return findings


def _domain_risk(source: str, trusted_domains: set[str]) -> float:
    parsed = urlparse(source)
    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return 0.25
    if hostname in trusted_domains or any(hostname.endswith("." + domain) for domain in trusted_domains):
        return 0.0
    if any(hostname.endswith(tld) for tld in LOW_TRUST_TLDS):
        return 1.0
    if parsed.scheme not in {"https", "file"}:
        return 0.75
    return 0.35
