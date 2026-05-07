"""MCP server and tool exposure security checks."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from zentris_security.types import Action, PipelineStage, RiskLevel, SecurityFinding

POWERFUL_TOOL_PATTERN = re.compile(r"(?i)(shell|terminal|exec|file|filesystem|browser|network|http|secrets?|env)")


def detect_mcp_risks(servers: list[dict], trusted_servers: set[str] | None = None) -> list[SecurityFinding]:
    trusted_servers = trusted_servers or set()
    findings: list[SecurityFinding] = []
    for server in servers:
        name = str(server.get("name") or server.get("server_name") or "unknown")
        url = str(server.get("url") or server.get("endpoint") or "")
        tools = [str(tool) for tool in server.get("tools", [])]
        signals: list[str] = []
        if name not in trusted_servers:
            signals.append("untrusted server")
        if url and _url_risky(url):
            signals.append("risky endpoint")
        if not server.get("auth") and url.startswith(("http://", "https://")):
            signals.append("missing auth")
        powerful_tools = [tool for tool in tools if POWERFUL_TOOL_PATTERN.search(tool)]
        if powerful_tools:
            signals.append("powerful tools exposed")
        if not signals:
            continue
        score = min(0.84, 0.25 + 0.14 * len(signals) + 0.05 * len(powerful_tools))
        findings.append(
            SecurityFinding(
                rule_id="ZMC-001",
                title="MCP server exposure risk",
                stage=PipelineStage.MCP,
                risk=RiskLevel.HIGH if score >= 0.72 else RiskLevel.MEDIUM,
                action=Action.REQUIRE_APPROVAL,
                score=score,
                evidence=f"{name} {url}".strip(),
                owasp=["LLM06:2025", "LLM07:2025"],
                mitre_atlas=["AML.T0052", "AML.T0049"],
                metadata={"server": name, "signals": signals, "powerful_tools": powerful_tools},
            )
        )
    return findings


def _url_risky(url: str) -> bool:
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    return parsed.scheme == "http" or hostname in {"localhost", "127.0.0.1", "0.0.0.0"} or hostname.endswith(".local")
