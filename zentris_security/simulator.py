"""Red-team simulator for regression testing Zentris policies."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from zentris_security.pipeline import ZentrisSecurityPipeline
from zentris_security.types import Action, DocumentChunk, SecurityRequest, ToolCall


@dataclass(frozen=True)
class SimulationResult:
    total: int
    passed: int
    blocked: int
    sanitized: int
    approval_required: int
    failures: list[dict[str, Any]]

    @property
    def pass_rate(self) -> float:
        if self.total == 0:
            return 0.0
        return round(self.passed / self.total, 4)


def run_attack_simulation(path: str | Path, pipeline: ZentrisSecurityPipeline | None = None) -> SimulationResult:
    runtime = pipeline or ZentrisSecurityPipeline()
    cases = json.loads(Path(path).read_text(encoding="utf-8"))
    passed = 0
    blocked = 0
    sanitized = 0
    approval_required = 0
    failures: list[dict[str, Any]] = []

    for case in cases:
        decision = runtime.inspect(_request_from_case(case))
        expected = Action(case["expected_action"])
        if decision.action == Action.BLOCK:
            blocked += 1
        elif decision.action == Action.SANITIZE:
            sanitized += 1
        elif decision.action == Action.REQUIRE_APPROVAL:
            approval_required += 1
        if decision.action == expected:
            passed += 1
        else:
            failures.append(
                {
                    "id": case["id"],
                    "expected_action": expected.value,
                    "actual_action": decision.action.value,
                    "risk": decision.risk.value,
                    "score": decision.score,
                    "findings": [asdict(finding) for finding in decision.findings],
                }
            )

    return SimulationResult(
        total=len(cases),
        passed=passed,
        blocked=blocked,
        sanitized=sanitized,
        approval_required=approval_required,
        failures=failures,
    )


def _request_from_case(case: dict[str, Any]) -> SecurityRequest:
    return SecurityRequest(
        prompt=case.get("prompt", ""),
        documents=[DocumentChunk(**document) for document in case.get("documents", [])],
        tool_calls=[ToolCall(**tool_call) for tool_call in case.get("tool_calls", [])],
        mcp_servers=case.get("mcp_servers", []),
        output=case.get("output", ""),
    )
