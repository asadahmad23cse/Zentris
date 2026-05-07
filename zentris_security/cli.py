"""Command line entrypoints for Zentris security scanning and simulation."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from zentris_security.pipeline import ZentrisSecurityPipeline
from zentris_security.simulator import run_attack_simulation
from zentris_security.types import DocumentChunk, SecurityContext, SecurityRequest, ToolCall


def main() -> int:
    parser = argparse.ArgumentParser(description="Zentris AI security runtime CLI")
    subcommands = parser.add_subparsers(dest="command", required=True)

    scan = subcommands.add_parser("scan", help="Inspect a prompt/request JSON payload")
    scan.add_argument("payload", help="Path to JSON payload or '-' for stdin")

    simulate = subcommands.add_parser("simulate", help="Run red-team benchmark cases")
    simulate.add_argument("cases", help="Path to red-team JSON cases")

    args = parser.parse_args()
    if args.command == "scan":
        payload = _read_json(args.payload)
        decision = ZentrisSecurityPipeline().inspect(_request_from_payload(payload))
        print(json.dumps(asdict(decision), default=_json_default, indent=2, sort_keys=True))
        return 0 if decision.action.value != "block" else 2
    if args.command == "simulate":
        result = run_attack_simulation(args.cases)
        print(json.dumps(asdict(result), default=_json_default, indent=2, sort_keys=True))
        return 0 if not result.failures else 1
    return 1


def _read_json(path: str) -> dict[str, Any]:
    if path == "-":
        import sys

        return json.load(sys.stdin)
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _request_from_payload(payload: dict[str, Any]) -> SecurityRequest:
    return SecurityRequest(
        prompt=payload.get("prompt", ""),
        documents=[DocumentChunk(**item) for item in payload.get("documents", [])],
        tool_calls=[ToolCall(**item) for item in payload.get("tool_calls", [])],
        mcp_servers=payload.get("mcp_servers", []),
        output=payload.get("output", ""),
        context=SecurityContext(**payload.get("context", {})),
    )


def _json_default(value: Any) -> Any:
    if hasattr(value, "value"):
        return value.value
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


if __name__ == "__main__":
    raise SystemExit(main())
