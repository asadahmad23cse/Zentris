"""Detector registry for Zentris security stages."""

from .indirect_injection import detect_indirect_injection
from .mcp_security import detect_mcp_risks
from .output_risk import detect_output_risks
from .prompt_injection import detect_prompt_injection
from .rag_poisoning import detect_rag_poisoning
from .tool_runtime import detect_tool_call_risks

__all__ = [
    "detect_indirect_injection",
    "detect_mcp_risks",
    "detect_output_risks",
    "detect_prompt_injection",
    "detect_rag_poisoning",
    "detect_tool_call_risks",
]
