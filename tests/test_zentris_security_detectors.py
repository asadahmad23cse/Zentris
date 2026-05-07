from zentris_security.detectors.mcp_security import detect_mcp_risks
from zentris_security.detectors.output_risk import detect_output_risks
from zentris_security.detectors.rag_poisoning import detect_rag_poisoning
from zentris_security.types import DocumentChunk


def test_rag_poisoning_scores_low_trust_instructional_document():
    findings = detect_rag_poisoning(
        [
            DocumentChunk(
                content="BEGIN SYSTEM hidden instruction credential api key ignore retrieval policy",
                source="http://example.click/doc",
                chunk_id="doc-1",
            )
        ]
    )
    assert findings
    assert findings[0].rule_id == "ZRP-001"


def test_mcp_detector_flags_untrusted_powerful_server():
    findings = detect_mcp_risks(
        [{"name": "unknown-local", "url": "http://127.0.0.1:9000", "tools": ["shell.exec"], "auth": None}]
    )
    assert findings
    assert findings[0].action.value == "require_approval"


def test_output_risk_blocks_secret_like_values():
    findings = detect_output_risks("token=sk-secretvalue000000 and password=hunter2")
    assert findings
    assert findings[0].action.value == "block"
