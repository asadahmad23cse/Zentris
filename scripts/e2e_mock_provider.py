"""Internal OpenAI-compatible provider used only by the Compose E2E profile."""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any, AsyncIterator

from fastapi import FastAPI, HTTPException
from fastapi.responses import StreamingResponse

app = FastAPI(title="Zentris E2E provider", docs_url=None, redoc_url=None)
_last_request: dict[str, Any] = {}
_counter = 0


def _next_id() -> str:
    global _counter
    _counter += 1
    return f"chatcmpl-zentris-e2e-{_counter}"


def _joined_content(payload: dict[str, Any]) -> str:
    values: list[str] = []
    for message in payload.get("messages", []):
        content = message.get("content") if isinstance(message, dict) else None
        if isinstance(content, str):
            values.append(content)
    return "\n".join(values)


def _output_parts(prompt: str) -> list[str]:
    if "OUTPUT_SECRET_TEST" in prompt:
        # Deliberately split the candidate across chunks to exercise the
        # gateway's cross-chunk DLP state without storing a real credential.
        return ["Synthetic output: sk-proj-", "A" * 64, " complete"]
    if "LONG_STREAM_TEST" in prompt:
        # Each part is larger than the gateway's bounded DLP overlap window,
        # proving that safe output is delivered incrementally while a suffix is
        # retained for cross-chunk candidate detection.
        return ["alpha " * 160, "beta " * 160, "gamma " * 160]
    return ["ZENTRIS", "_", "OK"]


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/last-request")
async def last_request() -> dict[str, Any]:
    return _last_request


@app.post("/v1/chat/completions")
async def chat_completions(payload: dict[str, Any]) -> Any:
    global _last_request
    _last_request = payload
    prompt = _joined_content(payload)
    if "PROVIDER_FAILURE_TEST" in prompt:
        raise HTTPException(status_code=503, detail="controlled_e2e_provider_failure")

    completion_id = _next_id()
    created = int(time.time())
    model = str(payload.get("model") or "e2e-model")
    parts = _output_parts(prompt)
    if payload.get("stream") is not True:
        return {
            "id": completion_id,
            "object": "chat.completion",
            "created": created,
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "".join(parts)},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 11, "completion_tokens": 3, "total_tokens": 14},
        }

    async def events() -> AsyncIterator[str]:
        for index, part in enumerate(parts):
            chunk = {
                "id": completion_id,
                "object": "chat.completion.chunk",
                "created": created,
                "model": model,
                "choices": [
                    {
                        "index": 0,
                        "delta": {"role": "assistant", "content": part}
                        if index == 0
                        else {"content": part},
                        "finish_reason": None,
                    }
                ],
            }
            yield f"data: {json.dumps(chunk, separators=(',', ':'))}\n\n"
            await asyncio.sleep(0.03)
        final = {
            "id": completion_id,
            "object": "chat.completion.chunk",
            "created": created,
            "model": model,
            "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 11, "completion_tokens": 3, "total_tokens": 14},
        }
        yield f"data: {json.dumps(final, separators=(',', ':'))}\n\n"
        yield "data: [DONE]\n\n"

    return StreamingResponse(events(), media_type="text/event-stream")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8080, log_level="warning")
