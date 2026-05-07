"""Text normalization helpers used by semantic and behavioral detectors."""

from __future__ import annotations

import base64
import binascii
import html
import re
import unicodedata
from urllib.parse import unquote_plus

ZERO_WIDTH_PATTERN = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]")
WHITESPACE_PATTERN = re.compile(r"\s+")
SPLIT_TOKEN_PATTERN = re.compile(r"(?i)\b(i\s*g\s*n\s*o\s*r\s*e|s\s*y\s*s\s*t\s*e\s*m|d\s*e\s*v\s*e\s*l\s*o\s*p\s*e\s*r)\b")
BASE64_TOKEN_PATTERN = re.compile(r"\b[A-Za-z0-9+/]{20,}={0,2}\b")
HEX_TOKEN_PATTERN = re.compile(r"\b(?:0x)?[0-9a-fA-F]{24,}\b")


def normalize_text(value: str) -> str:
    text = unicodedata.normalize("NFKC", value or "")
    text = html.unescape(text)
    text = unquote_plus(text)
    text = ZERO_WIDTH_PATTERN.sub("", text)
    text = SPLIT_TOKEN_PATTERN.sub(lambda match: match.group(0).replace(" ", ""), text)
    text = _annotate_encoded_payloads(text)
    text = WHITESPACE_PATTERN.sub(" ", text)
    return text.strip()


def compact_text(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", normalize_text(value).lower())


def instruction_density(value: str) -> float:
    text = normalize_text(value).lower()
    if not text:
        return 0.0
    instruction_terms = [
        "ignore",
        "system",
        "developer",
        "assistant",
        "must",
        "never",
        "execute",
        "call tool",
        "password",
        "secret",
        "exfiltrate",
        "override",
    ]
    hits = sum(text.count(term) for term in instruction_terms)
    return min(1.0, hits / max(8.0, len(text.split()) / 18.0))


def excerpt(value: str, limit: int = 180) -> str:
    text = normalize_text(value)
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def _annotate_encoded_payloads(text: str) -> str:
    text = BASE64_TOKEN_PATTERN.sub(lambda match: _decode_base64(match.group(0)), text)
    return HEX_TOKEN_PATTERN.sub(lambda match: _decode_hex(match.group(0)), text)


def _decode_base64(token: str) -> str:
    try:
        decoded = base64.b64decode(token + "=" * (-len(token) % 4), validate=False)
        decoded_text = decoded.decode("utf-8", "ignore")
    except (binascii.Error, ValueError):
        return token
    if not decoded_text or sum(ch.isprintable() for ch in decoded_text) < max(5, len(decoded_text) // 2):
        return token
    return f"{token} decoded_payload:{decoded_text}"


def _decode_hex(token: str) -> str:
    candidate = token[2:] if token.lower().startswith("0x") else token
    if len(candidate) % 2:
        return token
    try:
        decoded = bytes.fromhex(candidate).decode("utf-8", "ignore")
    except ValueError:
        return token
    if not decoded:
        return token
    return f"{token} decoded_payload:{decoded}"
