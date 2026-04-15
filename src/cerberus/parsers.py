"""Regex-driven think and JSON parser for Cerberus AI LLM responses.

The model is expected to emit a ``<think>...</think>`` block followed by one
JSON object. This module extracts both components defensively while preserving
the raw response so callers can render the thought block separately from the
visible action payload.
"""

from __future__ import annotations

import ast
import json
import re
from typing import Any

try:
    from json_repair import repair_json as _repair_json  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    _repair_json = None

# ---------------------------------------------------------------------------
# Self-correction payload
# ---------------------------------------------------------------------------

_SELF_CORRECTION_PAYLOAD: dict[str, Any] = {
    "status": "error",
    "message": (
        "Unable to determine next action. "
        "Provide a <think>...</think> block followed by one valid JSON object."
    ),
}

_FORMAT_CORRECTION_MESSAGE = (
    "ERROR: Format Violation. You MUST start with <think> and end with JSON. "
    "Do not provide conversational text."
)

_TRAILING_COMMA_RE = re.compile(r",\s*([}\]])")


def _strip_json_noise(raw_text: str) -> str:
    """Remove common markdown and anchor noise from a JSON-like payload."""
    cleaned = raw_text.strip()
    cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\s*```$", "", cleaned)
    cleaned = re.sub(
        r"^(?:JSON_PREVIEW|COMMITTING_JSON)\s*:\s*",
        "",
        cleaned,
        flags=re.IGNORECASE,
    )
    return cleaned.strip().strip("`").strip()


def _normalize_common_json_issues(raw_text: str) -> str:
    """Repair a minimal set of common JSON issues without changing semantics."""
    normalized = _strip_json_noise(raw_text)
    normalized = normalized.replace("\r\n", "\n").replace("\r", "\n")
    normalized = _TRAILING_COMMA_RE.sub(r"\1", normalized)
    normalized = re.sub(r"\bNone\b", "null", normalized)
    normalized = re.sub(r"\bTrue\b", "true", normalized)
    normalized = re.sub(r"\bFalse\b", "false", normalized)
    return normalized.strip()


def _extract_balanced_json_fragments(raw_text: str) -> list[str]:
    """Return balanced JSON-like fragments from free-form text."""
    fragments: list[str] = []
    stack: list[str] = []
    start_index: int | None = None
    quote_char: str | None = None
    escaping = False

    for index, char in enumerate(raw_text):
        if quote_char is not None:
            if escaping:
                escaping = False
                continue
            if char == "\\":
                escaping = True
                continue
            if char == quote_char:
                quote_char = None
            continue

        if char in {'"', "'"}:
            quote_char = char
            continue

        if char in "[{":
            if not stack:
                start_index = index
            stack.append("}" if char == "{" else "]")
            continue

        if char in "}]" and stack and char == stack[-1]:
            stack.pop()
            if not stack and start_index is not None:
                fragments.append(raw_text[start_index : index + 1])
                start_index = None

    return fragments


def _json_candidate_strings(raw_text: str, *, prefer_last: bool) -> list[str]:
    """Build de-duplicated candidate JSON payload strings from noisy text."""
    candidates: list[str] = []

    stripped = _strip_json_noise(raw_text)
    if stripped:
        candidates.append(stripped)

    for line in raw_text.splitlines():
        cleaned_line = _strip_json_noise(line)
        if cleaned_line and cleaned_line != stripped:
            candidates.append(cleaned_line)

    fragments = _extract_balanced_json_fragments(raw_text)
    if prefer_last:
        fragments = list(reversed(fragments))
    for fragment in fragments:
        cleaned_fragment = _strip_json_noise(fragment)
        if cleaned_fragment:
            candidates.append(cleaned_fragment)

    deduped: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        if candidate not in seen:
            deduped.append(candidate)
            seen.add(candidate)

    return deduped


def _repair_json_candidate(raw_text: str) -> Any:
    """Try optional json-repair support when available."""
    if _repair_json is None:
        raise ValueError("json_repair unavailable")

    try:
        return _repair_json(raw_text, return_objects=True)
    except TypeError:
        repaired_text = _repair_json(raw_text)
        return json.loads(repaired_text)


def parse_json_lenient(raw_text: str, *, prefer_last: bool = False) -> Any:
    """Parse JSON-like text while tolerating fences, prose bleed, and trailing commas."""
    if not isinstance(raw_text, str) or not raw_text.strip():
        raise ValueError("Empty JSON payload")

    last_error: Exception | None = None
    for candidate in _json_candidate_strings(raw_text, prefer_last=prefer_last):
        try:
            return json.loads(candidate)
        except Exception as exc:
            last_error = exc

        try:
            return _repair_json_candidate(candidate)
        except Exception as exc:
            last_error = exc

        try:
            return ast.literal_eval(candidate)
        except Exception as exc:
            last_error = exc

        normalized = _normalize_common_json_issues(candidate)
        if normalized and normalized != candidate:
            try:
                return json.loads(normalized)
            except Exception as exc:
                last_error = exc

            try:
                return _repair_json_candidate(normalized)
            except Exception as exc:
                last_error = exc

            try:
                return ast.literal_eval(normalized)
            except Exception as exc:
                last_error = exc

    raise ValueError(f"Unable to parse JSON payload: {last_error or 'unknown error'}")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def strip_think_block(raw_output: str) -> str:
    """Remove the first ``<think>...</think>`` block from model output."""
    if not isinstance(raw_output, str):
        return ""
    return re.sub(r"<think>.*?</think>", "", raw_output, count=1, flags=re.DOTALL).strip()


def parse_response(raw_output: str) -> dict[str, Any]:
    """Extract ``thought``, ``action``, and ``raw`` safely from model output."""
    if not isinstance(raw_output, str) or not raw_output.strip():
        return {
            "thought": "",
            "action": _SELF_CORRECTION_PAYLOAD.copy(),
            "action_json": _SELF_CORRECTION_PAYLOAD.copy(),
            "has_think_block": False,
            "has_valid_json_object": False,
            "format_violation": True,
            "format_error": "missing_think_and_json",
            "format_correction_message": _FORMAT_CORRECTION_MESSAGE,
            "raw": "",
            "visible_text": "",
        }

    think_match = re.search(r"<think>(.*?)</think>", raw_output, re.DOTALL)
    thought = think_match.group(1).strip() if think_match else ""
    has_think_block = think_match is not None

    visible_text = strip_think_block(raw_output)
    json_source = visible_text or raw_output
    json_candidates = _json_candidate_strings(json_source, prefer_last=True)
    has_valid_json_object = False
    format_error: str | None = None

    if not json_candidates:
        if not has_think_block:
            format_error = "missing_think_and_json"
        else:
            format_error = "missing_valid_json"
        return {
            "thought": thought,
            "action": _SELF_CORRECTION_PAYLOAD.copy(),
            "action_json": _SELF_CORRECTION_PAYLOAD.copy(),
            "has_think_block": has_think_block,
            "has_valid_json_object": False,
            "format_violation": True,
            "format_error": format_error,
            "format_correction_message": _FORMAT_CORRECTION_MESSAGE,
            "raw": raw_output,
            "visible_text": visible_text,
        }

    action_blob = json_candidates[0].strip()
    try:
        action_json = parse_json_lenient(action_blob, prefer_last=True)
        if not isinstance(action_json, dict):
            format_error = "invalid_json_object"
            action_json = {
                **_SELF_CORRECTION_PAYLOAD,
                "message": "Unable to determine next action.",
                "raw_action_json": action_blob,
            }
        else:
            has_valid_json_object = True
    except ValueError as exc:
        format_error = "invalid_json"
        action_json = {
            **_SELF_CORRECTION_PAYLOAD,
            "message": "Unable to determine next action.",
            "raw_action_json": action_blob,
            "parse_error": str(exc),
        }

    if not has_think_block:
        format_error = "missing_think_block"

    format_violation = (not has_think_block) or (not has_valid_json_object)

    return {
        "thought": thought,
        "action": action_json,
        "action_json": action_json,
        "has_think_block": has_think_block,
        "has_valid_json_object": has_valid_json_object,
        "format_violation": format_violation,
        "format_error": format_error,
        "format_correction_message": _FORMAT_CORRECTION_MESSAGE if format_violation else "",
        "raw": raw_output,
        "visible_text": visible_text,
    }


def parse_action(text: str) -> dict[str, Any]:
    """Backward-compatible wrapper returning only the extracted action JSON."""
    parsed = parse_response(text)
    action_json = parsed.get("action_json")
    return action_json if isinstance(action_json, dict) else _SELF_CORRECTION_PAYLOAD.copy()


def extract_think_block(text: str) -> str | None:
    """Backward-compatible wrapper returning the first think block, if present."""
    thought = parse_response(text).get("thought", "")
    return thought or None


__all__ = [
    "extract_think_block",
    "parse_action",
    "parse_json_lenient",
    "parse_response",
    "strip_think_block",
]
