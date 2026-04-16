"""Utility parsers for extracting and repairing JSON from noisy LLM output.

Functions here are intentionally dependency-light so they can be imported
from any layer of the stack without risk of circular imports.
"""

from __future__ import annotations

import json
import re
from typing import Any


# ---------------------------------------------------------------------------
# JSON extraction
# ---------------------------------------------------------------------------


def find_json_in_text(raw_text: str) -> dict[str, Any] | None:
    """Attempt to extract a JSON object from text that may contain surrounding noise.

    Uses brace-depth tracking to locate the outermost ``{...}`` block and
    then attempts strict JSON parsing followed by bracket-completion repair.
    Returns the first successfully parsed dict, or ``None`` if nothing
    parseable is found.

    Examples of inputs handled correctly:
    - Clean JSON: ``{"key": "value"}``
    - Wrapped in prose: ``Here is the call: {"tool": "ping"} done.``
    - Truncated tail: ``{"host": "localhost"`` (missing closing brace)
    - LLM noise tokens around valid JSON
    """
    if not raw_text or not isinstance(raw_text, str):
        return None

    candidates = _extract_json_candidates(raw_text)
    for candidate in candidates:
        result = _try_parse_dict(candidate)
        if result is not None:
            return result

        # Try bracket completion before giving up on this candidate.
        completed = _close_incomplete_json(candidate)
        if completed and completed != candidate:
            result = _try_parse_dict(completed)
            if result is not None:
                return result

    return None


def close_incomplete_json(raw: str) -> str | None:
    """Attempt to close an incomplete JSON string by adding missing brackets/quotes.

    Returns the repaired string on success, or ``None`` if the input cannot be
    meaningfully closed (e.g. it contains no opening brace at all).
    """
    return _close_incomplete_json(raw)


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _extract_json_candidates(text: str) -> list[str]:
    """Return a list of potential JSON object substrings, longest-first."""
    candidates: list[str] = []
    length = len(text)
    i = 0
    while i < length:
        if text[i] != "{":
            i += 1
            continue

        depth = 0
        in_string = False
        escape_next = False
        j = i
        while j < length:
            ch = text[j]
            if escape_next:
                escape_next = False
                j += 1
                continue
            if ch == "\\" and in_string:
                escape_next = True
                j += 1
                continue
            if ch == '"':
                in_string = not in_string
            elif not in_string:
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        candidates.append(text[i : j + 1])
                        break
            j += 1
        else:
            # Reached end of string without closing — partial candidate
            candidates.append(text[i:])

        i += 1

    # Longest candidates first (more likely to be the full object)
    candidates.sort(key=len, reverse=True)
    return candidates


def _try_parse_dict(candidate: str) -> dict[str, Any] | None:
    """Try to parse ``candidate`` as JSON; return the dict or None."""
    if not candidate:
        return None
    try:
        parsed = json.loads(candidate)
        if isinstance(parsed, dict):
            return parsed
    except (json.JSONDecodeError, ValueError):
        pass
    return None


def _close_incomplete_json(raw: str) -> str | None:
    """Add missing closing quotes and/or braces to make a partial JSON parseable.

    Handles the common LLM corruption pattern ``"value,"a`` where a string
    value is never closed and is followed by garbage characters.
    """
    if not raw or not isinstance(raw, str):
        return None

    stripped = raw.strip()
    if not stripped.startswith("{"):
        return None

    result = list(stripped)
    in_string = False
    escape_next = False
    brace_depth = 0

    for ch in result:
        if escape_next:
            escape_next = False
            continue
        if ch == "\\" and in_string:
            escape_next = True
            continue
        if ch == '"':
            in_string = not in_string
        elif not in_string:
            if ch == "{":
                brace_depth += 1
            elif ch == "}":
                brace_depth -= 1

    repaired = stripped

    # Close any open string
    if in_string:
        repaired = repaired + '"'
        # After closing the string we may have trailing garbage; strip up to
        # the last valid value boundary (comma, colon, or brace).
        repaired = re.sub(r'",\s*[^"{}\[\],:]+$', '"', repaired)
        repaired = re.sub(r'":\s*"[^"]*$', '": ""', repaired)

    # Close any open braces
    if brace_depth > 0:
        repaired = repaired + "}" * brace_depth

    return repaired if repaired != stripped else None
