import os
import re
from typing import Any

import requests

from cerberus.agents import function_tool


_DEFAULT_SEARXNG_BASE_URL = "http://searxng:8080"
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F]")
_ARTICLE_RE = re.compile(r"<article class=\"result[^>]*>(.*?)</article>", re.DOTALL | re.IGNORECASE)
_H3_LINK_RE = re.compile(r"<h3>\s*<a[^>]*href=\"([^\"]+)\"[^>]*>(.*?)</a>\s*</h3>", re.DOTALL | re.IGNORECASE)
_CONTENT_RE = re.compile(r"<p class=\"content\">(.*?)</p>", re.DOTALL | re.IGNORECASE)
_TAG_RE = re.compile(r"<[^>]+>")
_SPACE_RE = re.compile(r"\s+")
_LANG_BASE_RE = re.compile(r"^[A-Za-z]{2,3}$")
_LANG_LOCALE_RE = re.compile(r"^[A-Za-z]{2,3}([_-][A-Za-z]{2})$")


def _sanitize_external_content(raw: str) -> str:
    text = str(raw or "")
    text = _CONTROL_CHAR_RE.sub("", text)
    return text.strip()


def _strip_html(raw: str) -> str:
    cleaned = _TAG_RE.sub(" ", raw or "")
    cleaned = _SPACE_RE.sub(" ", cleaned)
    return cleaned.strip()


def _extract_results_from_html(html_text: str, max_results: int) -> str:
    matches = _ARTICLE_RE.findall(html_text or "")
    if not matches:
        return "No web results found."

    lines: list[str] = ["SearXNG Search Results:"]
    count = 0
    for block in matches:
        h3_match = _H3_LINK_RE.search(block)
        if not h3_match:
            continue

        url = (h3_match.group(1) or "").strip()
        title = _strip_html(h3_match.group(2)) or "Untitled"
        snippet_match = _CONTENT_RE.search(block)
        snippet = _strip_html(snippet_match.group(1)) if snippet_match else ""

        count += 1
        lines.append(f"{count}. {title}")
        if url:
            lines.append(f"   URL: {url}")
        if snippet:
            lines.append(f"   Snippet: {snippet}")
        if count >= max_results:
            break

    if count == 0:
        return "No web results found."
    return _sanitize_external_content("\n".join(lines))


def _resolve_searxng_base_url() -> str:
    raw = os.getenv("SEARXNG_BASE_URL", _DEFAULT_SEARXNG_BASE_URL).strip()
    if not raw:
        return _DEFAULT_SEARXNG_BASE_URL
    return raw.rstrip("/")


def _compose_query(query: str, context: str) -> str:
    query_text = (query or "").strip()
    context_text = (context or "").strip()
    if not context_text:
        return query_text
    if not query_text:
        return context_text
    # Keep context searchable while preserving direct query intent.
    return f"{query_text} {context_text}"


def _normalize_language(language: str) -> str:
    value = str(language or "").strip()
    if not value:
        return "en"

    # Handle malformed values such as "-US" by dropping leading separators.
    value = value.lstrip("-_")
    if not value:
        return "en"

    normalized = value.replace("_", "-")

    # Accept plain language codes like "en" and normalize to lowercase.
    if _LANG_BASE_RE.match(normalized):
        base = normalized.lower()
        # Guard against malformed country-only values from inputs like "-US".
        if base in {"us", "uk"}:
            return "en"
        return base

    # Accept locale tokens like "en-US".
    if _LANG_LOCALE_RE.match(normalized):
        parts = normalized.split("-", 1)
        return f"{parts[0].lower()}-{parts[1].upper()}"

    lowered = value.lower()
    if lowered in {"all", "auto"}:
        return lowered
    return "en"


def _normalize_categories(categories: str) -> str:
    value = str(categories or "").strip()
    if not value:
        return "general"
    return value


def _perform_searxng_search(
    *,
    query: str,
    context: str = "",
    max_results: int = 8,
    categories: str = "general",
    language: str = "en-US",
    time_range: str = "",
) -> str:
    normalized_query = _compose_query(query, context)
    if not normalized_query:
        return "Error: query is required."

    base_url = _resolve_searxng_base_url()
    endpoint = f"{base_url}/search"
    limit = max(1, min(int(max_results), 20))
    normalized_language = _normalize_language(language)
    normalized_categories = _normalize_categories(categories)
    params: dict[str, Any] = {
        "q": normalized_query,
        "safesearch": 0,
        "language": normalized_language,
        "categories": normalized_categories,
        "pageno": 1,
    }
    if time_range:
        params["time_range"] = time_range

    try:
        response = requests.get(endpoint, params=params, timeout=20, allow_redirects=True)
        response.raise_for_status()
        payload = response.text
    except Exception as exc:
        return f"Error querying SearXNG: {exc}"

    return _extract_results_from_html(payload, limit)


@function_tool
def searxng_web_search(
    query: str,
    context: str = "",
    max_results: int = 8,
    categories: str = "general",
    language: str = "en-US",
    time_range: str = "",
) -> str:
    """Search the web via the local SearXNG instance."""
    return _perform_searxng_search(
        query=query,
        context=context,
        max_results=max_results,
        categories=categories,
        language=language,
        time_range=time_range,
    )


@function_tool
def make_web_search_with_explanation(context: str = "", query: str = "") -> str:
    """Compatibility wrapper that routes web search to SearXNG."""
    return _perform_searxng_search(query=query, context=context)
