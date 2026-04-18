"""Headless browser reconnaissance helpers for dynamic web CTF workflows."""

from __future__ import annotations

import asyncio
import json
import os
import re
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Dict, Optional

from playwright.async_api import Browser, BrowserContext, Page, Playwright, async_playwright

from cerberus.agents import function_tool
from cerberus.tools._lazy import LazyToolProxy
from cerberus.tools.validation import sanitize_tool_output


_BROWSER_TIMEOUT_MS = max(5_000, int(os.getenv("CERBERUS_BROWSER_TIMEOUT_MS", "30000") or "30000"))
_MAX_PAGE_SOURCE_CHARS = max(10_000, int(os.getenv("CERBERUS_BROWSER_MAX_SOURCE_CHARS", "60000") or "60000"))
_SCREENSHOT_DIR = Path(os.getenv("CERBERUS_BROWSER_SCREENSHOT_DIR", "logs/browser_screenshots")).expanduser()


@dataclass(frozen=True)
class BrowserError:
    code: str
    message: str
    retryable: bool


class _StructureParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.headings: list[str] = []
        self.links: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self._heading_tag: str | None = None
        self._heading_buffer: list[str] = []
        self._current_form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = {key: value for key, value in attrs}
        if tag in {"h1", "h2", "h3"}:
            self._heading_tag = tag
            self._heading_buffer = []
            return
        if tag == "a" and attr_map.get("href"):
            self.links.append(str(attr_map.get("href")))
            return
        if tag == "form":
            self._current_form = {
                "action": attr_map.get("action"),
                "method": str(attr_map.get("method") or "get").lower(),
                "inputs": [],
            }
            return
        if tag in {"input", "textarea", "select"} and self._current_form is not None:
            self._current_form["inputs"].append(
                attr_map.get("name") or attr_map.get("id") or attr_map.get("type") or tag
            )

    def handle_endtag(self, tag: str) -> None:
        if tag in {"h1", "h2", "h3"} and self._heading_tag == tag:
            heading = " ".join(part.strip() for part in self._heading_buffer if part.strip()).strip()
            if heading:
                self.headings.append(heading)
            self._heading_tag = None
            self._heading_buffer = []
            return
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None

    def handle_data(self, data: str) -> None:
        if self._heading_tag is not None:
            self._heading_buffer.append(data)


def _strip_heavy_tags(html: str) -> str:
    cleaned = re.sub(r"<script\b[^>]*>.*?</script>", "", html, flags=re.IGNORECASE | re.DOTALL)
    cleaned = re.sub(r"<style\b[^>]*>.*?</style>", "", cleaned, flags=re.IGNORECASE | re.DOTALL)
    cleaned = re.sub(r"<svg\b[^>]*>.*?</svg>", "", cleaned, flags=re.IGNORECASE | re.DOTALL)
    cleaned = re.sub(r"\n\s*\n+", "\n", cleaned)
    cleaned = re.sub(r"[ \t]{2,}", " ", cleaned)
    return cleaned.strip()


class BrowserReconTool:
    """Async Playwright session manager for headless browser interaction."""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._playwright: Optional[Playwright] = None
        self._browser: Optional[Browser] = None
        self._context: Optional[BrowserContext] = None
        self._page: Optional[Page] = None
        self._auth_username: Optional[str] = None
        self._auth_password: Optional[str] = None
        self._last_url: str = ""

    async def Maps(
        self,
        *,
        url: str,
        auth_username: Optional[str] = None,
        auth_password: Optional[str] = None,
        cookies_json: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Navigate to URL and support HTTP Basic Auth through browser context."""
        target_url = str(url or "").strip()
        if not target_url:
            return self._error(BrowserError(code="missing_url", message="URL is required.", retryable=False))

        async with self._lock:
            try:
                await self._ensure_page(
                    auth_username=auth_username,
                    auth_password=auth_password,
                    cookies_json=cookies_json,
                )
                assert self._page is not None
                response = await self._page.goto(target_url, wait_until="domcontentloaded", timeout=_BROWSER_TIMEOUT_MS)
                self._last_url = str(self._page.url or target_url)
                title = await self._page.title()
                return {
                    "ok": True,
                    "url": self._last_url,
                    "title": title,
                    "status": int(response.status) if response else None,
                    "auth_mode": "cookies" if cookies_json else ("http_basic" if auth_username else "none"),
                }
            except Exception as exc:
                return self._error(
                    BrowserError(
                        code="navigation_failed",
                        message=f"Navigation failed: {exc}",
                        retryable=True,
                    )
                )

    async def get_page_source(self, *, strip_scripts: bool = True) -> Dict[str, Any]:
        """Return page source with optional aggressive tag stripping for token efficiency."""
        async with self._lock:
            try:
                if self._page is None:
                    return self._error(
                        BrowserError(
                            code="page_not_initialized",
                            message="No active page. Call Maps() first.",
                            retryable=False,
                        )
                    )

                source = await self._page.content()
                normalized = self._normalize_source(source, strip_scripts=bool(strip_scripts))
                truncated = False
                if len(normalized) > _MAX_PAGE_SOURCE_CHARS:
                    normalized = normalized[:_MAX_PAGE_SOURCE_CHARS]
                    truncated = True

                return {
                    "ok": True,
                    "url": str(self._page.url or self._last_url),
                    "strip_scripts": bool(strip_scripts),
                    "truncated": truncated,
                    "length": len(normalized),
                    "content": normalized,
                }
            except Exception as exc:
                return self._error(
                    BrowserError(
                        code="source_read_failed",
                        message=f"Failed reading page source: {exc}",
                        retryable=True,
                    )
                )

    async def click_element(self, *, selector: str) -> Dict[str, Any]:
        """Click a DOM element identified by a CSS selector."""
        candidate = str(selector or "").strip()
        if not candidate:
            return self._error(BrowserError(code="missing_selector", message="Selector is required.", retryable=False))

        async with self._lock:
            try:
                if self._page is None:
                    return self._error(
                        BrowserError(
                            code="page_not_initialized",
                            message="No active page. Call Maps() first.",
                            retryable=False,
                        )
                    )

                await self._page.locator(candidate).first.click(timeout=_BROWSER_TIMEOUT_MS)
                return {
                    "ok": True,
                    "selector": candidate,
                    "url": str(self._page.url or self._last_url),
                }
            except Exception as exc:
                return self._error(
                    BrowserError(
                        code="click_failed",
                        message=f"Click failed: {exc}",
                        retryable=True,
                    )
                )

    async def fill_form(self, *, selector: str, text: str) -> Dict[str, Any]:
        """Fill a form field identified by CSS selector."""
        candidate = str(selector or "").strip()
        if not candidate:
            return self._error(BrowserError(code="missing_selector", message="Selector is required.", retryable=False))

        async with self._lock:
            try:
                if self._page is None:
                    return self._error(
                        BrowserError(
                            code="page_not_initialized",
                            message="No active page. Call Maps() first.",
                            retryable=False,
                        )
                    )

                await self._page.locator(candidate).first.fill(str(text or ""), timeout=_BROWSER_TIMEOUT_MS)
                return {
                    "ok": True,
                    "selector": candidate,
                    "text_length": len(str(text or "")),
                    "url": str(self._page.url or self._last_url),
                }
            except Exception as exc:
                return self._error(
                    BrowserError(
                        code="fill_failed",
                        message=f"Form fill failed: {exc}",
                        retryable=True,
                    )
                )

    async def take_screenshot(self, *, label: str = "page") -> Dict[str, Any]:
        async with self._lock:
            try:
                if self._page is None:
                    return self._error(
                        BrowserError(
                            code="page_not_initialized",
                            message="No active page. Call Maps() first.",
                            retryable=False,
                        )
                    )

                safe_label = re.sub(r"[^a-zA-Z0-9._-]+", "-", str(label or "page")).strip("-") or "page"
                _SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)
                output_path = _SCREENSHOT_DIR / f"{safe_label}.png"
                await self._page.screenshot(path=str(output_path), full_page=True)
                return {
                    "ok": True,
                    "url": str(self._page.url or self._last_url),
                    "path": str(output_path.resolve()),
                }
            except Exception as exc:
                return self._error(
                    BrowserError(
                        code="screenshot_failed",
                        message=f"Screenshot failed: {exc}",
                        retryable=True,
                    )
                )

    async def extract_elements(self, *, selector: str, attribute: Optional[str] = None) -> Dict[str, Any]:
        candidate = str(selector or "").strip()
        if not candidate:
            return self._error(BrowserError(code="missing_selector", message="Selector is required.", retryable=False))

        async with self._lock:
            try:
                if self._page is None:
                    return self._error(
                        BrowserError(
                            code="page_not_initialized",
                            message="No active page. Call Maps() first.",
                            retryable=False,
                        )
                    )

                locator = self._page.locator(candidate)
                count = await locator.count()
                items: list[dict[str, Any]] = []
                for index in range(min(count, 25)):
                    handle = locator.nth(index)
                    text = (await handle.inner_text()).strip()
                    payload: dict[str, Any] = {"index": index, "text": text}
                    if attribute:
                        payload["attribute"] = attribute
                        payload["value"] = await handle.get_attribute(attribute)
                    items.append(payload)

                return {
                    "ok": True,
                    "url": str(self._page.url or self._last_url),
                    "selector": candidate,
                    "count": count,
                    "elements": items,
                }
            except Exception as exc:
                return self._error(
                    BrowserError(
                        code="extract_failed",
                        message=f"Element extraction failed: {exc}",
                        retryable=True,
                    )
                )

    async def describe_page_structure(self) -> Dict[str, Any]:
        async with self._lock:
            try:
                if self._page is None:
                    return self._error(
                        BrowserError(
                            code="page_not_initialized",
                            message="No active page. Call Maps() first.",
                            retryable=False,
                        )
                    )

                html = await self._page.content()
                parser = _StructureParser()
                parser.feed(html)

                return {
                    "ok": True,
                    "url": str(self._page.url or self._last_url),
                    "title": await self._page.title(),
                    "headings": parser.headings[:10],
                    "forms": parser.forms[:10],
                    "links": parser.links[:20],
                }
            except Exception as exc:
                return self._error(
                    BrowserError(
                        code="describe_failed",
                        message=f"Page description failed: {exc}",
                        retryable=True,
                    )
                )

    async def _ensure_page(
        self,
        *,
        auth_username: Optional[str],
        auth_password: Optional[str],
        cookies_json: Optional[str] = None,
    ) -> None:
        await self._ensure_browser()

        username = str(auth_username or "").strip() or None
        password = str(auth_password or "").strip() or None

        if (
            self._context is None
            or username != self._auth_username
            or password != self._auth_password
        ):
            if self._context is not None:
                await self._context.close()
            http_credentials = None
            if username:
                http_credentials = {"username": username, "password": password or ""}
            assert self._browser is not None
            self._context = await self._browser.new_context(http_credentials=http_credentials)
            self._auth_username = username
            self._auth_password = password
            self._page = None

        if cookies_json:
            cookies = self._normalize_cookies(cookies_json)
            if cookies:
                assert self._context is not None
                await self._context.add_cookies(cookies)

        if self._page is None:
            assert self._context is not None
            self._page = await self._context.new_page()

    @staticmethod
    def _normalize_cookies(cookies_json: str) -> list[dict[str, Any]]:
        raw = str(cookies_json or "").strip()
        if not raw:
            return []
        try:
            parsed = json.loads(raw)
        except Exception:
            return []

        if isinstance(parsed, dict):
            parsed = [
                {"name": key, "value": str(value), "domain": "127.0.0.1", "path": "/"}
                for key, value in parsed.items()
            ]

        if not isinstance(parsed, list):
            return []

        normalized: list[dict[str, Any]] = []
        for item in parsed:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name", "") or "").strip()
            value = str(item.get("value", "") or "")
            if not name:
                continue
            normalized.append(
                {
                    "name": name,
                    "value": value,
                    "domain": str(item.get("domain", "127.0.0.1") or "127.0.0.1"),
                    "path": str(item.get("path", "/") or "/"),
                    "httpOnly": bool(item.get("httpOnly", False)),
                    "secure": bool(item.get("secure", False)),
                }
            )
        return normalized

    async def _ensure_browser(self) -> None:
        if self._playwright is None:
            self._playwright = await async_playwright().start()
        if self._browser is None:
            assert self._playwright is not None
            self._browser = await self._playwright.chromium.launch(headless=True)

    @staticmethod
    def _normalize_source(source: str, *, strip_scripts: bool) -> str:
        html = str(source or "")
        if not strip_scripts:
            return html
        return _strip_heavy_tags(html)

    @staticmethod
    def _error(error: BrowserError) -> Dict[str, Any]:
        return {
            "ok": False,
            "error": {
                "code": error.code,
                "message": error.message,
                "retryable": error.retryable,
            },
        }


BROWSER_RECON_TOOL = LazyToolProxy(BrowserReconTool)


def _json_result(payload: Dict[str, Any], tool_name: str) -> str:
    return sanitize_tool_output(tool_name, json.dumps(payload, ensure_ascii=True, indent=2))


@function_tool
async def Maps(url: str, auth_username: Optional[str] = None, auth_password: Optional[str] = None, cookies_json: Optional[str] = None) -> str:
    payload = await BROWSER_RECON_TOOL.Maps(
        url=url,
        auth_username=auth_username,
        auth_password=auth_password,
        cookies_json=cookies_json,
    )
    return _json_result(payload, "Maps")


@function_tool
async def get_page_source(strip_scripts: bool = True) -> str:
    payload = await BROWSER_RECON_TOOL.get_page_source(strip_scripts=strip_scripts)
    return _json_result(payload, "get_page_source")


@function_tool
async def click_element(selector: str) -> str:
    payload = await BROWSER_RECON_TOOL.click_element(selector=selector)
    return _json_result(payload, "click_element")


@function_tool
async def fill_form(selector: str, text: str) -> str:
    payload = await BROWSER_RECON_TOOL.fill_form(selector=selector, text=text)
    return _json_result(payload, "fill_form")


@function_tool
async def browser_screenshot(label: str = "page") -> str:
    payload = await BROWSER_RECON_TOOL.take_screenshot(label=label)
    return _json_result(payload, "browser_screenshot")


@function_tool
async def extract_elements(selector: str, attribute: Optional[str] = None) -> str:
    payload = await BROWSER_RECON_TOOL.extract_elements(selector=selector, attribute=attribute)
    return _json_result(payload, "extract_elements")


@function_tool
async def describe_page_structure() -> str:
    payload = await BROWSER_RECON_TOOL.describe_page_structure()
    return _json_result(payload, "describe_page_structure")


__all__ = [
    "BrowserError",
    "BrowserReconTool",
    "BROWSER_RECON_TOOL",
    "Maps",
    "get_page_source",
    "click_element",
    "fill_form",
    "browser_screenshot",
    "extract_elements",
    "describe_page_structure",
]
