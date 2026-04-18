from __future__ import annotations

from pathlib import Path

import pytest

from cerberus.tools.reconnaissance.browser import BrowserReconTool


class _FakeLocatorItem:
    def __init__(self, text: str, attrs: dict[str, str | None] | None = None) -> None:
        self._text = text
        self._attrs = attrs or {}

    async def inner_text(self) -> str:
        return self._text

    async def get_attribute(self, name: str) -> str | None:
        return self._attrs.get(name)

    async def click(self, timeout: int) -> None:
        return None

    async def fill(self, text: str, timeout: int) -> None:
        self._text = text


class _FakeLocator:
    def __init__(self, items: list[_FakeLocatorItem]) -> None:
        self._items = items

    @property
    def first(self) -> _FakeLocatorItem:
        return self._items[0]

    async def count(self) -> int:
        return len(self._items)

    def nth(self, index: int) -> _FakeLocatorItem:
        return self._items[index]


class _FakePage:
    def __init__(self) -> None:
        self.url = "http://127.0.0.1:8080"
        self.screenshot_path: str | None = None

    async def title(self) -> str:
        return "Demo App"

    async def content(self) -> str:
        return """
        <html><body>
            <h1>Home</h1>
            <h2>Login</h2>
            <form action="/login" method="post">
                <input name="username" />
                <input name="password" type="password" />
            </form>
            <a href="/admin">Admin</a>
        </body></html>
        """

    def locator(self, selector: str) -> _FakeLocator:
        if selector == ".item":
            return _FakeLocator(
                [
                    _FakeLocatorItem("First item", {"href": "/one"}),
                    _FakeLocatorItem("Second item", {"href": "/two"}),
                ]
            )
        return _FakeLocator([_FakeLocatorItem("single")])

    async def screenshot(self, path: str, full_page: bool) -> None:
        self.screenshot_path = path
        Path(path).write_bytes(b"png")


@pytest.mark.asyncio
async def test_normalize_cookies_accepts_dict_payload() -> None:
    cookies = BrowserReconTool._normalize_cookies('{"session":"abc123"}')
    assert cookies == [
        {
            "name": "session",
            "value": "abc123",
            "domain": "127.0.0.1",
            "path": "/",
            "httpOnly": False,
            "secure": False,
        }
    ]


@pytest.mark.asyncio
async def test_take_screenshot_returns_saved_path(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr("cerberus.tools.reconnaissance.browser._SCREENSHOT_DIR", tmp_path)
    tool = BrowserReconTool()
    tool._page = _FakePage()
    tool._last_url = "http://127.0.0.1:8080"

    result = await tool.take_screenshot(label="landing")

    assert result["ok"] is True
    assert Path(result["path"]).exists()
    assert result["path"].endswith("landing.png")


@pytest.mark.asyncio
async def test_extract_elements_returns_text_and_attribute() -> None:
    tool = BrowserReconTool()
    tool._page = _FakePage()
    tool._last_url = "http://127.0.0.1:8080"

    result = await tool.extract_elements(selector=".item", attribute="href")

    assert result["ok"] is True
    assert result["count"] == 2
    assert result["elements"][0]["text"] == "First item"
    assert result["elements"][1]["value"] == "/two"


@pytest.mark.asyncio
async def test_describe_page_structure_summarizes_dom() -> None:
    tool = BrowserReconTool()
    tool._page = _FakePage()
    tool._last_url = "http://127.0.0.1:8080"

    result = await tool.describe_page_structure()

    assert result["ok"] is True
    assert result["title"] == "Demo App"
    assert result["headings"][:2] == ["Home", "Login"]
    assert result["forms"][0]["action"] == "/login"
    assert "/admin" in result["links"]