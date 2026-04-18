from __future__ import annotations

from types import SimpleNamespace

from cerberus.tools.web import search_web


def test_normalize_language_handles_malformed_locale() -> None:
    assert search_web._normalize_language("-US") == "en"
    assert search_web._normalize_language("") == "en"
    assert search_web._normalize_language("en_US") == "en-US"
    assert search_web._normalize_language("en-US") == "en-US"
    assert search_web._normalize_language("all") == "all"
    assert search_web._normalize_language("$$$") == "en"


def test_perform_search_uses_normalized_params(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def _fake_get(url, params, timeout, allow_redirects):
        captured["url"] = url
        captured["params"] = dict(params)
        return SimpleNamespace(
            text='''
            <article class="result"><h3><a href="https://example.com">Example</a></h3>
            <p class="content">Result snippet</p></article>
            ''',
            raise_for_status=lambda: None,
        )

    monkeypatch.setattr(search_web.requests, "get", _fake_get)

    result = search_web._perform_searxng_search(
        query="natas0 password",
        context="N level 0 challenge on OverTheWire",
        language="-US",
        categories="general",
    )

    assert "SearXNG Search Results:" in result
    assert captured["url"] == "http://searxng:8080/search"
    params = captured["params"]
    assert params["language"] == "en"
    assert params["categories"] == "general"
    assert params["q"] == "natas0 password N level 0 challenge on OverTheWire"
