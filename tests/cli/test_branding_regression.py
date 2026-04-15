"""Regression tests for user-facing branding in CLI help and banner output."""

from __future__ import annotations

import re

from rich.console import Console

from cerberus import cli
from cerberus.repl.ui.banner import BannerMetadata, CerberusBanner


FORBIDDEN_PATTERNS = (
    r"alias robotics",
    r"cybersecurity ai",
    r"\bcai\b",
    r"cai>",
    r"\bcerebro(?:-ai)?\b",
)


def _assert_no_legacy_tokens(rendered: str) -> None:
    lowered = rendered.lower()
    for pattern in FORBIDDEN_PATTERNS:
        assert re.search(pattern, lowered) is None, f"Legacy branding token detected: {pattern}"


def test_cli_help_has_no_legacy_branding(monkeypatch) -> None:
    console = Console(record=True, width=140)
    monkeypatch.setattr(cli, "console", console)

    cli._render_help()
    rendered = console.export_text()

    _assert_no_legacy_tokens(rendered)
    assert "cerberus ai" in rendered.lower()


def test_banner_has_no_legacy_branding(monkeypatch) -> None:
    console = Console(record=True, width=140)
    banner = CerberusBanner(console)

    fake_meta = BannerMetadata(
        version="0.0.0",
        system="linux / x86_64",
        brain="Brain: Local: qwen",
        workspace_status="healthy",
        memory_status="healthy",
        workspace_root="/tmp/workspace",
        startup_ms=10,
    )

    monkeypatch.setattr(CerberusBanner, "_collect_metadata", lambda self, start: fake_meta)
    monkeypatch.setattr(CerberusBanner, "_pick_tip", lambda self, meta: "Use /workspace dashboard to inspect artifacts.")

    banner.display()
    rendered = console.export_text()

    _assert_no_legacy_tokens(rendered)
    assert "cerberus ai" in rendered.lower()
