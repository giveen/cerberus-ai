from __future__ import annotations

import subprocess
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

import pytest
from playwright.sync_api import Page, expect, sync_playwright


REPO_ROOT = Path(__file__).resolve().parents[2]
DOCKER_DIR = REPO_ROOT / "dockerized"
DASHBOARD_URL = "http://127.0.0.1:8000"
ROOT_ENV_PATH = REPO_ROOT / ".env"
TEST_API_BASE = "http://127.0.0.1:65531/v1"


def _run_compose(*args: str) -> None:
    subprocess.run(
        ["docker", "compose", *args],
        cwd=str(DOCKER_DIR),
        check=True,
        capture_output=True,
        text=True,
    )


def _wait_for_dashboard(timeout_s: int = 180) -> None:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            with urlopen(DASHBOARD_URL, timeout=5) as response:
                if response.status == 200:
                    return
        except (URLError, OSError, ConnectionResetError):
            pass
        time.sleep(2)
    raise AssertionError(f"Timed out waiting for dashboard at {DASHBOARD_URL}")


@pytest.mark.integration
def test_config_manager_flow() -> None:
    original_env = ROOT_ENV_PATH.read_text(encoding="utf-8")
    try:
        _run_compose("up", "-d", "--build", "redis", "valkey", "searxng", "cerberus-dashboard")
        _wait_for_dashboard()

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            page = browser.new_page()
            _exercise_config_flow(page)
            browser.close()
    finally:
        try:
            _run_compose("down", "--remove-orphans")
        except Exception:
            pass
        ROOT_ENV_PATH.write_text(original_env, encoding="utf-8")


def _exercise_config_flow(page: Page) -> None:
    page.goto(DASHBOARD_URL, wait_until="networkidle")

    page.locator('[data-config-button="true"]').click()
    expect(page.locator('[data-config-overlay="true"]')).to_be_visible()

    api_input = page.locator('[data-config-input="CERBERUS_API_BASE"]')
    save_button = page.locator('[data-config-save="true"]')

    api_input.fill("localhost:11434")
    api_input.press("Tab")
    expect(save_button).to_be_disabled()

    api_input.fill(TEST_API_BASE)
    api_input.press("Tab")
    expect(save_button).to_be_enabled()
    save_button.click()

    expect(page.get_by_text("Configuration updated.").first).to_be_visible()
    assert f"CERBERUS_API_BASE='{TEST_API_BASE}'" in ROOT_ENV_PATH.read_text(encoding="utf-8")