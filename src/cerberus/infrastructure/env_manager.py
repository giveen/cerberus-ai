from __future__ import annotations

import os
import subprocess
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from typing import Iterable

from dotenv import dotenv_values, set_key


REPO_ROOT = Path(__file__).resolve().parents[3]
ROOT_ENV_PATH = REPO_ROOT / ".env"
DOCKERIZED_DIR = REPO_ROOT / "dockerized"
APP_ENV_CANDIDATES = (
    DOCKERIZED_DIR / "app.env",
    DOCKERIZED_DIR / ".env" / "app.env",
)
DASHBOARD_ENV_CANDIDATES = (
    DOCKERIZED_DIR / "dashboard.env",
    DOCKERIZED_DIR / ".env" / "dashboard.env",
)
APP_ENV_PATH = APP_ENV_CANDIDATES[-1]
DASHBOARD_ENV_PATH = DASHBOARD_ENV_CANDIDATES[-1]
COMPOSE_FILE_PATH = DOCKERIZED_DIR / "docker-compose.yml"
EXTRA_KEYS = {"REDIS_URL", "REFLEX_REDIS_URL", "DEBUG_MODE"}
KEY_MIRRORS: dict[str, tuple[str, ...]] = {
    "CERBERUS_API_BASE": ("CERBERUS_API_BASE", "CEREBRO_API_BASE"),
    "CEREBRO_MODEL": ("CEREBRO_MODEL", "CERBERUS_MODEL"),
    "CERBERUS_ACTIVE_CONTAINER": ("CERBERUS_ACTIVE_CONTAINER", "CEREBRO_ACTIVE_CONTAINER"),
    "REDIS_URL": ("REDIS_URL", "REFLEX_REDIS_URL"),
    "DEBUG_MODE": ("DEBUG_MODE",),
}
RESTART_SERVICES_BY_FILE = {
    "dashboard.env": ("cerberus-dashboard",),
    "app.env": ("container-mcp",),
}
TOOLS_HUB_HOSTNAME = "cerberus-tools-hub"
TOOLS_HUB_URL_KEYS = {
    "SEARXNG_BASE_URL": 8080,
    "CERBERUS_CONTAINER_MCP_URL": 8000,
}


def _first_existing_path(candidates: Iterable[Path], fallback: Path) -> Path:
    for candidate in candidates:
        if candidate.exists() and candidate.is_file():
            return candidate
    return fallback


def _normalize_value(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value or "")


def _force_tools_hub_url(key: str, value: str) -> str:
    normalized_key = str(key or "").strip().upper()
    if normalized_key not in TOOLS_HUB_URL_KEYS:
        return str(value or "")

    raw = str(value or "").strip()
    default_port = TOOLS_HUB_URL_KEYS[normalized_key]
    if not raw:
        if normalized_key == "CERBERUS_CONTAINER_MCP_URL":
            return f"http://{TOOLS_HUB_HOSTNAME}:{default_port}/sse"
        return f"http://{TOOLS_HUB_HOSTNAME}:{default_port}"

    parsed = urlsplit(raw)
    if not parsed.scheme:
        if normalized_key == "CERBERUS_CONTAINER_MCP_URL":
            return f"http://{TOOLS_HUB_HOSTNAME}:{default_port}/sse"
        return f"http://{TOOLS_HUB_HOSTNAME}:{default_port}"

    path = parsed.path or ""
    if normalized_key == "CERBERUS_CONTAINER_MCP_URL" and not path:
        path = "/sse"

    netloc = f"{TOOLS_HUB_HOSTNAME}:{default_port}"
    return urlunsplit((parsed.scheme, netloc, path, parsed.query, parsed.fragment))


def resolve_env_path_for_key(key: str) -> Path:
    normalized = str(key or "").strip().upper()
    if normalized in {
        "REDIS_URL",
        "REFLEX_REDIS_URL",
        "CERBERUS_WORKSPACE_ROOT",
        "SEARXNG_BASE_URL",
        "CERBERUS_CONTAINER_MCP_URL",
    }:
        return _first_existing_path(DASHBOARD_ENV_CANDIDATES, DASHBOARD_ENV_PATH)
    if normalized in {"DEBUG_MODE", "MCP_HOST", "MCP_PORT"}:
        return _first_existing_path(APP_ENV_CANDIDATES, APP_ENV_PATH)
    return ROOT_ENV_PATH


def restart_services_for_env_path(env_path: Path) -> tuple[str, ...]:
    target = Path(env_path)
    services = RESTART_SERVICES_BY_FILE.get(target.name, ())
    if not services or not COMPOSE_FILE_PATH.exists():
        return ()

    restarted: list[str] = []
    for service in services:
        try:
            subprocess.run(
                ["docker", "compose", "restart", service],
                cwd=str(DOCKERIZED_DIR),
                check=True,
                capture_output=True,
                text=True,
            )
            restarted.append(service)
        except Exception:
            continue
    return tuple(restarted)


def load_config() -> dict[str, str]:
    payload: dict[str, str] = {}
    for env_path in (ROOT_ENV_PATH, resolve_env_path_for_key("REDIS_URL"), resolve_env_path_for_key("DEBUG_MODE")):
        if not env_path.exists():
            continue
        for key, value in dotenv_values(env_path).items():
            if value is None:
                continue
            normalized = str(key or "").strip()
            if not normalized:
                continue
            if normalized.startswith("CERBERUS_") or normalized.startswith("CEREBRO_") or normalized in EXTRA_KEYS:
                payload[normalized] = str(value)

    for key, value in os.environ.items():
        if key.startswith("CERBERUS_") or key.startswith("CEREBRO_") or key in EXTRA_KEYS:
            payload[key] = str(value)

    for key in TOOLS_HUB_URL_KEYS:
        if key in payload:
            payload[key] = _force_tools_hub_url(key, payload[key])

    return payload


def update_env(key: str, value: object) -> tuple[str, ...]:
    normalized_key = str(key or "").strip().upper()
    if not normalized_key:
        raise ValueError("Environment key is required.")

    normalized_value = _normalize_value(value)
    normalized_value = _force_tools_hub_url(normalized_key, normalized_value)
    target_path = resolve_env_path_for_key(normalized_key)
    target_path.parent.mkdir(parents=True, exist_ok=True)
    if not target_path.exists():
        target_path.touch()

    for env_key in KEY_MIRRORS.get(normalized_key, (normalized_key,)):
        set_key(str(target_path), env_key, normalized_value, quote_mode="auto")
        os.environ[env_key] = normalized_value

    return restart_services_for_env_path(target_path)
