from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import Mock

from cerberus.infrastructure import env_manager


def test_load_config_merges_root_and_dashboard_env(monkeypatch, tmp_path: Path) -> None:
    root_env = tmp_path / ".env"
    dashboard_env = tmp_path / "dockerized" / ".env" / "dashboard.env"
    app_env = tmp_path / "dockerized" / ".env" / "app.env"
    dashboard_env.parent.mkdir(parents=True, exist_ok=True)
    root_env.write_text("CEREBRO_MODEL=qwen\nCERBERUS_ACTIVE_CONTAINER=cerberus\n", encoding="utf-8")
    dashboard_env.write_text("REDIS_URL=redis://redis:6379\n", encoding="utf-8")
    app_env.write_text("DEBUG_MODE=true\n", encoding="utf-8")

    monkeypatch.setattr(env_manager, "ROOT_ENV_PATH", root_env)
    monkeypatch.setattr(env_manager, "DASHBOARD_ENV_CANDIDATES", (dashboard_env,))
    monkeypatch.setattr(env_manager, "DASHBOARD_ENV_PATH", dashboard_env)
    monkeypatch.setattr(env_manager, "APP_ENV_CANDIDATES", (app_env,))
    monkeypatch.setattr(env_manager, "APP_ENV_PATH", app_env)
    monkeypatch.delenv("CEREBRO_MODEL", raising=False)
    monkeypatch.delenv("CERBERUS_MODEL", raising=False)
    monkeypatch.delenv("CERBERUS_ACTIVE_CONTAINER", raising=False)
    monkeypatch.delenv("CEREBRO_ACTIVE_CONTAINER", raising=False)
    monkeypatch.delenv("REDIS_URL", raising=False)
    monkeypatch.delenv("REFLEX_REDIS_URL", raising=False)
    monkeypatch.delenv("DEBUG_MODE", raising=False)
    monkeypatch.setenv("CERBERUS_API_BASE", "http://127.0.0.1:8080/v1")

    loaded = env_manager.load_config()

    assert loaded["CERBERUS_API_BASE"] == "http://127.0.0.1:8080/v1"
    assert loaded["CEREBRO_MODEL"] == "qwen"
    assert loaded["CERBERUS_ACTIVE_CONTAINER"] == "cerberus"
    assert loaded["REDIS_URL"] == "redis://redis:6379"
    assert loaded["DEBUG_MODE"] == "true"


def test_update_env_routes_and_mirrors_known_aliases(monkeypatch, tmp_path: Path) -> None:
    root_env = tmp_path / ".env"
    dashboard_env = tmp_path / "dockerized" / ".env" / "dashboard.env"
    app_env = tmp_path / "dockerized" / ".env" / "app.env"
    dashboard_env.parent.mkdir(parents=True, exist_ok=True)
    root_env.write_text("", encoding="utf-8")
    dashboard_env.write_text("", encoding="utf-8")
    app_env.write_text("", encoding="utf-8")

    monkeypatch.setattr(env_manager, "ROOT_ENV_PATH", root_env)
    monkeypatch.setattr(env_manager, "DASHBOARD_ENV_CANDIDATES", (dashboard_env,))
    monkeypatch.setattr(env_manager, "DASHBOARD_ENV_PATH", dashboard_env)
    monkeypatch.setattr(env_manager, "APP_ENV_CANDIDATES", (app_env,))
    monkeypatch.setattr(env_manager, "APP_ENV_PATH", app_env)
    restart_mock = Mock(return_value=("cerberus-dashboard",))
    monkeypatch.setattr(env_manager, "restart_services_for_env_path", restart_mock)

    env_manager.update_env("CERBERUS_API_BASE", "http://localhost:11434/v1")
    env_manager.update_env("REDIS_URL", "redis://localhost:6379")
    env_manager.update_env("DEBUG_MODE", True)

    root_text = root_env.read_text(encoding="utf-8")
    dashboard_text = dashboard_env.read_text(encoding="utf-8")
    app_text = app_env.read_text(encoding="utf-8")

    assert "CERBERUS_API_BASE='http://localhost:11434/v1'" in root_text
    assert "CEREBRO_API_BASE='http://localhost:11434/v1'" in root_text
    assert "REDIS_URL='redis://localhost:6379'" in dashboard_text
    assert "REFLEX_REDIS_URL='redis://localhost:6379'" in dashboard_text
    assert "DEBUG_MODE=true" in app_text
    assert os.environ["CERBERUS_API_BASE"] == "http://localhost:11434/v1"
    assert os.environ["CEREBRO_API_BASE"] == "http://localhost:11434/v1"
    assert os.environ["REDIS_URL"] == "redis://localhost:6379"
    assert os.environ["REFLEX_REDIS_URL"] == "redis://localhost:6379"
    assert os.environ["DEBUG_MODE"] == "true"
    assert restart_mock.call_count == 3


def test_restart_services_for_dashboard_env_restarts_expected_service(monkeypatch, tmp_path: Path) -> None:
    dockerized_dir = tmp_path / "dockerized"
    dockerized_dir.mkdir(parents=True, exist_ok=True)
    compose_path = dockerized_dir / "docker-compose.yml"
    compose_path.write_text("services: {}\n", encoding="utf-8")
    env_path = dockerized_dir / ".env" / "dashboard.env"
    env_path.parent.mkdir(parents=True, exist_ok=True)
    env_path.write_text("REDIS_URL=redis://redis:6379\n", encoding="utf-8")

    commands: list[list[str]] = []

    def fake_run(command, cwd, check, capture_output, text):
        commands.append(command)
        return None

    monkeypatch.setattr(env_manager, "DOCKERIZED_DIR", dockerized_dir)
    monkeypatch.setattr(env_manager, "COMPOSE_FILE_PATH", compose_path)
    monkeypatch.setattr(env_manager.subprocess, "run", fake_run)

    restarted = env_manager.restart_services_for_env_path(env_path)

    assert restarted == ("cerberus-dashboard",)
    assert commands == [["docker", "compose", "restart", "cerberus-dashboard"]]