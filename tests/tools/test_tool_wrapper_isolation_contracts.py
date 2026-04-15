from __future__ import annotations

from types import SimpleNamespace

import pytest

from cerberus.tools.runners import docker as docker_runner
from cerberus.tools.runners import local as local_runner
from cerberus.tools import validation as validation_tool


def test_local_runner_wrapper_returns_plain_string(monkeypatch):
    async def _fake_execute(**_kwargs):
        return {"ok": True, "stdout": "scan completed", "stderr": "", "exit_code": 0}

    monkeypatch.setattr(local_runner.LOCAL_RUNNER, "execute", _fake_execute)

    result = local_runner.run_local("echo test")
    assert isinstance(result, str)
    assert result == "scan completed"


def test_docker_runner_wrapper_returns_plain_string(monkeypatch):
    monkeypatch.setattr(
        docker_runner.DOCKER_TOOL,
        "run_command",
        lambda **_kwargs: {"ok": True, "stdout": "docker output", "stderr": "", "exit_code": 0},
    )

    result = docker_runner.run_docker("id")
    assert isinstance(result, str)
    assert result == "docker output"


@pytest.mark.asyncio
async def test_validation_wrapper_returns_json_like_dict(monkeypatch):
    class _Result:
        def model_dump(self, mode="json"):
            return {"ok": True, "gate": "schema", "mode": mode}

    async def _fake_validate_json_schema(**_kwargs):
        return _Result()

    monkeypatch.setattr(validation_tool.VALIDATION_TOOL, "validate_json_schema", _fake_validate_json_schema)

    result = await validation_tool.validate_json_schema(payload={"a": 1}, schema_name="scanner_output")
    assert isinstance(result, dict)
    assert result["ok"] is True
    assert result["gate"] == "schema"
