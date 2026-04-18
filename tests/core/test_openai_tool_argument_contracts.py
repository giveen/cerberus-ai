from __future__ import annotations

import json

from pydantic import BaseModel, ConfigDict

from cerberus.agents.models import openai_chatcompletions as occ


class _StrictNmapArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    target: str
    args: str


class _FakeTool:
    params_pydantic_model = _StrictNmapArgs


class _FakeRegistry:
    def get_tool_by_name(self, _name: str):
        return _FakeTool()


def test_coerce_tool_arguments_for_api_rejects_hallucinated_keys(monkeypatch):
    monkeypatch.setattr("cerberus.tools.all_tools.get_tool_registry", lambda: _FakeRegistry())

    payload = occ._coerce_tool_arguments_for_api(
        {"target": "127.0.0.1", "args": "-sV", "hallucinated": "boom"},
        tool_name="nmap",
        call_id="call_abc123",
    )

    assert payload is not None
    parsed = json.loads(payload)
    assert parsed.get("_parse_error") == "tool_arguments_schema_validation_failed"
    assert "hallucinated" in parsed.get("_raw_arguments", "")


def test_coerce_tool_arguments_for_api_accepts_strict_valid_payload(monkeypatch):
    monkeypatch.setattr("cerberus.tools.all_tools.get_tool_registry", lambda: _FakeRegistry())

    payload = occ._coerce_tool_arguments_for_api(
        {"target": "127.0.0.1", "args": "-sV"},
        tool_name="nmap",
        call_id="call_good",
    )

    assert payload is not None
    parsed = json.loads(payload)
    assert parsed == {"target": "127.0.0.1", "args": "-sV"}
