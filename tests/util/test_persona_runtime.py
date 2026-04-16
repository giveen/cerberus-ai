from __future__ import annotations

from pathlib import Path

from cerberus.persona_runtime import PersonaRegistry


def _registry() -> PersonaRegistry:
    prompts_root = Path(__file__).resolve().parents[2] / "src" / "cerberus" / "prompts"
    registry = PersonaRegistry(prompts_root=prompts_root)
    registry.clear_active_persona()
    return registry


def test_determine_persona_defaults_to_master() -> None:
    registry = _registry()

    assert registry.determine_persona("hello there") == "master"


def test_determine_persona_switches_and_persists_until_sleep() -> None:
    registry = _registry()

    assert registry.determine_persona("switch to red team mode") == "red_team"
    assert registry.determine_persona("continue enumerating targets") == "red_team"
    assert registry.determine_persona("sleep") == "master"
    assert registry.determine_persona("continue") == "master"


def test_determine_persona_fuzzy_match() -> None:
    registry = _registry()

    assert registry.determine_persona("please engage bluetam posture") == "blue_team"
