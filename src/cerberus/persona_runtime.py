"""Dynamic persona selection and session-scoped state management.

This module provides a lightweight persona registry used by the headless
dispatcher to select and persist a prompt persona per logical session.
"""

from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass
from difflib import SequenceMatcher
from pathlib import Path
import re


@dataclass(frozen=True)
class PersonaDefinition:
    """Describes one selectable runtime persona."""

    name: str
    prompt_path: str
    keywords: tuple[str, ...]


@dataclass(frozen=True)
class PersonaSelection:
    """Selection output consumed by the dispatcher."""

    name: str
    prompt_path: str
    prompt_file: Path
    explicit_match: bool
    sleep_command: bool


_ACTIVE_PERSONA_NAME: ContextVar[str | None] = ContextVar("cerberus_active_persona_name", default=None)


class PersonaRegistry:
    """Keyword/fuzzy persona resolver with contextvar-backed active state."""

    DEFAULT_PERSONA = "master"

    _SLEEP_PATTERNS = (
        "sleep",
        "go to sleep",
        "persona sleep",
        "agent sleep",
        "stand down",
    )

    def __init__(self, *, prompts_root: Path) -> None:
        self._prompts_root = prompts_root.resolve()
        self._personas: dict[str, PersonaDefinition] = {
            "master": PersonaDefinition(
                name="master",
                prompt_path="core/system_master_template.md",
                keywords=("default", "master", "orchestrator", "general"),
            ),
            "red_team": PersonaDefinition(
                name="red_team",
                prompt_path="system_red_team_agent.md",
                keywords=("red", "red team", "offense", "offensive", "exploit", "payload", "attack"),
            ),
            "blue_team": PersonaDefinition(
                name="blue_team",
                prompt_path="system_blue_team_agent.md",
                keywords=("blue", "blue team", "defense", "defensive", "hardening", "mitigate"),
            ),
            "dfir": PersonaDefinition(
                name="dfir",
                prompt_path="system_dfir_agent.md",
                keywords=("dfir", "forensic", "forensics", "incident response", "triage", "postmortem"),
            ),
        }

    def get_active_persona(self) -> str | None:
        return _ACTIVE_PERSONA_NAME.get()

    def set_active_persona(self, persona_name: str) -> None:
        if persona_name not in self._personas:
            return
        _ACTIVE_PERSONA_NAME.set(persona_name)

    def clear_active_persona(self) -> None:
        _ACTIVE_PERSONA_NAME.set(None)

    def determine_persona(self, user_input: str) -> str:
        """Resolve persona from prompt with keyword/fuzzy scoring.

        Behavior:
        - explicit persona mention switches active persona
        - sleep command clears active persona and falls back to default
        - no explicit match keeps active persona if one exists
        - final fallback is master template
        """
        text = (user_input or "").strip()
        if self._is_sleep_command(text):
            self.clear_active_persona()
            return self.DEFAULT_PERSONA

        matched = self._match_persona(text)
        if matched:
            self.set_active_persona(matched)
            return matched

        active = self.get_active_persona()
        if active in self._personas:
            return active

        self.set_active_persona(self.DEFAULT_PERSONA)
        return self.DEFAULT_PERSONA

    def select_for_input(self, user_input: str) -> PersonaSelection:
        normalized = (user_input or "").strip()
        sleep_command = self._is_sleep_command(normalized)
        matched = self._match_persona(normalized)
        chosen = self.determine_persona(normalized)

        definition = self._personas.get(chosen) or self._personas[self.DEFAULT_PERSONA]
        prompt_file = self._resolve_prompt_file(definition.prompt_path)
        return PersonaSelection(
            name=definition.name,
            prompt_path=definition.prompt_path,
            prompt_file=prompt_file,
            explicit_match=matched is not None,
            sleep_command=sleep_command,
        )

    def _resolve_prompt_file(self, prompt_path: str) -> Path:
        candidate = Path(prompt_path)
        if candidate.is_absolute():
            return candidate.resolve()
        return (self._prompts_root / candidate).resolve()

    def _is_sleep_command(self, user_input: str) -> bool:
        if not user_input:
            return False
        lower = user_input.strip().lower()
        return lower in self._SLEEP_PATTERNS

    def _match_persona(self, user_input: str) -> str | None:
        if not user_input:
            return None

        lowered = user_input.lower()
        lowered = re.sub(r"\s+", " ", lowered)

        scores: dict[str, float] = {}
        for name, definition in self._personas.items():
            if name == self.DEFAULT_PERSONA:
                continue
            score = self._score_persona(lowered, definition)
            if score > 0:
                scores[name] = score

        if not scores:
            return None

        best_name = max(scores, key=scores.get)
        if scores[best_name] < 1.0:
            return None
        return best_name

    def _score_persona(self, user_input: str, definition: PersonaDefinition) -> float:
        score = 0.0
        tokens = [token for token in re.split(r"[^a-z0-9_]+", user_input) if token]
        for keyword in definition.keywords:
            keyword_lower = keyword.lower().strip()
            if not keyword_lower:
                continue
            if keyword_lower in user_input:
                score += 2.0
                continue

            # Lightweight fuzzy fallback catches typos such as "bluetam" or "forencis".
            fuzzy = self._best_fuzzy_ratio(keyword_lower, tokens)
            if fuzzy >= 0.86:
                score += 1.0
        return score

    @staticmethod
    def _best_fuzzy_ratio(keyword: str, tokens: list[str]) -> float:
        if not tokens:
            return 0.0
        best = 0.0
        for token in tokens:
            ratio = SequenceMatcher(None, keyword, token).ratio()
            if ratio > best:
                best = ratio
        return best


def build_default_persona_registry() -> PersonaRegistry:
    prompts_root = Path(__file__).resolve().parent / "prompts"
    return PersonaRegistry(prompts_root=prompts_root)


__all__ = [
    "PersonaDefinition",
    "PersonaSelection",
    "PersonaRegistry",
    "build_default_persona_registry",
]