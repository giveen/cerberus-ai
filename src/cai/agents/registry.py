"""Agent persona registry for role normalization and prompt discovery.

This module centralizes role alias handling and persona prompt path resolution.
It also records exact absolute paths searched for a role request so failures are
fully auditable.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence


@dataclass(frozen=True)
class PromptSearchResult:
    """Prompt lookup result for a role request."""

    role: str
    selected_path: Path | None
    searched_paths: tuple[Path, ...]

    @property
    def missing(self) -> bool:
        return self.selected_path is None


class AgentRegistry:
    """Role and persona prompt resolver for runtime agent hydration."""

    _ROLE_ALIASES: Mapping[str, str] = {
        "redteam_agent": "red_teamer",
        "red_team_agent": "red_teamer",
        "redteam": "red_teamer",
        "blue_team_agent": "blue_teamer",
        "generic": "generic_intelligence",
    }

    def __init__(self, *, prompts_root: Path, logger: object | None = None) -> None:
        self._prompts_root = prompts_root.resolve()
        self._src_root = self._prompts_root.parent
        self._logger = logger

    def normalize_role(self, value: str) -> str:
        normalized = value.strip().lower().replace("-", "_").replace(" ", "_")
        return self._ROLE_ALIASES.get(normalized, normalized)

    def prompt_candidates(self, *, role: str, stem: str) -> tuple[str, ...]:
        normalized_role = self.normalize_role(role)
        normalized_stem = self.normalize_role(stem)
        return (
            f"prompts/personas/{normalized_role}.md",
            f"prompts/personas/{normalized_role}.yaml",
            f"prompts/personas/{normalized_stem}.md",
            f"prompts/personas/{normalized_stem}.yaml",
            f"prompts/{normalized_role}.md",
            f"prompts/system_{normalized_role}.md",
            f"prompts/{normalized_stem}.md",
            f"prompts/system_{normalized_stem}.md",
            "prompts/system_reasoner_supporter.md",
        )

    def resolve_prompt_paths(
        self,
        *,
        role: str,
        stem: str,
        candidates: Sequence[str] | None = None,
    ) -> PromptSearchResult:
        normalized_role = self.normalize_role(role)
        candidate_list = tuple(candidates or self.prompt_candidates(role=normalized_role, stem=stem))

        searched: list[Path] = []
        selected: Path | None = None

        for candidate in candidate_list:
            absolute = self._candidate_to_absolute(candidate)
            searched.append(absolute)
            self._log_path_check(normalized_role, absolute)
            if absolute.is_file() and selected is None:
                selected = absolute

        return PromptSearchResult(
            role=normalized_role,
            selected_path=selected,
            searched_paths=tuple(searched),
        )

    def _candidate_to_absolute(self, candidate: str) -> Path:
        candidate_path = Path(candidate)
        if candidate_path.is_absolute():
            return candidate_path.resolve()

        candidate_norm = candidate.replace("\\", "/")
        if candidate_norm.startswith("prompts/"):
            relative = candidate_norm.split("prompts/", 1)[1]
            return (self._prompts_root / relative).resolve()

        return (self._src_root / candidate_path).resolve()

    def _log_path_check(self, role: str, absolute_path: Path) -> None:
        audit = getattr(self._logger, "audit", None)
        if not callable(audit):
            return
        audit(
            "Agent persona path validation",
            actor="AgentRegistry",
            data={"role": role, "candidate_path": str(absolute_path)},
            tags=["agent_registry", "persona_lookup"],
            terminal=False,
        )


__all__ = ["AgentRegistry", "PromptSearchResult"]
