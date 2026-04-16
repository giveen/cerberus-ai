from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable


@dataclass(frozen=True)
class PlanExecutionSelection:
    """Bridges validated planner tool nodes to concrete callable tool objects."""

    selected_tools: list[Any]
    missing_tool_names: list[str]


def select_tools_for_execution(
    *,
    available_tools: Iterable[Any],
    allowed_tool_names: set[str],
) -> PlanExecutionSelection:
    selected: list[Any] = []
    selected_names: set[str] = set()

    for tool in available_tools:
        tool_name = getattr(tool, "name", None) or getattr(tool, "__name__", "")
        normalized_name = str(tool_name or "").strip()
        if not normalized_name or normalized_name not in allowed_tool_names:
            continue
        selected.append(tool)
        selected_names.add(normalized_name)

    missing = sorted(name for name in allowed_tool_names if name not in selected_names)
    return PlanExecutionSelection(selected_tools=selected, missing_tool_names=missing)
