from __future__ import annotations

from typing import Any

from .console import renderable_to_text


class Tree:
    def __init__(self, label: Any, *args: Any, **kwargs: Any) -> None:
        _ = args, kwargs
        self.label = renderable_to_text(label)
        self.children: list["Tree"] = []

    def add(self, label: Any, *args: Any, **kwargs: Any) -> "Tree":
        child = Tree(label, *args, **kwargs)
        self.children.append(child)
        return child

    def __str__(self) -> str:
        lines = [self.label]
        for child in self.children:
            for line in str(child).splitlines():
                lines.append(f"  {line}")
        return "\n".join(lines)