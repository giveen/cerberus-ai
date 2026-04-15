from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .console import renderable_to_text


@dataclass
class Panel:
    renderable: Any
    title: str | None = None
    border_style: str | None = None
    box: Any = None

    def __str__(self) -> str:
        body = renderable_to_text(self.renderable)
        return f"{self.title}\n{body}" if self.title else body