from __future__ import annotations

from typing import Any


class Live:
    def __init__(self, renderable: Any, *args: Any, **kwargs: Any) -> None:
        _ = args, kwargs
        self.renderable = renderable

    def __enter__(self) -> "Live":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False

    def update(self, renderable: Any) -> None:
        self.renderable = renderable