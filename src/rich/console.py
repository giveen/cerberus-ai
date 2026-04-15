from __future__ import annotations

import json
import re
import sys
from typing import Any, TextIO


_MARKUP_RE = re.compile(r"\[/?[^\]]+\]")


def renderable_to_text(renderable: Any) -> str:
    if renderable is None:
        return ""
    if isinstance(renderable, str):
        return _MARKUP_RE.sub("", renderable)
    return str(renderable)


class Group:
    def __init__(self, *renderables: Any) -> None:
        self.renderables = list(renderables)

    def __str__(self) -> str:
        return "\n".join(renderable_to_text(item) for item in self.renderables)


class Console:
    def __init__(
        self,
        *args: Any,
        file: TextIO | None = None,
        stderr: bool = False,
        width: int = 100,
        record: bool = True,
        color_system: str | None = "standard",
        **kwargs: Any,
    ) -> None:
        _ = args, kwargs
        self.file = file or (sys.stderr if stderr else sys.stdout)
        self.width = width
        self.record = record
        self.color_system = color_system
        self._buffer: list[str] = []

    @property
    def is_terminal(self) -> bool:
        return bool(getattr(self.file, "isatty", lambda: False)())

    def print(self, *objects: Any, sep: str = " ", end: str = "\n", **kwargs: Any) -> None:
        _ = kwargs
        text = sep.join(renderable_to_text(obj) for obj in objects)
        self.file.write(text + end)
        self.file.flush()
        if self.record:
            self._buffer.append(text + end)

    def print_json(self, json: str | None = None, *, data: Any = None, **kwargs: Any) -> None:
        _ = kwargs
        if data is not None:
            payload = data
        elif json is not None:
            try:
                payload = __import__("json").loads(json)
            except Exception:
                self.print(json)
                return
        else:
            payload = {}
        self.print(__import__("json").dumps(payload, indent=2, ensure_ascii=True, default=str))

    def input(self, prompt: str = "") -> str:
        return input(renderable_to_text(prompt))

    def export_text(self, *, clear: bool = False) -> str:
        text = "".join(self._buffer)
        if clear:
            self._buffer.clear()
        return text