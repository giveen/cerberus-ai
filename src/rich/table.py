from __future__ import annotations

from typing import Any

from .console import renderable_to_text


class Table:
    def __init__(
        self,
        *args: Any,
        title: str | None = None,
        expand: bool = False,
        box: Any = None,
        show_header: bool = True,
        **kwargs: Any,
    ) -> None:
        _ = args, kwargs
        self.title = title
        self.expand = expand
        self.box = box
        self.show_header = show_header
        self.columns: list[str] = []
        self.rows: list[list[str]] = []

    @classmethod
    def grid(cls, *args: Any, **kwargs: Any) -> "Table":
        kwargs.setdefault("show_header", False)
        return cls(*args, **kwargs)

    def add_column(self, header: str = "", **kwargs: Any) -> None:
        _ = kwargs
        self.columns.append(renderable_to_text(header))

    def add_row(self, *values: Any) -> None:
        self.rows.append([renderable_to_text(value) for value in values])

    def add_section(self) -> None:
        self.rows.append([])

    def update(self, other: Any) -> None:
        if isinstance(other, Table):
            self.columns = list(other.columns)
            self.rows = [list(row) for row in other.rows]
        else:
            self.rows = [[renderable_to_text(other)]]

    def __str__(self) -> str:
        lines: list[str] = []
        if self.title:
            lines.append(self.title)
        if self.columns and self.show_header:
            lines.append(" | ".join(self.columns))
        for row in self.rows:
            if not row:
                lines.append("-")
            else:
                lines.append(" | ".join(row))
        return "\n".join(lines)