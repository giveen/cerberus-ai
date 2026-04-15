from __future__ import annotations

import re


_MARKUP_RE = re.compile(r"\[/?[^\]]+\]")


class Text(str):
    def __new__(cls, value: str = "", *args, **kwargs):
        _ = args, kwargs
        return super().__new__(cls, value)

    @classmethod
    def from_markup(cls, value: str) -> "Text":
        return cls(_MARKUP_RE.sub("", value))

    @property
    def plain(self) -> str:
        return str(self)