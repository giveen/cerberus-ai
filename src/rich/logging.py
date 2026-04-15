from __future__ import annotations

import logging
from typing import Any


class RichHandler(logging.StreamHandler):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        kwargs.pop("console", None)
        kwargs.pop("markup", None)
        kwargs.pop("show_path", None)
        kwargs.pop("show_time", None)
        super().__init__(*args, **kwargs)