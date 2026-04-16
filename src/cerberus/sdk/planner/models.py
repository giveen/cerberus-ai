from __future__ import annotations

from enum import Enum


class DependencyKind(str, Enum):
    """Classifies dependency tokens referenced by execution plans."""

    INTERNAL_TOOL = "INTERNAL_TOOL"
    SYSTEM_BINARY = "SYSTEM_BINARY"
    EXTERNAL_CAPABILITY = "EXTERNAL_CAPABILITY"
