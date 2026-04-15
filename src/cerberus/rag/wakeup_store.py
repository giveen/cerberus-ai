"""Global accessor for a singleton WakeupIndex instance.

Provides a simple `get_global_wakeup_index()` factory so different parts
of the application can share a single WakeupIndex without tight
coupling or circular imports.
"""
from __future__ import annotations

from typing import Optional, Any

from cerberus.rag.wakeup_index import WakeupIndex


_GLOBAL_WAKEUP: Optional[WakeupIndex] = None


def get_global_wakeup_index(max_facts_per_session: int = 200, embeddings_provider: Optional[Any] = None) -> WakeupIndex:
    """Return a singleton WakeupIndex, creating it on first use."""
    global _GLOBAL_WAKEUP
    if _GLOBAL_WAKEUP is None:
        _GLOBAL_WAKEUP = WakeupIndex(max_facts_per_session=max_facts_per_session, embeddings_provider=embeddings_provider)
    return _GLOBAL_WAKEUP


def set_global_wakeup_index(index: WakeupIndex) -> None:
    """Replace the global WakeupIndex (useful for tests)."""
    global _GLOBAL_WAKEUP
    _GLOBAL_WAKEUP = index


__all__ = ["get_global_wakeup_index", "set_global_wakeup_index"]
