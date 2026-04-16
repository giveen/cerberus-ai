# Holds the current active span
import contextvars
from typing import TYPE_CHECKING, Any

from ..logger import logger

if TYPE_CHECKING:
    from .spans import Span
    from .traces import Trace

_current_span: contextvars.ContextVar["Span[Any] | None"] = contextvars.ContextVar(
    "current_span", default=None
)

_current_trace: contextvars.ContextVar["Trace | None"] = contextvars.ContextVar(
    "current_trace", default=None
)


class Scope:
    @classmethod
    def get_current_span(cls) -> "Span[Any] | None":
        return _current_span.get()

    @classmethod
    def set_current_span(cls, span: "Span[Any] | None") -> "contextvars.Token[Span[Any] | None]":
        return _current_span.set(span)

    @classmethod
    def reset_current_span(cls, token: "contextvars.Token[Span[Any] | None]") -> None:
        try:
            _current_span.reset(token)
        except ValueError:
            # The token was created in a different Context and cannot be
            # reset in this one (happens during shutdown or when spans are
            # moved across tasks). Log and silently ignore to avoid raising
            # during cleanup.
            logger.debug("reset_current_span: token from different Context; skipping reset")

    @classmethod
    def get_current_trace(cls) -> "Trace | None":
        return _current_trace.get()

    @classmethod
    def set_current_trace(cls, trace: "Trace | None") -> "contextvars.Token[Trace | None]":
        logger.debug(f"Setting current trace: {trace.trace_id if trace else None}")
        return _current_trace.set(trace)

    @classmethod
    def reset_current_trace(cls, token: "contextvars.Token[Trace | None]") -> None:
        logger.debug("Resetting current trace")
        try:
            _current_trace.reset(token)
        except ValueError:
            logger.debug("reset_current_trace: token from different Context; skipping reset")
