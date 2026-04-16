from dataclasses import dataclass, field
from typing import Any, Generic

from typing_extensions import TypeVar

from .usage import Usage

TContext = TypeVar("TContext", default=Any)


@dataclass
class RunContextWrapper(Generic[TContext]):
    """This wraps the context object that you passed to `Runner.run()`. It also contains
    information about the usage of the agent run so far.

    NOTE: Contexts are not passed to the LLM. They're a way to pass dependencies and data to code
    you implement, like tool functions, callbacks, hooks, etc.
    """

    context: TContext
    """The context object (or None), passed by you to `Runner.run()`"""

    usage: Usage = field(default_factory=Usage)
    """The usage of the agent run so far. For streamed responses, the usage will be stale until the
    last chunk of the stream is processed.
    """

    last_tool_name: str = ""
    """Most recent primary tool name seen in the current run loop."""

    last_tool_args: str = ""
    """Normalized arguments for the most recent primary tool call."""

    consecutive_tool_count: int = 0
    """How many times the current primary tool signature has repeated consecutively."""

    last_tool_validation: dict[str, Any] = field(default_factory=dict)
    """Latest runner-level tool validation metadata for repeat-call guidance."""

    format_correction_count: int = 0
    """How many corrective turns have been injected for format violations in this run."""

    last_tool_error_signature: str = ""
    """Signature of the most recent runner-detected tool error used for escalation."""

    consecutive_tool_error_count: int = 0
    """Number of consecutive turns that hit the same runner-detected tool error."""

    suppress_next_tool_loop_warning: bool = False
    """Skip the outer generic loop warning when a targeted retry injection already fired."""

    policy_audit_history: list[dict[str, Any]] = field(default_factory=list)
    """Recent preflight/post-audit policy reports captured during the run loop."""
