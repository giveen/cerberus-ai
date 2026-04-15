"""Base module for the Cerebro REPL command framework.

Defines ``FrameworkCommand``, the abstract base class that every CLI command
must subclass.  The class enforces a strict execution contract:

* ``execute(args)``  — the mandatory async entry-point for all logic.
* ``help()``         — mandatory self-documentation and security warnings.
* Automatic audit-logging of start/end time and user identity for every
  invocation (commercial compliance hook).
* Input sanitisation applied *before* ``execute`` is reached.

Module-level registry helpers (``register_command``, ``get_command``,
``handle_command``) are intentionally kept for drop-in compatibility so that
existing code importing from this module continues to work without changes.

Adding a new command is as simple as creating a new file under
``cerberus/repl/commands/`` and subclassing ``FrameworkCommand``.
"""

from __future__ import annotations

import asyncio
import getpass
import logging
import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from rich.console import Console  # pylint: disable=import-error

__all__ = [
    "FrameworkCommand",
    "Command",          # back-compat alias
    "SessionContext",
    "CommandError",
    "ValidationError",
    "AuditRecord",
    "COMMANDS",
    "COMMAND_ALIASES",
    "register_command",
    "get_command",
    "handle_command",
]

_log = logging.getLogger(__name__)
console = Console()

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class CommandError(Exception):
    """Raised when a command fails during execution."""

    def __init__(self, message: str, command_name: str = "", exit_code: int = 1):
        super().__init__(message)
        self.command_name = command_name
        self.exit_code = exit_code


class ValidationError(CommandError):
    """Raised when user-supplied arguments fail sanitisation."""


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

@dataclass
class AuditRecord:
    """Immutable record written for every command execution."""

    command: str
    args: List[str]
    user: str
    start_time: float
    end_time: float = 0.0
    success: bool = False
    error: Optional[str] = None

    @property
    def elapsed_ms(self) -> float:
        return (self.end_time - self.start_time) * 1_000


# ---------------------------------------------------------------------------
# Session context
# ---------------------------------------------------------------------------

@dataclass
class SessionContext:
    """Shared session state injected into every command instance.

    ``workspace`` and ``memory`` are intentionally typed as ``Any`` so that
    the concrete Workspace / MemoryManager types defined elsewhere can be
    substituted without creating a circular import.
    """

    workspace: Any = None
    memory: Any = None
    user: str = field(default_factory=lambda: _current_user())
    metadata: Dict[str, Any] = field(default_factory=dict)


def _current_user() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"


# Process-wide session context; commands read from this at instantiation time.
_SESSION: SessionContext = SessionContext()


def get_session() -> SessionContext:
    """Return the process-wide ``SessionContext``."""
    return _SESSION


def set_session(ctx: SessionContext) -> None:
    """Replace the process-wide ``SessionContext`` (e.g. during testing)."""
    global _SESSION
    _SESSION = ctx


# ---------------------------------------------------------------------------
# Input sanitisation helpers
# ---------------------------------------------------------------------------

# Characters that have no place in REPL argument tokens
_DANGEROUS_PATTERN = re.compile(
    r"[;&|`$<>]"           # shell metacharacters
    r"|\.\./"              # path traversal
    r"|\x00"               # null bytes
)


def _sanitize_token(token: str) -> str:
    """Strip or reject a single argument token.

    Raises ``ValidationError`` if the token contains injection-risk sequences.
    """
    if _DANGEROUS_PATTERN.search(token):
        raise ValidationError(
            f"Argument contains disallowed characters: {token!r}",
            exit_code=2,
        )
    return token.strip()


# ---------------------------------------------------------------------------
# Abstract base class
# ---------------------------------------------------------------------------

class FrameworkCommand(ABC):
    """Abstract base class for all Cerebro REPL commands.

    Subclass this, implement ``execute()``, ``help()``, and set
    ``name`` / ``description``.  Register the instance with
    ``register_command()`` and the REPL will pick it up automatically.

    Execution flow (via ``handle()``)::

        sanitize_args(args)
        → _audit_before()
        → await execute(clean_args)
        → _audit_after()

    All of that is handled by ``handle()``; subclasses only need to write
    their domain logic inside ``execute()``.
    """

    #: Primary REPL token, e.g. ``"/agent"``.  Must be set by sub-classes.
    name: str = ""
    #: One-line description shown in listing tables.
    description: str = ""
    #: Alternative tokens that resolve to this command.
    aliases: List[str] = []

    def __init__(self) -> None:
        # Snapshot the session context at instantiation so commands always
        # have a valid reference even if the session is replaced later.
        self._session: SessionContext = get_session()
        # Sub-command dispatch table (name → handler callable).
        self._subcommands: Dict[str, str] = {}

    # -- properties exposed to sub-classes -----------------------------------

    @property
    def session(self) -> SessionContext:
        return self._session

    @property
    def workspace(self) -> Any:
        return self._session.workspace

    @property
    def memory(self) -> Any:
        return self._session.memory

    # -- mandatory contract --------------------------------------------------

    @abstractmethod
    async def execute(self, args: List[str]) -> bool:
        """Execute the command with pre-sanitised arguments.

        Returns ``True`` on success, ``False`` on handled failure.
        Raise ``CommandError`` for unhandled failures.
        """

    @property
    @abstractmethod
    def help(self) -> str:  # type: ignore[override]
        """Return usage instructions and any relevant security warnings.

        Example::

            return (
                "Usage: /agent load <key> [--caps cap1,cap2]\\n"
                "WARNING: ensure the key belongs to a trusted registry file."
            )
        """

    # -- input sanitisation --------------------------------------------------

    def sanitize_args(self, args: Optional[List[str]]) -> List[str]:
        """Validate and clean raw argument tokens.

        Raises ``ValidationError`` on any suspicious input.  Sub-classes may
        override this to add domain-specific rules but should call
        ``super().sanitize_args(args)`` first.
        """
        if args is None:
            return []
        return [_sanitize_token(a) for a in args]

    # -- audit helpers -------------------------------------------------------

    def _audit_before(self, args: List[str]) -> AuditRecord:
        record = AuditRecord(
            command=self.name,
            args=args,
            user=self._session.user,
            start_time=time.time(),
        )
        _log.info("[AUDIT] START  cmd=%s user=%s args=%r", self.name, record.user, args)
        return record

    def _audit_after(self, record: AuditRecord, *, success: bool, error: Optional[str] = None) -> None:
        record.end_time = time.time()
        record.success = success
        record.error = error
        _log.info(
            "[AUDIT] END    cmd=%s user=%s elapsed=%.1fms success=%s error=%s",
            record.command, record.user, record.elapsed_ms, success, error or "-",
        )

    # -- public dispatcher ---------------------------------------------------

    def handle(self, args: Optional[List[str]] = None) -> bool:
        """Synchronous entry-point used by the REPL loop.

        Sanitises arguments, runs the audit hook, dispatches to
        ``execute()``, and returns a bool result.  If there is already a
        running event loop (e.g. inside an async TUI) the coroutine is
        scheduled as a task; otherwise a new loop is used.
        """
        try:
            clean = self.sanitize_args(args)
        except ValidationError as exc:
            console.print(f"[red]Input validation failed: {exc}[/red]")
            return False

        record = self._audit_before(clean)
        try:
            result = self._run_execute(clean)
        except CommandError as exc:
            self._audit_after(record, success=False, error=str(exc))
            console.print(f"[red]{self.name}: {exc}[/red]")
            return False
        except Exception as exc:  # pylint: disable=broad-except
            self._audit_after(record, success=False, error=repr(exc))
            console.print(f"[red]{self.name}: unexpected error — {exc}[/red]")
            return False

        self._audit_after(record, success=result)
        return result

    def _run_execute(self, args: List[str]) -> bool:
        """Drive the async ``execute()`` coroutine from a sync context."""
        coro = self.execute(args)
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            # We're inside an already-running async context.
            # Schedule the coroutine and block via run_coroutine_threadsafe
            # if called from a worker thread, otherwise create a task.
            import concurrent.futures
            future: concurrent.futures.Future[bool] = asyncio.run_coroutine_threadsafe(coro, loop)
            try:
                return future.result(timeout=120)
            except concurrent.futures.TimeoutError:
                raise CommandError(f"{self.name} timed out", self.name)
        else:
            return asyncio.run(coro)

    # -- sub-command helpers (convenience, not required) --------------------

    def add_subcommand(self, name: str, description: str, handler: Callable) -> None:  # pylint: disable=unused-argument
        """Register a named sub-command handler (optional helper)."""
        self._subcommands[name] = description
        # Store handler on the instance for retrieval by dispatch logic
        setattr(self, f"_sub_{name}", handler)

    def get_subcommands(self) -> List[str]:
        return list(self._subcommands.keys())

    def get_subcommand_description(self, name: str) -> str:
        return self._subcommands.get(name, "")

    def handle_no_args(self) -> bool:
        subs = ", ".join(self.get_subcommands())
        console.print(f"[yellow]{self.name}: sub-command required ({subs})[/yellow]")
        return False

    def handle_unknown_subcommand(self, sub: str) -> bool:
        console.print(f"[red]{self.name}: unknown sub-command '{sub}'[/red]")
        return False

    def __repr__(self) -> str:
        return f"<{type(self).__name__} name={self.name!r}>"


# ---------------------------------------------------------------------------
# Back-compat alias — existing code that does ``class Foo(Command)`` still
# works.  ``Command`` is a concrete (non-abstract) passthrough that provides
# default no-op implementations so legacy subclasses that override ``handle``
# directly don't need to implement ``execute`` or ``help``.
# ---------------------------------------------------------------------------

class Command(FrameworkCommand):
    """Concrete shim kept for backward compatibility.

    Legacy commands that override ``handle()`` directly and never call
    ``execute()`` / ``help()`` will continue to work unchanged.
    """

    name: str = ""
    description: str = ""
    aliases: List[str] = []

    def __init__(self, name: str = "", description: str = "", aliases: Optional[List[str]] = None):
        # Allow positional construction used by legacy code.
        self.name = name or self.__class__.name
        self.description = description or self.__class__.description
        self.aliases = aliases if aliases is not None else list(self.__class__.aliases)
        super().__init__()
        self.subcommands: Dict[str, Dict[str, Any]] = {}

    async def execute(self, args: List[str]) -> bool:  # type: ignore[override]
        """Default execute delegates to ``handle()``'s sub-command dispatch."""
        if not args:
            return self.handle_no_args()
        sub = args[0]
        registered = self.subcommands.get(sub)
        if registered:
            handler = registered.get("handler")
            if callable(handler):
                return bool(handler(args[1:] or None))
        handler = getattr(self, f"handle_{sub}", None)
        if handler:
            return bool(handler(args[1:] or None))
        return self.handle_unknown_subcommand(sub)

    @property
    def help(self) -> str:
        return f"{self.name} — {self.description}"

    def add_subcommand(self, name: str, description: str, handler: Callable) -> None:  # type: ignore[override]
        self.subcommands[name] = {
            "description": description,
            "handler": handler,
        }
        self._subcommands[name] = description

    def get_subcommands(self) -> List[str]:  # type: ignore[override]
        return list(self.subcommands.keys())

    def get_subcommand_description(self, name: str) -> str:  # type: ignore[override]
        entry = self.subcommands.get(name)
        if not entry:
            return ""
        return str(entry.get("description", ""))

    # Legacy commands override ``handle`` directly; honour that by not
    # wrapping through the audit/sanitise path unless they call super().
    def handle(self, args: Optional[List[str]] = None) -> bool:  # type: ignore[override]
        """Pass-through dispatcher for legacy command subclasses."""
        clean: List[str]
        try:
            clean = self.sanitize_args(args)
        except ValidationError as exc:
            console.print(f"[red]Input validation failed: {exc}[/red]")
            return False

        record = self._audit_before(clean)
        try:
            if not clean:
                result = self.handle_no_args()
            else:
                sub = clean[0]
                handler = None
                registered = self.subcommands.get(sub)
                if registered:
                    maybe_handler = registered.get("handler")
                    if callable(maybe_handler):
                        handler = maybe_handler
                if handler is None:
                    handler = getattr(self, f"handle_{sub}", None)
                if handler:
                    result = handler(clean[1:] or None)
                else:
                    result = self.handle_unknown_subcommand(sub)
        except CommandError as exc:
            self._audit_after(record, success=False, error=str(exc))
            console.print(f"[red]{self.name}: {exc}[/red]")
            return False
        except Exception as exc:  # pylint: disable=broad-except
            self._audit_after(record, success=False, error=repr(exc))
            raise

        self._audit_after(record, success=bool(result))
        return bool(result)


# ---------------------------------------------------------------------------
# Global command registry
# ---------------------------------------------------------------------------

COMMANDS: Dict[str, FrameworkCommand] = {}
COMMAND_ALIASES: Dict[str, str] = {}


def register_command(command: FrameworkCommand) -> None:
    """Register *command* in the process-wide registry."""
    COMMANDS[command.name] = command
    for alias in command.aliases:
        COMMAND_ALIASES[alias] = command.name


def get_command(name: str) -> Optional[FrameworkCommand]:
    """Look up a command by primary name or alias."""
    resolved = COMMAND_ALIASES.get(name, name)
    return COMMANDS.get(resolved)


def handle_command(command: str, args: Optional[List[str]] = None) -> bool:
    """Convenience dispatcher: look up *command* and call its ``handle()``."""
    cmd = get_command(command)
    if cmd:
        return cmd.handle(args)

    try:
        from cerberus.internal.dispatcher import GLOBAL_COMMAND_DISPATCHER

        result = GLOBAL_COMMAND_DISPATCHER.dispatch(command, list(args or []))
        return bool(result.exit_code == 0)
    except Exception:
        return False
