"""REPL Context-Aware Suggestion Engine.

Provides ``FrameworkCompleter``, a prompt_toolkit ``Completer`` subclass that
drives all tab-completion in the Cerebro REPL.  Unlike a static word list, this
engine queries live framework state at suggestion time:

Data sources (all lazy, thread-safe, TTL-cached):
    _CommandSource  — reads ``COMMANDS`` + ``COMMAND_ALIASES`` from base.py.
    _AgentSource    — reads ``get_available_agents()`` from the agent package.
    _ToolSource     — reads tools from the active agent via AGENT_MANAGER.
    _ModelSource    — reads predefined models; optionally extends with Ollama.
    _PathSource     — filesystem path completion restricted to the active
                      workspace directory (injection-safe).

Fuzzy matching:
    ``_EditDistance`` implements the Wagner-Fischer algorithm for normalised
    Levenshtein distance.  Suggestions with distance ≤ threshold are ranked
    after exact prefix matches.

Completion flow (``get_completions``):
    1. Tokenise ``document.text_before_cursor``.
    2. Identify depth (main command / subcommand / argument).
    3. Route to the appropriate source(s).
    4. Yield prefix matches first, fuzzy matches second, ranked by usage freq.

Back-compat:
    ``FuzzyCommandCompleter`` is an alias for ``FrameworkCompleter`` so any
    existing import continues to work without changes.
"""

from __future__ import annotations

import os
import threading
import time
from functools import lru_cache
from pathlib import Path
from typing import Dict, Generator, Iterable, List, Optional, Tuple

from prompt_toolkit.completion import Completer, Completion   # type: ignore[import-untyped]
from prompt_toolkit.document import Document                   # type: ignore[import-untyped]
from prompt_toolkit.formatted_text import HTML                 # type: ignore[import-untyped]

from cerberus.repl.commands.base import (
    COMMAND_ALIASES,
    COMMANDS,
    get_session,
)
from cerberus.repl.commands.model import get_predefined_model_names  # type: ignore[import-untyped]

__all__ = [
    "FrameworkCompleter",
    "FuzzyCommandCompleter",  # back-compat alias
]

# ---------------------------------------------------------------------------
# Fuzzy matcher — Wagner-Fischer Levenshtein (original implementation)
# ---------------------------------------------------------------------------

class _EditDistance:
    """Compute normalised Levenshtein distance between two strings.

    Uses the standard Wagner-Fischer DP algorithm.  All comparison is
    case-insensitive so that 'cve' matches 'CVE'.

    The *normalised* distance is ``raw / max(len(a), len(b))`` giving a value
    in [0, 1].  A threshold of 0.4 works well for short REPL tokens.
    """

    __slots__ = ()

    @staticmethod
    def raw(a: str, b: str) -> int:
        """Return the raw edit distance between *a* and *b*."""
        a, b = a.lower(), b.lower()
        la, lb = len(a), len(b)
        if la == 0:
            return lb
        if lb == 0:
            return la
        # Two-row DP; avoids O(m×n) space
        prev = list(range(lb + 1))
        for i, ca in enumerate(a, 1):
            curr = [i] + [0] * lb
            for j, cb in enumerate(b, 1):
                if ca == cb:
                    curr[j] = prev[j - 1]
                else:
                    curr[j] = 1 + min(prev[j], curr[j - 1], prev[j - 1])
            prev = curr
        return prev[lb]

    @classmethod
    def normalised(cls, a: str, b: str) -> float:
        """Return normalised distance in [0, 1]."""
        longer = max(len(a), len(b))
        if longer == 0:
            return 0.0
        return cls.raw(a, b) / longer

    @classmethod
    def is_close(cls, query: str, candidate: str, threshold: float = 0.40) -> bool:
        """Return True when candidate is within *threshold* edit distance of query."""
        if not query:
            return True
        if candidate.lower().startswith(query.lower()):
            return True
        return cls.normalised(query, candidate) <= threshold


_ED = _EditDistance()


# ---------------------------------------------------------------------------
# TTL cache helper
# ---------------------------------------------------------------------------

class _TTLCache:
    """Thread-safe key→value store with per-entry TTL."""

    def __init__(self, ttl: float = 60.0) -> None:
        self._data: Dict[str, Tuple[float, object]] = {}
        self._lock = threading.Lock()
        self._ttl = ttl

    def get(self, key: str) -> Optional[object]:
        with self._lock:
            entry = self._data.get(key)
            if entry and time.monotonic() - entry[0] < self._ttl:
                return entry[1]
            return None

    def set(self, key: str, value: object) -> None:
        with self._lock:
            self._data[key] = (time.monotonic(), value)

    def invalidate(self, key: str) -> None:
        with self._lock:
            self._data.pop(key, None)


# ---------------------------------------------------------------------------
# Data sources
# ---------------------------------------------------------------------------

class _CommandSource:
    """Reads live command/subcommand data from the base registry.

    The registry is process-global and mutated at import time when each
    command module is loaded, so we re-read it on every call (it is a
    plain dict lookup — O(1), well under 1 µs).
    """

    @staticmethod
    def commands() -> Dict[str, str]:
        """Return {name: description} for all registered commands."""
        return {cmd.name: cmd.description for cmd in COMMANDS.values()}

    @staticmethod
    def aliases() -> Dict[str, str]:
        """Return {alias: real_name} for all registered aliases."""
        return dict(COMMAND_ALIASES)

    @staticmethod
    def subcommands(cmd_name: str) -> Dict[str, str]:
        """Return {sub_name: description} for a command's subcommands.

        Resolves aliases to their backing command first.
        """
        real = COMMAND_ALIASES.get(cmd_name, cmd_name)
        cmd = COMMANDS.get(real)
        if not cmd:
            return {}
        return {sub: cmd.get_subcommand_description(sub) for sub in cmd.get_subcommands()}


class _AgentSource:
    """Lazy-loaded, TTL-cached list of available agent keys.

    Refresh happens at most once per *ttl* seconds.  An additional
    background thread primes the cache at startup so the first Tab press
    never blocks.
    """

    _TTL = 60.0

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._keys: List[str] = []
        self._last: float = 0.0
        # Warm cache in background
        threading.Thread(target=self._refresh, daemon=True).start()

    def keys(self) -> List[str]:
        """Return agent key list; refresh if stale (non-blocking on hot path)."""
        if time.monotonic() - self._last > self._TTL:
            # Refresh inline if the lock is immediately available; else use stale data
            if self._lock.acquire(blocking=False):
                try:
                    self._do_refresh()
                finally:
                    self._lock.release()
        return list(self._keys)

    def _refresh(self) -> None:
        with self._lock:
            self._do_refresh()

    def _do_refresh(self) -> None:
        try:
            from cerberus.agents import get_available_agents  # type: ignore[import-untyped]
            agents = get_available_agents()
            result: List[str] = []
            for key, agent in agents.items():
                # Skip parallel-pattern agents (match /agent list behaviour)
                if hasattr(agent, "_pattern"):
                    pat = agent._pattern
                    if hasattr(pat, "type"):
                        if getattr(getattr(pat.type, "value", str(pat.type)), "__str__", lambda: str(pat.type))() == "parallel":
                            continue
                result.append(key)
            self._keys = result
        except Exception:  # pylint: disable=broad-except
            pass
        self._last = time.monotonic()


class _ToolSource:
    """Returns the tool names attached to the currently active agent."""

    _TTL = 30.0
    _cache: Optional[Tuple[float, List[str]]] = None

    @classmethod
    def names(cls) -> List[str]:
        if cls._cache and time.monotonic() - cls._cache[0] < cls._TTL:
            return cls._cache[1]
        result: List[str] = []
        try:
            from cerberus.agents.simple_agent_manager import AGENT_MANAGER  # type: ignore[import-untyped]
            agent = AGENT_MANAGER.get_active_agent()
            if agent and hasattr(agent, "tools"):
                for t in agent.tools:
                    name = getattr(t, "name", None) or getattr(t, "__name__", None)
                    if name:
                        result.append(name)
        except Exception:  # pylint: disable=broad-except
            pass
        cls._cache = (time.monotonic(), result)
        return result


class _ModelSource:
    """Lazy-loaded list of models (predefined + Ollama)."""

    _TTL = 120.0

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._models: List[str] = []
        self._last: float = 0.0
        threading.Thread(target=self._refresh, daemon=True).start()

    def models(self) -> List[str]:
        if time.monotonic() - self._last > self._TTL:
            if self._lock.acquire(blocking=False):
                try:
                    self._do_refresh()
                finally:
                    self._lock.release()
        return list(self._models)

    def _refresh(self) -> None:
        with self._lock:
            self._do_refresh()

    def _do_refresh(self) -> None:
        result: List[str] = list(get_predefined_model_names())
        # Optional: extend with Ollama models (≤ 0.5 s budget)
        try:
            from cerberus.util import get_ollama_api_base  # type: ignore[import-untyped]
            import urllib.request
            import json as _json
            base = get_ollama_api_base().replace("/v1", "")
            req = urllib.request.Request(f"{base}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=0.5) as resp:
                data = _json.loads(resp.read())
            for m in data.get("models", data.get("items", [])):
                name = m.get("name", "")
                if name:
                    result.append(name)
        except Exception:  # pylint: disable=broad-except
            pass
        self._models = result
        self._last = time.monotonic()


class _PathSource:
    """Workspace-scoped filesystem path completer.

    Only paths that share the resolved workspace root as a prefix are
    returned, preventing directory-traversal leakage.
    """

    @staticmethod
    def _workspace_root() -> Optional[Path]:
        session = get_session()
        ws = session.workspace
        if ws is None:
            return None
        raw = str(ws) if isinstance(ws, str) else getattr(ws, "path", None)
        if not raw:
            return None
        return Path(raw).resolve(strict=False)

    @classmethod
    def completions(cls, partial: str) -> List[Tuple[str, bool]]:
        """Return ``[(path_suggestion, is_dir), ...]`` scoped to workspace.

        *partial* is the fragment the user has typed so far (may be empty).
        Returns an empty list when no workspace is configured or partial
        contains an injection attempt.
        """
        # Reject traversal
        if ".." in partial or "\x00" in partial:
            return []

        root = cls._workspace_root()
        if not root:
            return []

        search_dir: Path
        prefix: str
        if partial:
            candidate = (root / partial)
            if candidate.is_dir():
                search_dir = candidate
                prefix = partial.rstrip("/") + "/"
            else:
                search_dir = candidate.parent
                prefix = partial
        else:
            search_dir = root
            prefix = ""

        # Guard against escaping workspace
        real_dir = search_dir.resolve(strict=False)
        try:
            real_dir.relative_to(root)
        except ValueError:
            return []

        try:
            entries = list(real_dir.iterdir())
        except OSError:
            return []

        results: List[Tuple[str, bool]] = []
        fragment = Path(partial).name if partial else ""
        for entry in entries:
            if entry.name.startswith("."):
                continue  # Skip hidden entries
            if not entry.name.startswith(fragment):
                continue
            rel = entry.relative_to(root).as_posix()
            results.append((rel, entry.is_dir()))
        return results


# ---------------------------------------------------------------------------
# MCP server source (thin wrapper around existing mcp module)
# ---------------------------------------------------------------------------

def _mcp_server_names() -> List[str]:
    try:
        from cerberus.repl.commands.mcp import _GLOBAL_MCP_SERVERS  # type: ignore[import-untyped]
        return list(_GLOBAL_MCP_SERVERS.keys())
    except Exception:  # pylint: disable=broad-except
        return []


# ---------------------------------------------------------------------------
# Slash-normalisation helper
# ---------------------------------------------------------------------------

def _bare(token: str) -> str:
    """Strip a leading '/' from a REPL token so it can be looked up in COMMANDS."""
    return token.lstrip("/")


# ---------------------------------------------------------------------------
# FrameworkCompleter
# ---------------------------------------------------------------------------

class FrameworkCompleter(Completer):
    """Context-Aware Suggestion Engine for the Cerebro REPL.

    Sources are queried lazily and cached to keep every keystroke under 10 ms.
    Fuzzy matching (Levenshtein ≤ 0.4) catches minor typos without returning
    noise.

    Typical usage::

        from cerberus.repl.commands.completer import FrameworkCompleter
        completer = FrameworkCompleter()
        # pass to prompt_toolkit session
    """

    def __init__(self) -> None:
        super().__init__()
        # Per-instance sources
        self._agents = _AgentSource()
        self._models = _ModelSource()
        # Usage frequency for shadow / ranking
        self._usage: Dict[str, int] = {}
        # Suggestion result cache (keyed by text_before_cursor)
        self._result_cache = _TTLCache(ttl=0.8)

    # ------------------------------------------------------------------ #
    # Public back-compat helpers (kept so callers don't break)           #
    # ------------------------------------------------------------------ #

    def record_command_usage(self, command: str) -> None:
        """Record that *command* was executed (used for usage-frequency ranking)."""
        if command.startswith("/"):
            key = command.split()[0] if command.split() else command
            self._usage[key] = self._usage.get(key, 0) + 1

    def fetch_all_models(self) -> None:
        """Trigger a model-list refresh (non-blocking)."""
        self._models._refresh()  # pylint: disable=protected-access

    def fetch_all_agents(self) -> None:
        """Trigger an agent-list refresh (non-blocking)."""
        self._agents._refresh()  # pylint: disable=protected-access

    def get_command_shadow(self, text: str) -> Optional[str]:
        """Return the most used command that starts with *text*, or None."""
        if not text or not text.startswith("/"):
            return None
        best: Optional[str] = None
        best_count = 0
        for cmd, count in self._usage.items():
            if cmd.startswith(text) and cmd != text and count > best_count:
                best = cmd
                best_count = count
        return best

    # ------------------------------------------------------------------ #
    # Completion entry-point                                              #
    # ------------------------------------------------------------------ #

    def get_completions(
        self, document: Document, complete_event: object
    ) -> Generator[Completion, None, None]:
        """Yield completions for *document*.

        This method is called by prompt_toolkit on every keystroke.  It
        completes in under 10 ms as long as the underlying source caches are
        warm (which they are after the first Tab press since background threads
        prime every source at ``__init__`` time).
        """
        raw = document.text_before_cursor
        cached = self._result_cache.get(raw)
        if cached is not None:
            yield from cached  # type: ignore[arg-type]
            return

        results = list(self._compute_completions(raw))
        self._result_cache.set(raw, results)
        yield from results

    # ------------------------------------------------------------------ #
    # Internal completion logic                                           #
    # ------------------------------------------------------------------ #

    def _compute_completions(self, raw: str) -> List[Completion]:
        text = raw.strip()
        trailing_space = bool(raw) and raw[-1] == " "

        if not text:
            return self._all_commands()

        if not text.startswith("/"):
            return []

        words = text.split()
        # Build effective word list respecting trailing space
        if trailing_space:
            effective = words + [""]
        else:
            effective = words

        depth = len(effective)
        current = effective[-1]  # word being typed (may be "")

        if depth == 1:
            # Typing the main command token
            return self._command_suggestions(current)

        cmd_token = words[0]

        if depth == 2:
            return self._depth2(cmd_token, current)

        if depth == 3:
            sub_token = words[1] if len(words) > 1 else ""
            return self._depth3(cmd_token, sub_token, current)

        if depth == 4:
            sub_token = words[1] if len(words) > 1 else ""
            return self._depth4(cmd_token, sub_token, current)

        return []

    # ------------------------------------------------------------------ #
    # Depth-specific routers                                              #
    # ------------------------------------------------------------------ #

    def _depth2(self, cmd: str, current: str) -> List[Completion]:
        # Resolve alias, then normalise slash for comparison
        real = _bare(COMMAND_ALIASES.get(_bare(cmd), _bare(cmd)))
        if real == "model":
            return self._model_suggestions(current)
        if real == "agent":
            return self._agent_suggestions(current)
        # Generic subcommand (handles mcp and everything else)
        return self._subcommand_suggestions(cmd, current)

    def _depth3(self, cmd: str, sub: str, current: str) -> List[Completion]:
        real = _bare(COMMAND_ALIASES.get(_bare(cmd), _bare(cmd)))
        if real == "agent" and sub in ("select", "info", "load"):
            return self._agent_suggestions(current)
        if real == "mcp":
            if sub == "load":
                return self._static_suggestions(
                    [("stdio", "Local process"), ("sse", "HTTP/SSE")], current
                )
            if sub in ("add", "remove", "tools"):
                return self._mcp_server_suggestions(current)
        # Check if previous sub suggests file path
        if sub in ("save", "load", "open", "read", "write", "file"):
            return self._path_suggestions(current)
        return []

    def _depth4(self, cmd: str, sub: str, current: str) -> List[Completion]:
        real = _bare(COMMAND_ALIASES.get(_bare(cmd), _bare(cmd)))
        if real == "mcp" and sub == "add":
            return self._agent_suggestions(current)
        return []

    # ------------------------------------------------------------------ #
    # Suggestion builders                                                 #
    # ------------------------------------------------------------------ #

    def _all_commands(self) -> List[Completion]:
        """Yield every registered command, sorted by usage frequency."""
        cmds = _CommandSource.commands()
        ordered = sorted(cmds.items(),
                         key=lambda kv: self._usage.get(kv[0], 0), reverse=True)
        return [
            Completion(
                name, start_position=0,
                display=HTML(f"<ansicyan><b>{name:<16}</b></ansicyan>{desc}"),
                style="fg:ansicyan bold",
            )
            for name, desc in ordered
        ]

    def _command_suggestions(self, fragment: str) -> List[Completion]:
        """Prefix then fuzzy matches against registered command names.

        Handles both slash-prefixed input (``/com``) and bare input (``com``).
        Completions always preserve the slash: typing ``/com`` → ``/compact``.
        """
        cmds = _CommandSource.commands()
        aliases = _CommandSource.aliases()
        results: List[Completion] = []

        # Normalise: strip slash for matching, keep slash for completion text
        has_slash = fragment.startswith("/")
        bare_frag = fragment[1:] if has_slash else fragment
        prefix = "/" if has_slash else ""

        seen: set = set()

        # Prefix matches first (sorted by usage frequency)
        for name, desc in sorted(cmds.items(),
                                  key=lambda kv: self._usage.get("/" + kv[0], 0),
                                  reverse=True):
            full = prefix + name
            if name.startswith(bare_frag):
                seen.add(name)
                results.append(Completion(
                    full, start_position=-len(fragment),
                    display=HTML(f"<ansicyan><b>{full:<16}</b></ansicyan>{desc}"),
                    style="fg:ansicyan bold",
                ))

        # Fuzzy near-miss matches (append after prefix)
        for name, desc in cmds.items():
            if name in seen:
                continue
            if _ED.is_close(bare_frag, name):
                full = prefix + name
                results.append(Completion(
                    full, start_position=-len(fragment),
                    display=HTML(f"<ansicyan>{full:<16}</ansicyan>{desc} <dim>(~)</dim>"),
                    style="fg:ansicyan",
                ))

        # Alias completions
        for alias, real in sorted(aliases.items()):
            real_desc = cmds.get(_bare(real), cmds.get(real, ""))
            bare_alias = _bare(alias)
            full_alias = prefix + bare_alias
            if bare_alias.startswith(bare_frag) or _ED.is_close(bare_frag, bare_alias):
                bold = "bold" if bare_alias.startswith(bare_frag) else ""
                results.append(Completion(
                    full_alias, start_position=-len(fragment),
                    display=HTML(
                        f"<ansigreen><b>{full_alias:<16}</b></ansigreen>"
                        f"{real} — {real_desc}"
                    ),
                    style=f"fg:ansigreen {bold}",
                ))

        return results

    def _subcommand_suggestions(self, cmd: str, fragment: str) -> List[Completion]:
        # Normalise: COMMANDS keys don't have slashes
        subs = _CommandSource.subcommands(_bare(cmd))
        results: List[Completion] = []

        for sub, desc in sorted(subs.items()):
            if sub.startswith(fragment):
                results.append(Completion(
                    sub, start_position=-len(fragment),
                    display=HTML(f"<ansiyellow><b>{sub:<16}</b></ansiyellow>{desc}"),
                    style="fg:ansiyellow bold",
                ))

        for sub, desc in subs.items():
            if sub.startswith(fragment):
                continue
            if _ED.is_close(fragment, sub):
                results.append(Completion(
                    sub, start_position=-len(fragment),
                    display=HTML(f"<ansiyellow>{sub:<16}</ansiyellow>{desc}"),
                    style="fg:ansiyellow",
                ))

        return results

    def _model_suggestions(self, fragment: str) -> List[Completion]:
        models = self._models.models()
        results: List[Completion] = []

        for idx, name in enumerate(models, 1):
            num = str(idx)
            if num.startswith(fragment):
                results.append(Completion(
                    num, start_position=-len(fragment),
                    display=HTML(f"<ansiwhite><b>{num:<4}</b></ansiwhite>{name}"),
                    style="fg:ansiwhite bold",
                ))

        for name in models:
            if name.startswith(fragment):
                results.append(Completion(
                    name, start_position=-len(fragment),
                    display=HTML(f"<ansimagenta><b>{name}</b></ansimagenta>"),
                    style="fg:ansimagenta bold",
                ))
            elif _ED.is_close(fragment, name):
                results.append(Completion(
                    name, start_position=-len(fragment),
                    display=HTML(f"<ansimagenta>{name}</ansimagenta>"),
                    style="fg:ansimagenta",
                ))

        return results

    def _agent_suggestions(self, fragment: str) -> List[Completion]:
        keys = self._agents.keys()
        results: List[Completion] = []

        # Number shortcuts
        for idx, key in enumerate(keys, 1):
            num = str(idx)
            if num.startswith(fragment):
                results.append(Completion(
                    num, start_position=-len(fragment),
                    display=HTML(f"<ansiwhite><b>{num:<4}</b></ansiwhite>{key}"),
                    style="fg:ansiwhite bold",
                ))

        # Name matches
        for key in keys:
            if key.startswith(fragment):
                results.append(Completion(
                    key, start_position=-len(fragment),
                    display=HTML(f"<ansimagenta><b>{key}</b></ansimagenta>"),
                    style="fg:ansimagenta bold",
                ))
            elif _ED.is_close(fragment, key):
                results.append(Completion(
                    key, start_position=-len(fragment),
                    display=HTML(f"<ansimagenta>{key}</ansimagenta>"),
                    style="fg:ansimagenta",
                ))

        return results

    def _tool_suggestions(self, fragment: str) -> List[Completion]:
        names = _ToolSource.names()
        results: List[Completion] = []
        for name in names:
            if name.startswith(fragment) or _ED.is_close(fragment, name):
                bold = "bold" if name.startswith(fragment) else ""
                results.append(Completion(
                    name, start_position=-len(fragment),
                    display=HTML(f"<ansicyan{' bold' if bold else ''}>"
                                 f"{name}</ansicyan{' bold' if bold else ''}>"),
                    style=f"fg:ansicyan {bold}",
                ))
        return results

    def _mcp_server_suggestions(self, fragment: str) -> List[Completion]:
        results: List[Completion] = []
        for name in _mcp_server_names():
            if name.startswith(fragment) or _ED.is_close(fragment, name):
                bold = "bold" if name.startswith(fragment) else ""
                results.append(Completion(
                    name, start_position=-len(fragment),
                    display=HTML(f"<ansicyan{' bold' if bold else ''}>"
                                 f"{name}</ansicyan{' bold' if bold else ''}>"),
                    style=f"fg:ansicyan {bold}",
                ))
        return results

    def _path_suggestions(self, fragment: str) -> List[Completion]:
        results: List[Completion] = []
        for rel, is_dir in _PathSource.completions(fragment):
            suffix = "/" if is_dir else ""
            display_name = rel + suffix
            results.append(Completion(
                rel + suffix,
                start_position=-len(fragment),
                display=HTML(
                    f"<ansiblue>{display_name}</ansiblue>"
                    if is_dir else f"<ansiwhite>{display_name}</ansiwhite>"
                ),
                style="fg:ansiblue" if is_dir else "fg:ansiwhite",
            ))
        return results

    @staticmethod
    def _static_suggestions(
        items: Iterable[Tuple[str, str]], fragment: str
    ) -> List[Completion]:
        results: List[Completion] = []
        for name, desc in items:
            if name.startswith(fragment) or _ED.is_close(fragment, name):
                bold = "bold" if name.startswith(fragment) else ""
                results.append(Completion(
                    name, start_position=-len(fragment),
                    display=HTML(f"<ansiyellow{' bold' if bold else ''}>"
                                 f"{name}</{('ansiyellow bold' if bold else 'ansiyellow')}> {desc}"),
                    style=f"fg:ansiyellow {bold}",
                ))
        return results


# ---------------------------------------------------------------------------
# Back-compat alias
# ---------------------------------------------------------------------------

#: Legacy name kept so existing imports don't break.
FuzzyCommandCompleter = FrameworkCompleter
