"""Cerberus AI productivity-first keybinding engine for the REPL."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import subprocess  # nosec B404 - Required for screen clearing
import time
from dataclasses import dataclass
from typing import Any, Callable, Coroutine, Dict, Iterable, List, Optional, Sequence, Tuple

from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.key_binding.key_processor import KeyPressEvent
from rich.console import Console
from rich.text import Text

from cerberus.repl.commands import FuzzyCommandCompleter, get_command, handle_command
from cerberus.repl.commands.config import CONFIG_STORE
from cerberus.tools.workspace import get_project_space


AsyncEventHandler = Callable[[KeyPressEvent], Coroutine[Any, Any, None]]


@dataclass(frozen=True)
class ShortcutSpec:
    action: str
    default: Tuple[str, ...]
    description: str


class DefaultCommandRegistry:
    """Async-safe adapter over the process-wide command registry."""

    async def dispatch(self, command: str, args: Optional[List[str]] = None) -> bool:
        return await asyncio.to_thread(handle_command, command, args)

    def has(self, command: str) -> bool:
        return get_command(command) is not None


class CerberusKeyRegistry:
    """Create and manage async, remappable key bindings for REPL productivity."""

    _EXIT_CONFIRM_WINDOW = 1.5

    _DEFAULT_SHORTCUTS: Sequence[ShortcutSpec] = (
        ShortcutSpec("clear_screen", ("c-l",), "Clear terminal viewport"),
        ShortcutSpec("submit_multiline", ("escape", "enter"), "Insert newline or submit multiline text"),
        ShortcutSpec("interrupt", ("c-c",), "Interrupt active execution via kill command"),
        ShortcutSpec("cycle_workspace", ("escape", "w"), "Switch to next workspace"),
        ShortcutSpec("cycle_model", ("escape", "m"), "Switch to next LLM model"),
        ShortcutSpec("toggle_history", ("escape", "h"), "Toggle forensic history visibility"),
        ShortcutSpec("context_tab", ("tab",), "Context-aware completion for commands and file paths"),
        ShortcutSpec("safe_exit", ("c-d",), "Double-tap guard for exit"),
    )

    def __init__(
        self,
        *,
        current_text: List[str],
        command_registry: Optional[Any] = None,
        key_log: Optional[Callable[[str], None]] = None,
    ) -> None:
        self._current_text = current_text
        self._registry = command_registry or DefaultCommandRegistry()
        self._key_log = key_log or self._default_key_log
        self._console = Console()
        self._completer = FuzzyCommandCompleter()
        self._history_suggest = AutoSuggestFromHistory()
        self._last_ctrl_d = 0.0
        self._workspace_cursor = 0
        self._model_cursor = 0
        self._workspace_cache: List[str] = []
        self._model_cache: List[str] = []
        self._binding_overrides = self._load_binding_overrides()

    def build(self) -> KeyBindings:
        kb = KeyBindings()

        handlers: Dict[str, AsyncEventHandler] = {
            "clear_screen": self._clear_screen,
            "submit_multiline": self._submit_multiline,
            "interrupt": self._interrupt_execution,
            "cycle_workspace": self._cycle_workspace,
            "cycle_model": self._cycle_model,
            "toggle_history": self._toggle_history,
            "context_tab": self._handle_context_tab,
            "safe_exit": self._safe_exit,
        }

        for shortcut in self._DEFAULT_SHORTCUTS:
            sequence = self._resolve_sequence(shortcut)
            if not sequence:
                continue

            async_handler = handlers[shortcut.action]

            @kb.add(*sequence)
            def _route(event: KeyPressEvent, _handler: AsyncEventHandler = async_handler) -> None:
                event.app.create_background_task(_handler(event))

        return kb

    def _resolve_sequence(self, shortcut: ShortcutSpec) -> Optional[Tuple[str, ...]]:
        override = self._binding_overrides.get(shortcut.action)
        if override is None:
            return shortcut.default
        if isinstance(override, str):
            return self._normalize_key_sequence(override)
        if isinstance(override, list) and override:
            joined = " ".join(str(k) for k in override)
            return self._normalize_key_sequence(joined)
        return shortcut.default

    def _load_binding_overrides(self) -> Dict[str, Any]:
        raw = CONFIG_STORE.get("CERBERUS_KEYBINDINGS")
        if not raw or raw == "Not set":
            raw = os.getenv("CERBERUS_KEYBINDINGS")
        if not raw:
            return {}

        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            self._key_log("Key Log: invalid CERBERUS_KEYBINDINGS payload; using defaults")
            return {}

    def _normalize_key_sequence(self, spec: str) -> Optional[Tuple[str, ...]]:
        tokens = [item.strip().lower() for item in spec.replace("+", " ").split() if item.strip()]
        if not tokens:
            return None

        if len(tokens) >= 2 and tokens[0] in {"alt", "meta", "option"}:
            key = self._normalize_single_key(tokens[1])
            return ("escape", key) if key else None

        if len(tokens) >= 2 and tokens[0] in {"ctrl", "control", "cmd", "command"}:
            key = self._normalize_single_key(tokens[1])
            if not key:
                return None
            return (f"c-{key}",)

        normalized: List[str] = []
        for token in tokens:
            key = self._normalize_single_key(token)
            if key:
                normalized.append(key)

        return tuple(normalized) if normalized else None

    @staticmethod
    def _normalize_single_key(token: str) -> Optional[str]:
        aliases = {
            "return": "enter",
            "esc": "escape",
            "spacebar": "space",
            "del": "delete",
            "backspace": "backspace",
            "tab": "tab",
            "enter": "enter",
            "left": "left",
            "right": "right",
            "up": "up",
            "down": "down",
        }
        if token in aliases:
            return aliases[token]
        if len(token) == 1 and token.isprintable():
            return token
        if token.startswith("f") and token[1:].isdigit():
            return token
        if token.startswith("c-"):
            return token[2:]
        return None

    async def _clear_screen(self, event: KeyPressEvent) -> None:
        command = ["cls"] if os.name == "nt" else ["clear"]
        await asyncio.to_thread(subprocess.run, command, shell=False, check=False)  # nosec B603 B607
        self._key_log("Key Log: screen cleared")

    async def _submit_multiline(self, event: KeyPressEvent) -> None:
        buffer = event.current_buffer
        text = buffer.text
        if "\n" in text:
            buffer.validate_and_handle()
            self._key_log("Key Log: multiline submitted")
            return

        buffer.insert_text("\n")
        self._key_log("Key Log: multiline mode")

    async def _interrupt_execution(self, _event: KeyPressEvent) -> None:
        ok = await self._dispatch_first([
            ("/kill", ["--all", "--reason", "USER_INTERVENTION"]),
            ("/kill", ["--reason", "USER_INTERVENTION"]),
        ])
        self._key_log("Key Log: execution interrupted" if ok else "Key Log: interrupt requested")

    async def _cycle_workspace(self, _event: KeyPressEvent) -> None:
        self._workspace_cache = self._workspace_cache or self._discover_workspaces()
        if not self._workspace_cache:
            self._key_log("Key Log: no workspaces found")
            return

        current = os.getenv("CERBERUS_WORKSPACE", "")
        if current in self._workspace_cache:
            idx = self._workspace_cache.index(current)
            target = self._workspace_cache[(idx + 1) % len(self._workspace_cache)]
        else:
            target = self._workspace_cache[self._workspace_cursor % len(self._workspace_cache)]
            self._workspace_cursor += 1

        ok = await self._dispatch_first([("/workspace", ["switch", target]), ("/workspace", ["set", target])])
        self._key_log(f"Key Log: workspace -> {target}" if ok else "Key Log: workspace switch failed")

    async def _cycle_model(self, _event: KeyPressEvent) -> None:
        self._model_cache = self._model_cache or self._discover_models()
        if not self._model_cache:
            self._key_log("Key Log: no model candidates")
            return

        current = os.getenv("CERBERUS_MODEL", "")
        if current in self._model_cache:
            idx = self._model_cache.index(current)
            target = self._model_cache[(idx + 1) % len(self._model_cache)]
        else:
            target = self._model_cache[self._model_cursor % len(self._model_cache)]
            self._model_cursor += 1

        ok = await self._dispatch_first([("/model", [target]), ("/model", ["list"])])
        self._key_log(f"Key Log: model -> {target}" if ok else "Key Log: model switch failed")

    async def _toggle_history(self, _event: KeyPressEvent) -> None:
        ok = await self._dispatch_first([
            ("/history", ["--tail", "20"]),
            ("/history", []),
        ])
        self._key_log("Key Log: history toggled" if ok else "Key Log: history unavailable")

    async def _handle_context_tab(self, event: KeyPressEvent) -> None:
        buffer = event.current_buffer
        text = buffer.text
        self._current_text[0] = text

        if self._is_command_context(text):
            shadow = self._completer.get_command_shadow(text)
            if shadow and shadow.startswith(text):
                buffer.text = shadow
                buffer.cursor_position = len(shadow)
                return

        if self._is_path_context(text):
            completion = self._path_completion(text)
            if completion:
                buffer.text = completion
                buffer.cursor_position = len(completion)
                return

        suggestion = self._history_suggest.get_suggestion(buffer, buffer.document)
        if suggestion and suggestion.text:
            completed = text + suggestion.text
            buffer.text = completed
            buffer.cursor_position = len(completed)
            return

        if buffer.complete_state:
            buffer.complete_next()
        else:
            buffer.start_completion(select_first=True)

    async def _safe_exit(self, event: KeyPressEvent) -> None:
        buffer = event.current_buffer
        if buffer.text.strip():
            buffer.delete(1)
            return

        now = time.monotonic()
        if now - self._last_ctrl_d > self._EXIT_CONFIRM_WINDOW:
            self._last_ctrl_d = now
            self._key_log("Key Log: press Ctrl+D again to exit")
            return

        ok = await self._dispatch_first([("/exit", []), ("/quit", [])])
        if ok:
            self._key_log("Key Log: session exit confirmed")
            return
        event.app.exit(result="")

    async def _dispatch_first(self, attempts: Iterable[Tuple[str, List[str]]]) -> bool:
        for command, args in attempts:
            if hasattr(self._registry, "has") and not self._registry.has(command):
                continue
            if hasattr(self._registry, "dispatch"):
                try:
                    if await self._registry.dispatch(command, args):
                        return True
                except Exception:
                    continue
                continue
            try:
                if await asyncio.to_thread(handle_command, command, args):
                    return True
            except Exception:
                continue
        return False

    def _discover_workspaces(self) -> List[str]:
        root = get_project_space().ensure_initialized().resolve()
        workspace_root = root.parent / "workspaces"
        if not workspace_root.exists():
            return []
        return sorted([entry.name for entry in workspace_root.iterdir() if entry.is_dir()])

    def _discover_models(self) -> List[str]:
        custom = CONFIG_STORE.get("CERBERUS_MODEL_CYCLE") or os.getenv("CERBERUS_MODEL_CYCLE", "")
        if custom and custom != "Not set":
            models = [item.strip() for item in custom.split(",") if item.strip()]
            if models:
                return models

        return [
            "reasoner",
            "cerebro1",
            "gpt-4o",
            "claude-3-7-sonnet",
            "gemini-2.5-pro",
        ]

    @staticmethod
    def _is_command_context(text: str) -> bool:
        stripped = text.lstrip()
        return stripped.startswith("/") and " " not in stripped

    @staticmethod
    def _is_path_context(text: str) -> bool:
        token = text.rsplit(" ", 1)[-1]
        if not token:
            return False
        return token.startswith(("./", "../", "~/", "/")) or "/" in token

    @staticmethod
    def _path_completion(text: str) -> Optional[str]:
        left, token = CerberusKeyRegistry._split_token(text)
        expanded = os.path.expanduser(token)
        candidate_base = Path(expanded)
        base_dir = candidate_base if token.endswith("/") else candidate_base.parent
        prefix = "" if token.endswith("/") else candidate_base.name

        if str(base_dir) == "":
            base_dir = Path(".")

        if not base_dir.exists() or not base_dir.is_dir():
            return None

        matches = sorted([p.name for p in base_dir.iterdir() if p.name.startswith(prefix)])
        if not matches:
            return None

        if len(matches) == 1:
            replacement = matches[0]
        else:
            replacement = os.path.commonprefix(matches)
            if not replacement:
                return None

        new_token = str((base_dir / replacement).as_posix())
        if token.startswith("~/"):
            home = str(Path.home().as_posix())
            new_token = "~" + new_token[len(home):] if new_token.startswith(home) else new_token
        return f"{left}{new_token}"

    @staticmethod
    def _split_token(text: str) -> Tuple[str, str]:
        if " " not in text:
            return "", text
        idx = text.rfind(" ")
        return text[: idx + 1], text[idx + 1 :]

    def _default_key_log(self, message: str) -> None:
        subtle = Text(message, style="dim cyan")
        self._console.print(subtle)


def create_key_bindings(
    current_text: List[str],
    command_registry: Optional[Any] = None,
    key_log: Optional[Callable[[str], None]] = None,
) -> KeyBindings:
    """Build REPL key bindings with Cerberus AI productivity defaults.

    ``current_text`` is kept for backward compatibility with existing prompt shadow logic.
    """
    return CerberusKeyRegistry(
        current_text=current_text,
        command_registry=command_registry,
        key_log=key_log,
    ).build()
