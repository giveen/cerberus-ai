"""Cerberus AI REPL prompt HUD engine.

Provides a high-performance, dynamic prompt implementation that reflects
workspace/model/cost/agent status in real time while preserving backwards
compatibility with the existing ``get_user_input`` integration.
"""

from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Callable, Dict, List, Optional, Tuple

from prompt_toolkit import PromptSession  # pylint: disable=import-error
from prompt_toolkit.application.current import get_app_or_none  # pylint: disable=import-error
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory  # pylint: disable=import-error
from prompt_toolkit.formatted_text import HTML  # pylint: disable=import-error
from prompt_toolkit.history import FileHistory  # pylint: disable=import-error
from prompt_toolkit.styles import Style  # pylint: disable=import-error
from rich.console import Console

from cerberus.memory.logic import clean
from cerberus.repl.commands import FuzzyCommandCompleter
from cerberus.repl.commands.config import CONFIG_STORE
from cerberus.repl.ui.logging import prepare_prompt_history_file
from cerberus.tools.workspace import get_project_space
from cerberus.util import COST_TRACKER

_SECRETISH_RE = re.compile(r"(?i)(token|secret|password|apikey|api_key|key=|bearer)")
_HOSTISH_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|[A-Za-z0-9._-]+\.[A-Za-z]{2,}\b")
_PROMPT_SESSIONS: Dict[str, PromptSession] = {}


@dataclass(frozen=True)
class HUDSnapshot:
    workspace: str
    target: str
    cost_total: float
    cost_limit: float
    model: str
    agent_status: str
    multiline: bool
    budget_exceeded: bool


class CerberusPromptHUD:
    """Dependency-injected prompt HUD generator with event-sensitive styling."""

    def __init__(
        self,
        *,
        config: Any = None,
        workspace_manager: Any = None,
        cost_manager: Any = None,
        model_provider: Optional[Callable[[], str]] = None,
        agent_status_provider: Optional[Callable[[], str]] = None,
        ansi_safe: Optional[bool] = None,
    ) -> None:
        self._config = config or CONFIG_STORE
        self._workspace_manager = workspace_manager
        self._cost_manager = cost_manager or COST_TRACKER
        self._model_provider = model_provider
        self._agent_status_provider = agent_status_provider
        self._ansi_safe = self._detect_ansi_safe() if ansi_safe is None else bool(ansi_safe)
        self._unicode_safe = self._detect_unicode_safe()
        self._state_cache: Optional[HUDSnapshot] = None
        self._state_cache_t = 0.0
        self._state_cache_ttl = 0.08

    def get_prompt_fragments(self, current_text: str) -> List[Tuple[str, str]]:
        state = self._snapshot(current_text)
        primary_label = "CERBERUS>"
        continuation_label = "...".ljust(len(primary_label) - 1) + ">"
        prompt_label = continuation_label if state.multiline else primary_label
        if not self._ansi_safe:
            return [
                (
                    "class:hud.plain",
                    f"[{state.workspace}] ${state.cost_total:.4f}/{self._fmt_limit(state.cost_limit)} "
                    f"{state.model} {state.agent_status} {prompt_label} ",
                )
            ]

        palette = self._palette_for(state)
        icon_model = "🧠" if self._unicode_safe else "M"
        icon_workspace = "💼" if self._unicode_safe else "W"
        icon_cost = "💳" if self._unicode_safe else "$"
        icon_status = "⚡" if self._unicode_safe else "S"

        segments: List[Tuple[str, str]] = [
            ("class:hud.seg0", f" {prompt_label} "),
            ("class:hud.sep", " "),
            ("class:hud.seg1", f" {icon_workspace} {state.workspace} "),
            ("class:hud.sep", " "),
            (
                palette["cost"],
                f" {icon_cost} ${state.cost_total:.4f}/{self._fmt_limit(state.cost_limit)} ",
            ),
            ("class:hud.sep", " "),
            ("class:hud.seg3", f" {icon_model} {state.model} "),
            ("class:hud.sep", " "),
            (palette["status"], f" {icon_status} {state.agent_status} "),
        ]

        if state.target:
            segments.extend([
                ("class:hud.sep", " "),
                ("class:hud.seg4", f" T {state.target} "),
            ])

        segments.append(("class:hud.tail", " "))
        return segments

    def get_rprompt_shadow(self, text: str) -> Optional[HTML]:
        shadow = get_command_shadow(text)
        if not shadow:
            return None
        return HTML(f"<ansigray>{shadow}</ansigray>")

    def _snapshot(self, current_text: str) -> HUDSnapshot:
        now = time.perf_counter()
        if self._state_cache is not None and now - self._state_cache_t < self._state_cache_ttl:
            multiline = "\n" in current_text
            if self._state_cache.multiline != multiline:
                return HUDSnapshot(
                    workspace=self._state_cache.workspace,
                    target=self._state_cache.target,
                    cost_total=self._state_cache.cost_total,
                    cost_limit=self._state_cache.cost_limit,
                    model=self._state_cache.model,
                    agent_status=self._state_cache.agent_status,
                    multiline=multiline,
                    budget_exceeded=self._state_cache.budget_exceeded,
                )
            return self._state_cache

        workspace_raw = self._resolve_workspace_name()
        target_raw = self._resolve_target_name()
        total_cost = self._resolve_cost_total()
        limit = self._resolve_cost_limit()
        budget_exceeded = limit > 0 and total_cost > limit
        model = self._resolve_model_name()
        status = self._resolve_agent_status()

        state = HUDSnapshot(
            workspace=self._sanitize_label(workspace_raw),
            target=self._sanitize_label(target_raw),
            cost_total=total_cost,
            cost_limit=limit,
            model=self._sanitize_label(model, max_len=20),
            agent_status=self._sanitize_label(status, max_len=16),
            multiline="\n" in current_text,
            budget_exceeded=budget_exceeded,
        )
        self._state_cache = state
        self._state_cache_t = now
        return state

    def _resolve_workspace_name(self) -> str:
        val = self._cfg_get("CERBERUS_WORKSPACE")
        if val:
            return val
        try:
            if self._workspace_manager is not None and hasattr(self._workspace_manager, "session_id"):
                return str(self._workspace_manager.session_id)
            return get_project_space().session_id
        except Exception:
            return "workspace"

    def _resolve_target_name(self) -> str:
        return self._cfg_get("CERBERUS_TARGET") or self._cfg_get("CTF_IP") or ""

    def _resolve_cost_total(self) -> float:
        try:
            return float(getattr(self._cost_manager, "session_total_cost", 0.0) or 0.0)
        except Exception:
            return 0.0

    def _resolve_cost_limit(self) -> float:
        raw = self._cfg_get("CERBERUS_PRICE_LIMIT")
        if not raw:
            return 0.0
        try:
            return float(raw)
        except Exception:
            return 0.0

    def _resolve_model_name(self) -> str:
        if self._model_provider is not None:
            try:
                return self._model_provider() or "model"
            except Exception:
                pass
        return self._cfg_get("CERBERUS_MODEL") or "cerebro1"

    def _resolve_agent_status(self) -> str:
        if self._agent_status_provider is not None:
            try:
                return self._agent_status_provider() or "Idle"
            except Exception:
                pass
        state = self._cfg_get("CERBERUS_AGENT_STATUS")
        if state:
            return state
        return "Thinking" if self._cfg_get("CERBERUS_STREAM", "false").lower() == "true" else "Idle"

    def _sanitize_label(self, value: str, *, max_len: int = 24) -> str:
        safe = clean(value or "")
        if _SECRETISH_RE.search(safe):
            return "[obfuscated]"
        if _HOSTISH_RE.search(safe):
            safe = self._obfuscate_middle(safe)
        if len(safe) > max_len:
            safe = safe[: max_len - 1] + "…"
        return safe or "-"

    @staticmethod
    def _obfuscate_middle(value: str) -> str:
        if len(value) <= 8:
            return "***"
        return value[:3] + "***" + value[-2:]

    def _cfg_get(self, key: str, default: str = "") -> str:
        try:
            val = self._config.get(key)
            if val and val != "Not set":
                return str(val)
        except Exception:
            pass
        return str(os.getenv(key, default) or "")

    @staticmethod
    def _fmt_limit(limit: float) -> str:
        return "∞" if limit <= 0 else f"{limit:.2f}"

    @staticmethod
    def _detect_ansi_safe() -> bool:
        term = os.getenv("TERM", "").lower()
        if os.getenv("NO_COLOR"):
            return False
        if term in {"", "dumb"}:
            return False
        try:
            return Console().color_system is not None
        except Exception:
            return True

    @staticmethod
    def _detect_unicode_safe() -> bool:
        lang = os.getenv("LC_ALL") or os.getenv("LC_CTYPE") or os.getenv("LANG") or ""
        return "UTF-8" in lang.upper() or "UTF8" in lang.upper()

    @staticmethod
    def _palette_for(state: HUDSnapshot) -> Dict[str, str]:
        if state.budget_exceeded:
            return {"cost": "class:hud.alert", "status": "class:hud.alert"}
        if state.cost_limit > 0 and state.cost_total > state.cost_limit * 0.8:
            return {"cost": "class:hud.warn", "status": "class:hud.status"}
        return {"cost": "class:hud.seg2", "status": "class:hud.status"}


# Cache for command shadow to avoid recalculating it too frequently
shadow_cache = {
    "text": "",
    "result": "",
    "last_update": 0.0,
    "update_interval": 0.1,
}


@lru_cache(maxsize=32)
def get_command_shadow_cached(text: str) -> str:
    """Get command shadow suggestion with caching for repeated calls."""
    shadow = FuzzyCommandCompleter().get_command_shadow(text)
    if shadow and shadow.startswith(text):
        return shadow[len(text):]
    return ""


def get_command_shadow(text: str) -> str:
    """Get command shadow suggestion with throttling."""
    current_time = time.time()

    if text == shadow_cache["text"]:
        return str(shadow_cache["result"])

    if current_time - float(shadow_cache["last_update"]) < float(shadow_cache["update_interval"]):
        result = str(shadow_cache["result"])
        if result:
            return result

    result = get_command_shadow_cached(text)
    shadow_cache["text"] = text
    shadow_cache["result"] = result
    shadow_cache["last_update"] = current_time
    return result


def create_prompt_style() -> Style:
    """Create prompt toolkit style map including HUD segment gradients."""
    return Style.from_dict(
        {
            "prompt": "bold cyan",
            "hud.plain": "bold",
            "hud.seg0": "bold #0c1b2b bg:#30b0c7",
            "hud.seg1": "bold #07131f bg:#57c9b8",
            "hud.seg2": "bold #081019 bg:#8dd585",
            "hud.seg3": "bold #f4fbff bg:#256e9f",
            "hud.seg4": "bold #111111 bg:#d6dd7b",
            "hud.status": "bold #101010 bg:#f3c969",
            "hud.warn": "bold #1a1200 bg:#ffb347",
            "hud.alert": "bold #ffffff bg:#c43d3d",
            "hud.sep": "bg:#1b1b1b #8fa0a8",
            "hud.tail": "bold #9fdfff",
            "completion-menu": "bg:#2b2b2b #ffffff",
            "completion-menu.completion": "bg:#2b2b2b #ffffff",
            "completion-menu.completion.current": "bg:#004b6b #ffffff",
            "scrollbar.background": "bg:#2b2b2b",
            "scrollbar.button": "bg:#004b6b",
        }
    )


def _get_prompt_session(history_file: Any) -> PromptSession:
    """Return a cached PromptSession bound to the shared FileHistory path."""
    history_path = prepare_prompt_history_file(history_file)
    cache_key = str(history_path)
    session = _PROMPT_SESSIONS.get(cache_key)
    if session is None:
        session = PromptSession(history=FileHistory(str(history_path)))
        _PROMPT_SESSIONS[cache_key] = session
    return session


def get_user_input(
    command_completer,
    key_bindings,
    history_file,
    toolbar_func,
    current_text,
    *,
    hud: Optional[CerberusPromptHUD] = None,
    config: Any = None,
    workspace_manager: Any = None,
    cost_manager: Any = None,
    model_provider: Optional[Callable[[], str]] = None,
    agent_status_provider: Optional[Callable[[], str]] = None,
):
    """Get user input with dynamic HUD prompt and command shadow support."""
    prompt_hud = hud or CerberusPromptHUD(
        config=config,
        workspace_manager=workspace_manager,
        cost_manager=cost_manager,
        model_provider=model_provider,
        agent_status_provider=agent_status_provider,
    )

    def get_live_text() -> str:
        app = get_app_or_none()
        if app is not None and hasattr(app, "current_buffer") and app.current_buffer is not None:
            return app.current_buffer.text or ""
        return current_text[0] if current_text else ""

    def get_rprompt():
        live_text = get_live_text()
        if current_text:
            current_text[0] = live_text
        return prompt_hud.get_rprompt_shadow(live_text)

    def get_hud_message() -> List[Tuple[str, str]]:
        live_text = get_live_text()
        if current_text:
            current_text[0] = live_text
        return prompt_hud.get_prompt_fragments(live_text)

    session = _get_prompt_session(history_file)
    user_input = session.prompt(
        get_hud_message,
        completer=command_completer,
        style=create_prompt_style(),
        auto_suggest=AutoSuggestFromHistory(),
        key_bindings=key_bindings,
        bottom_toolbar=toolbar_func,
        complete_in_thread=True,
        complete_while_typing=True,
        enable_system_prompt=True,
        mouse_support=True,
        enable_suspend=True,
        enable_open_in_editor=True,
        multiline=False,
        rprompt=get_rprompt,
        color_depth=None,
    )
    if current_text:
        current_text[0] = user_input or ""
    return user_input
