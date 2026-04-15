"""Canonical command registry for internal dispatch.

This module builds a 1:1 mapping between CLI command tokens and the backend
command handlers registered in the REPL command framework.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Callable, Dict, Mapping, Optional

from cerberus.repl import commands as _commands_module  # noqa: F401
from cerberus.repl.commands.base import COMMAND_ALIASES, COMMANDS, FrameworkCommand


_REQUIRED_HELP_ALIASES = {
    "/mem",
    "/ws",
    "/cfg",
    "/cost",
    "/env",
    "/ctx",
    "/exit",
    "/flush",
    "/his",
    "/k",
    "/l",
    "/m",
    "/mrg",
    "/mod",
    "/mod-show",
    "/par",
    "/plat",
    "/qs",
    "/r",
    "/s",
    "/virt",
    "/graph",
}


_COMPAT_ALIAS_MAP: Mapping[str, str] = {
    "/ctx": "compact",
    "ctx": "compact",
    "/mem": "/memory",
    "/ws": "/workspace",
    "/cfg": "config",
    "/his": "/history",
    "/k": "/kill",
    "/l": "/load",
    "/m": "/memory",
    "/mrg": "/merge",
    "/mod": "/model",
    "/mod-show": "/model-show",
    "/par": "/parallel",
    "/plat": "/platform",
    "/qs": "/quickstart",
    "/r": "/run",
    "/s": "/shell",
    "/virt": "/virtualization",
}

_RISK_IMPACT_MAP: Mapping[str, tuple[str, str]] = {
    "agent": ("Medium", "Agent switches can alter execution behavior"),
    "memory": ("Low", "Memory actions affect retained context"),
    "workspace": ("Medium", "Workspace operations can move/archive artifacts"),
    "cost": ("Low", "Cost tracking and budget policy interaction"),
    "config": ("Medium", "Configuration changes alter runtime behavior"),
    "env": ("High", "Environment operations can affect runtime state"),
    "exit": ("Medium", "Shutdown lifecycle can terminate active processing"),
    "flush": ("High", "State purge can remove volatile artifacts"),
    "graph": ("Medium", "Graph output may expose operational context"),
    "shell": ("High", "Shell execution runs host commands"),
    "virtualization": ("High", "Virtualization controls infrastructure runtime"),
    "mcp": ("Medium", "External integration trust boundary expansion"),
    "parallel": ("Medium", "Concurrent execution increases system pressure"),
    "run": ("Medium", "Execution can trigger backend side effects"),
    "kill": ("High", "Signal-based termination affects live processes"),
    "load": ("Medium", "Session/load operations mutate active state"),
    "model": ("Low", "Model selection changes inference backend"),
    "quickstart": ("Low", "Setup-oriented command with limited side effects"),
    "platform": ("Low", "Platform auditing is primarily observational"),
    "merge": ("Medium", "Merge operations rewrite workspace data"),
    "history": ("Low", "History inspection with limited mutation"),
    "compact": ("Medium", "Compaction rewrites context representation"),
    "help": ("Low", "Documentation query only"),
}


@dataclass(frozen=True)
class RegisteredCommand:
    """Resolved command backend mapping entry."""

    token: str
    canonical: str
    command: FrameworkCommand
    backend: Callable[..., Any]

    @property
    def is_async_backend(self) -> bool:
        return asyncio.iscoroutinefunction(self.backend)


class CerberusCommandRegistry:
    """Builds and validates command-token to backend mappings."""

    def __init__(self) -> None:
        self._token_map: Dict[str, RegisteredCommand] = {}
        self._canonical_map: Dict[str, RegisteredCommand] = {}
        self.refresh()

    @staticmethod
    def _normalize_token(token: str) -> str:
        value = token.strip()
        if not value:
            return value
        if not value.startswith("/"):
            value = f"/{value}"
        return value.lower()

    def refresh(self) -> None:
        token_map: Dict[str, RegisteredCommand] = {}
        canonical_map: Dict[str, RegisteredCommand] = {}

        for command_key, command_obj in COMMANDS.items():
            canonical = self._normalize_token(command_key)
            primary = RegisteredCommand(
                token=canonical,
                canonical=canonical,
                command=command_obj,
                backend=command_obj.execute,
            )
            token_map[canonical] = primary
            canonical_map[canonical] = primary

            declared_aliases = set(getattr(command_obj, "aliases", []) or [])
            for alias_key, alias_target in COMMAND_ALIASES.items():
                if alias_target != command_key:
                    continue
                declared_aliases.add(alias_key)

            for alias in declared_aliases:
                alias_norm = self._normalize_token(alias)
                token_map[alias_norm] = RegisteredCommand(
                    token=alias_norm,
                    canonical=canonical,
                    command=command_obj,
                    backend=command_obj.execute,
                )

        for alias, target in _COMPAT_ALIAS_MAP.items():
            alias_norm = self._normalize_token(alias)
            target_norm = self._normalize_token(target)
            target_entry = token_map.get(target_norm)
            if target_entry is None:
                continue
            token_map[alias_norm] = RegisteredCommand(
                token=alias_norm,
                canonical=target_entry.canonical,
                command=target_entry.command,
                backend=target_entry.backend,
            )

        self._token_map = token_map
        self._canonical_map = canonical_map

    def resolve(self, token: str) -> Optional[RegisteredCommand]:
        return self._token_map.get(self._normalize_token(token))

    def audit_required_help_aliases(self) -> Dict[str, Any]:
        available = set(self._token_map.keys())
        missing = sorted(alias for alias in _REQUIRED_HELP_ALIASES if alias not in available)

        invalid_targets = sorted(
            alias
            for alias, entry in self._token_map.items()
            if not callable(entry.backend)
        )

        return {
            "required": sorted(_REQUIRED_HELP_ALIASES),
            "missing": missing,
            "invalid_backends": invalid_targets,
            "ok": not missing and not invalid_targets,
        }

    def command_docstring(self, token: str) -> str:
        entry = self.resolve(token)
        if entry is None:
            return ""

        execute_doc = (entry.backend.__doc__ or "").strip()
        if execute_doc:
            return execute_doc

        class_doc = (entry.command.__class__.__doc__ or "").strip()
        if class_doc:
            return class_doc

        help_text = ""
        try:
            help_text = str(entry.command.help).strip()
        except Exception:
            help_text = ""
        return help_text

    def command_risk_impact(self, token: str) -> tuple[str, str]:
        entry = self.resolve(token)
        if entry is None:
            return ("Low", "Unknown command")

        cmd = entry.command
        declared_risk = getattr(cmd, "risk_level", None)
        declared_impact = getattr(cmd, "impact", None)
        if isinstance(declared_risk, str) and declared_risk.strip() and isinstance(declared_impact, str):
            return (declared_risk.strip(), declared_impact.strip())

        normalized = entry.canonical.lstrip("/").strip().lower()
        return _RISK_IMPACT_MAP.get(normalized, ("Low", "Read-only or low-impact operation"))


__all__ = ["CerberusCommandRegistry", "RegisteredCommand"]
