"""Dynamic command help formatter for slash commands.

Builds runtime documentation from the live command registry using introspection.
"""

from __future__ import annotations

import inspect
from pathlib import Path
import re
from typing import Any, Iterable

from pydantic import BaseModel
from rich.console import Console
from rich.table import Table

from cai.internal.registry.commands import RegisteredCommand
from cai.tools.reconnaissance.filesystem import PathGuard


_HOST_PATH_RE = re.compile(r"(/[^\s]+)")


def _scrub_host_paths(text: str, workspace_root: Path) -> str:
    """Redact absolute host paths outside workspace scope."""

    def _replace(match: re.Match[str]) -> str:
        token = match.group(1)
        try:
            candidate = Path(token)
            if not candidate.is_absolute():
                return token
            resolved = candidate.resolve()
            if str(resolved).startswith(str(workspace_root)):
                return token
            if str(resolved).startswith("/workspace"):
                return token
            return "<host-path-redacted>"
        except Exception:
            return token

    return _HOST_PATH_RE.sub(_replace, text)


def _format_default(value: Any, workspace_root: Path) -> str:
    if value is inspect.Signature.empty:
        return "required"
    if value is None:
        return "None"
    text = repr(value)
    return _scrub_host_paths(text, workspace_root)


def _iter_pydantic_models(command: RegisteredCommand) -> Iterable[type[BaseModel]]:
    module = inspect.getmodule(command.command.__class__)
    if module is None:
        return []

    models: list[type[BaseModel]] = []
    for _, obj in inspect.getmembers(module, inspect.isclass):
        if not issubclass(obj, BaseModel):
            continue
        if obj is BaseModel:
            continue
        if obj.__module__ != module.__name__:
            continue
        models.append(obj)
    return models


def generate_command_help(
    *,
    command_name: str,
    command: RegisteredCommand,
    risk_level: str,
    impact: str,
    workspace_root: Path,
) -> str:
    """Generate runtime command help from live registry metadata."""
    guard = PathGuard(workspace_root, lambda _event, _payload: None)
    guard.validate_path(workspace_root, action="command_help_render", mode="read")

    backend = command.backend
    signature = inspect.signature(backend)

    command_token = command_name if command_name.startswith("/") else f"/{command_name}"

    description = (inspect.getdoc(backend) or inspect.getdoc(command.command.__class__) or "No description available.").strip()
    description = _scrub_host_paths(description, workspace_root)

    syntax_tokens: list[str] = [command_token]
    option_rows: list[tuple[str, str, str, str]] = []

    for name, param in signature.parameters.items():
        if name == "self":
            continue
        annotation = "Any" if param.annotation is inspect.Signature.empty else getattr(param.annotation, "__name__", str(param.annotation))
        default = _format_default(param.default, workspace_root)
        required = param.default is inspect.Signature.empty
        syntax_tokens.append(f"<{name}>" if required else f"[{name}]")
        option_rows.append((name, annotation, default, "backend parameter"))

    for model in _iter_pydantic_models(command):
        for field_name, field in model.model_fields.items():
            annotation = str(field.annotation)
            default = _format_default(field.default, workspace_root)
            flag = f"--{field_name.replace('_', '-')}"
            option_rows.append((flag, annotation, default, f"{model.__name__} schema field"))

    aliases = list(getattr(command.command, "aliases", []) or [])

    table = Table(title=f"Command Help: {command_token}")
    table.add_column("Field", style="cyan", no_wrap=True)
    table.add_column("Value", style="white")
    table.add_row("Command Syntax", " ".join(syntax_tokens))
    table.add_row("Description", description)
    table.add_row("Canonical", command.canonical)
    table.add_row("Aliases", ", ".join(aliases) if aliases else "-")
    table.add_row("Risk", risk_level)
    table.add_row("Impact", impact)

    options = Table(title="Options / Flags")
    options.add_column("Option", style="green")
    options.add_column("Type", style="magenta")
    options.add_column("Default", style="yellow")
    options.add_column("Source", style="white")

    if option_rows:
        seen: set[tuple[str, str, str, str]] = set()
        for row in option_rows:
            if row in seen:
                continue
            seen.add(row)
            options.add_row(*row)
    else:
        options.add_row("-", "-", "-", "No explicit options discovered")

    console = Console(record=True, width=120)
    console.print(table)
    console.print(options)
    rendered = console.export_text()
    return _scrub_host_paths(rendered, workspace_root)


__all__ = ["generate_command_help"]
