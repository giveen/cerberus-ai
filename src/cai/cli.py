"""Cerberus AI CLI entry point.

This module provides a commercial-grade command router with:
- early configuration/environment bootstrap
- nested command routing (repl/run/workspace/doctor)
- terminal presentation
- graceful global error handling with support IDs

The parser and top-level help keep imports intentionally light so
`cerberus-ai --help` remains fast.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
from pathlib import Path
import shlex
import sys
import tempfile
import time
import traceback
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


APP_NAME = "Cerberus AI"
# Use the invoked program name (e.g. `cai`) for help text so examples
# match what the user actually typed. Fall back to `cai` if argv is empty.
APP_COMMAND = Path(sys.argv[0]).name if len(sys.argv) > 0 else "cai"

console = Console()


def __getattr__(name: str) -> Any:
    if name == "Runner":
        from cai.sdk.agents.run import Runner as _Runner

        return _Runner
    if name == "get_agent_by_name":
        from cai.agents import get_agent_by_name as _get_agent_by_name

        return _get_agent_by_name
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


class CLIUserError(Exception):
    """Expected user-facing CLI failure."""


@dataclass(frozen=True)
class GlobalOptions:
    workspace: Optional[str]
    silent: bool
    debug: bool
    verbose: bool


@dataclass(frozen=True)
class BootstrapState:
    provider_credentials_present: bool
    license_present: bool


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=APP_COMMAND,
        description="Enterprise agentic security orchestration",
        add_help=False,
    )

    parser.add_argument("--workspace", type=str, default=None, help="Workspace/case root path")
    parser.add_argument("--silent", action="store_true", help="Suppress banner and non-essential UI")
    parser.add_argument("--debug", action="store_true", help="Enable verbose terminal diagnostics")
    parser.add_argument("--verbose", action="store_true", help="Show extended runtime and tool diagnostics")
    parser.add_argument("--openai-key", type=str, default=None, help=argparse.SUPPRESS)
    parser.add_argument("--export-traces", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("-h", "--help", action="store_true", help="Show help")

    subparsers = parser.add_subparsers(dest="command")

    repl_p = subparsers.add_parser("repl", add_help=False, help="Launch interactive REPL")
    repl_p.add_argument("-h", "--help", action="store_true", help="Show repl help")

    run_p = subparsers.add_parser("run", add_help=False, help="Run one non-interactive prompt")
    run_p.add_argument("prompt", nargs="+", help="Prompt to execute")
    run_p.add_argument("-h", "--help", action="store_true", help="Show run help")

    ws_p = subparsers.add_parser("workspace", add_help=False, help="Execute workspace subcommands")
    ws_p.add_argument("workspace_args", nargs=argparse.REMAINDER, help="Workspace command args")
    ws_p.add_argument("-h", "--help", action="store_true", help="Show workspace help")

    doctor_p = subparsers.add_parser("doctor", add_help=False, help="Run platform/environment diagnostics")
    doctor_p.add_argument("--json", action="store_true", help="Emit doctor report as JSON")
    doctor_p.add_argument("-h", "--help", action="store_true", help="Show doctor help")

    return parser


def _render_help() -> None:
    panel = Panel(
        Text(
            "\n".join(
                [
                    f"{APP_COMMAND}                # Start interactive local-first REPL (default)",
                    f"{APP_COMMAND} repl           # Start interactive local-first REPL",
                    f"{APP_COMMAND} run <prompt>   # Run one prompt against configured local/provider model",
                    f"{APP_COMMAND} workspace <cmd> # Workspace isolation and artifact commands",
                    f"{APP_COMMAND} doctor         # Validate host/runtime readiness",
                    "",
                    "Global flags:",
                    "  --workspace <path>  set active engagement folder",
                    "  --silent            suppress banner/UI extras",
                    "  --debug             enable runtime debug diagnostics",
                    "  --verbose           include detailed stream and tool telemetry",
                    "",
                    "Deprecated flags removed:",
                    "  --openai-key        removed (use env/config, e.g. CEREBRO_API_BASE)",
                    "  --export-traces     removed (runtime uses local audit artifacts)",
                    "",
                    "Examples:",
                    f"  {APP_COMMAND}",
                    f"  {APP_COMMAND} repl --workspace ./cases/acme",
                    f"  {APP_COMMAND} run \"Summarize local findings and next actions\"",
                    f"  {APP_COMMAND} workspace new acme_q2",
                    f"  {APP_COMMAND} doctor --json",
                ]
            )
        , style="white"),
        title=f"{APP_NAME} CLI",
        border_style="cyan",
    )
    console.print(panel)


def _load_dotenv() -> None:
    try:
        from dotenv import load_dotenv  # type: ignore

        load_dotenv(override=True)
    except Exception:
        return


def _configure_workspace_env(workspace_flag: Optional[str]) -> None:
    if not workspace_flag:
        return

    workspace_root = Path(workspace_flag).expanduser().resolve()
    workspace_root.mkdir(parents=True, exist_ok=True)

    os.environ["CEREBRO_WORKSPACE_ACTIVE_ROOT"] = str(workspace_root)
    os.environ["WORKSPACE_ROOT"] = str(workspace_root)

    if "CEREBRO_WORKSPACE" not in os.environ:
        os.environ["CEREBRO_WORKSPACE"] = workspace_root.name
    if "CEREBRO_WORKSPACE_DIR" not in os.environ:
        os.environ["CEREBRO_WORKSPACE_DIR"] = str(workspace_root.parent)


def _apply_global_flags(opts: GlobalOptions) -> None:
    if opts.silent:
        os.environ["CEREBRO_SILENT"] = "1"
    if opts.debug:
        os.environ["CEREBRO_DEBUG"] = "2"
        logging.basicConfig(level=logging.DEBUG)
    if opts.verbose:
        os.environ["CEREBRO_VERBOSE"] = "1"


def _bootstrap_config_and_env() -> BootstrapState:
    # Boot config/env subsystems before loading tools/agents.
    from cai.repl.commands.config import CONFIG_STORE
    from cai.repl.commands.env import ENV_AUDITOR

    provider_checks = {item.name: item for item in ENV_AUDITOR.run_audit()}
    provider_present = bool(provider_checks.get("provider_credentials") and provider_checks["provider_credentials"].passed)

    license_value = os.getenv("CEREBRO_LICENSE_KEY", "").strip()
    if not license_value:
        try:
            cfg_license, _tier = CONFIG_STORE.resolve("CEREBRO_LICENSE_KEY")
            if cfg_license and cfg_license != "Not set":
                license_value = str(cfg_license).strip()
        except Exception:
            pass

    return BootstrapState(
        provider_credentials_present=provider_present,
        license_present=bool(license_value),
    )


def _ensure_runtime_prerequisites(state: BootstrapState, command: str) -> None:
    if command not in {"repl", "run"}:
        return

    if state.provider_credentials_present:
        return

    if state.license_present:
        return

    raise CLIUserError(
        "Missing provider credentials or license key. "
        "Set at least one API key (OPENAI_API_KEY / ANTHROPIC_API_KEY / GEMINI_API_KEY / DEEPSEEK_API_KEY) "
        "or configure CEREBRO_LICENSE_KEY before running interactive workloads."
    )


def _log_support_error(exc: BaseException) -> str:
    support_id = f"SUP-{uuid.uuid4().hex[:12].upper()}"
    workspace_root = Path(os.getenv("CEREBRO_WORKSPACE_ACTIVE_ROOT") or os.getenv("WORKSPACE_ROOT") or os.getcwd()).resolve()
    out_dir = workspace_root / ".cai" / "errors"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{support_id}.json"

    payload = {
        "support_id": support_id,
        "timestamp": time.time(),
        "error_type": type(exc).__name__,
        "message": str(exc),
        "traceback": traceback.format_exc(),
    }

    encoded = json.dumps(payload, ensure_ascii=True, indent=2).encode("utf-8")
    with tempfile.NamedTemporaryFile(dir=out_dir, delete=False) as tmp:
        tmp.write(encoded)
        tmp_path = Path(tmp.name)
    tmp_path.replace(out_path)

    return support_id


async def _dispatch_repl(opts: GlobalOptions) -> int:
    from cai.repl.ui.banner import CerebroBanner
    from cai.repl.commands import handle_command as commands_handle_command
    from cai.repl.commands.base import SessionContext, set_session
    from cai.tools.workspace import get_project_space

    memory = None
    try:
        from cai.memory import MemoryManager

        memory = MemoryManager()
        memory.initialize()
    except Exception:
        memory = None

    workspace = get_project_space()
    workspace.ensure_initialized()
    set_session(SessionContext(workspace=workspace, memory=memory))

    if not opts.silent:
        CerebroBanner(console).display()

    console.print(Panel("Interactive REPL ready. Type /help for command list, /exit to quit.", border_style="green"))
    prompt_label = "CERBERUS> "

    while True:
        try:
            line = await asyncio.to_thread(input, prompt_label)
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]Session closed.[/dim]")
            return 0

        text = (line or "").strip()
        if not text:
            continue
        if text.lower() in {"quit", "exit", "/quit", "/exit"}:
            return 0

        if text.startswith("/"):
            try:
                tokens = shlex.split(text)
            except ValueError as exc:
                console.print(f"[red]Parse error:[/red] {exc}")
                continue
            cmd = tokens[0]
            args = tokens[1:]
            ok = await asyncio.to_thread(commands_handle_command, cmd, args)
            if not ok:
                console.print(f"[yellow]Command failed or unknown:[/yellow] {cmd}")
            await asyncio.sleep(0)
            continue

        # Non-command text routes through supervised run command.
        ok = await asyncio.to_thread(commands_handle_command, "/run", [text])
        if not ok:
            console.print("[yellow]Run command failed. Use /help for details.[/yellow]")
        await asyncio.sleep(0)


async def _dispatch_run(prompt_parts: Sequence[str]) -> int:
    from cai.repl.commands import handle_command as commands_handle_command
    from cai.repl.commands.base import SessionContext, set_session
    from cai.tools.workspace import get_project_space

    memory = None
    try:
        from cai.memory import MemoryManager

        memory = MemoryManager()
        memory.initialize()
    except Exception:
        memory = None

    workspace = get_project_space()
    workspace.ensure_initialized()
    set_session(SessionContext(workspace=workspace, memory=memory))

    prompt = " ".join(prompt_parts).strip()
    if not prompt:
        raise CLIUserError("run requires a prompt")

    ok = await asyncio.to_thread(commands_handle_command, "/run", [prompt])
    return 0 if ok else 1


async def _dispatch_workspace(workspace_args: Sequence[str]) -> int:
    from cai.repl.commands import handle_command as commands_handle_command
    from cai.repl.commands.base import SessionContext, set_session
    from cai.tools.workspace import get_project_space

    memory = None
    try:
        from cai.memory import MemoryManager

        memory = MemoryManager()
        memory.initialize()
    except Exception:
        memory = None

    workspace = get_project_space()
    workspace.ensure_initialized()
    set_session(SessionContext(workspace=workspace, memory=memory))

    args = [a for a in workspace_args if a]
    if args and args[0] == "--":
        args = args[1:]

    if not args:
        args = ["dashboard"]

    ok = await asyncio.to_thread(commands_handle_command, "/workspace", list(args))
    return 0 if ok else 1


async def _dispatch_doctor(as_json: bool) -> int:
    from cai.memory import MemoryManager
    from cai.repl.commands.env import ENV_AUDITOR
    from cai.repl.commands.platform import get_system_auditor

    memory = MemoryManager()
    memory.initialize()

    auditor = get_system_auditor(memory)
    platform_specs = await auditor.audit(refresh=True)
    env_checks = ENV_AUDITOR.run_audit()

    payload: Dict[str, Any] = {
        "platform": platform_specs.model_dump(mode="json"),
        "env_checks": [item.model_dump(mode="json") for item in env_checks],
        "healthy": all(item.passed or item.severity == "warning" for item in env_checks),
    }

    if as_json:
        console.print_json(json.dumps(payload))
        return 0

    table = Table(title="Cerberus AI Doctor Report")
    table.add_column("Check", style="cyan", no_wrap=True)
    table.add_column("Status", style="white", no_wrap=True)
    table.add_column("Detail", style="white")

    for check in env_checks:
        status = "PASS" if check.passed else "FAIL"
        color = "green" if check.passed else ("yellow" if check.severity == "warning" else "red")
        table.add_row(check.name, f"[{color}]{status}[/{color}]", check.detail)

    console.print(table)

    summary = Table(title="Platform Summary")
    summary.add_column("Signal", style="cyan", no_wrap=True)
    summary.add_column("Value", style="white")
    summary.add_row("OS", f"{platform_specs.os.distribution} {platform_specs.os.version}")
    summary.add_row("Kernel", f"{platform_specs.kernel.family} {platform_specs.kernel.release}")
    summary.add_row("Arch", platform_specs.architecture.machine)
    summary.add_row("Execution", platform_specs.virtualization.summary)
    summary.add_row("Tools Available", str(sum(1 for t in platform_specs.tools if t.available)))
    console.print(summary)

    return 0 if payload["healthy"] else 1


async def _async_main(argv: Optional[Sequence[str]] = None) -> int:
    _load_dotenv()

    parser = _build_parser()
    args = parser.parse_args(list(argv) if argv is not None else sys.argv[1:])

    # If user asked for help explicitly, show help. If no subcommand was
    # provided, treat invocation with no args as a desire to enter the REPL.
    if getattr(args, "help", False):
        _render_help()
        return 0

    if getattr(args, "openai_key", None) or getattr(args, "export_traces", False):
        raise CLIUserError(
            "Deprecated flags detected: --openai-key/--export-traces are removed. "
            "Use CEREBRO_API_BASE and local runtime audit logging instead."
        )

    if args.command is None:
        args.command = "repl"

    global_opts = GlobalOptions(
        workspace=args.workspace,
        silent=bool(args.silent),
        debug=bool(args.debug),
        verbose=bool(args.verbose),
    )
    _configure_workspace_env(global_opts.workspace)
    _apply_global_flags(global_opts)

    # Attempt to load a workspace-scoped .env file (if present).  We call
    # load_dotenv again after the workspace has been configured so that
    # environment variables stored inside the workspace (e.g. a local
    # LLM endpoint or CEREBRO_MODEL) are loaded into the process and used by
    # the EnvironmentAuditor checks below.
    try:
        from dotenv import load_dotenv  # type: ignore

        workspace_env_root = os.getenv("WORKSPACE_ROOT") or global_opts.workspace
        if workspace_env_root:
            dotenv_path = Path(workspace_env_root) / ".env"
            if dotenv_path.exists():
                load_dotenv(dotenv_path=str(dotenv_path), override=True)
    except Exception:
        pass

    bootstrap = _bootstrap_config_and_env()
    _ensure_runtime_prerequisites(bootstrap, args.command)

    if args.command == "repl":
        if getattr(args, "help", False):
            console.print(f"[cyan]Usage:[/cyan] {APP_COMMAND} repl [--workspace <path>] [--silent] [--debug] [--verbose]")
            return 0
        return await _dispatch_repl(global_opts)

    if args.command == "run":
        if getattr(args, "help", False):
            console.print(f"[cyan]Usage:[/cyan] {APP_COMMAND} run <prompt> [--workspace <path>] [--silent] [--debug] [--verbose]")
            return 0
        return await _dispatch_run(args.prompt)

    if args.command == "workspace":
        if getattr(args, "help", False):
            console.print(f"[cyan]Usage:[/cyan] {APP_COMMAND} workspace <cmd> [args]")
            return 0
        return await _dispatch_workspace(args.workspace_args)

    if args.command == "doctor":
        if getattr(args, "help", False):
            console.print(f"[cyan]Usage:[/cyan] {APP_COMMAND} doctor [--json]")
            return 0
        return await _dispatch_doctor(bool(args.json))

    raise CLIUserError(f"Unknown command: {args.command}")


def main(argv: Optional[Sequence[str]] = None) -> int:
    """CLI entrypoint used by console scripts."""
    try:
        return asyncio.run(_async_main(argv))
    except CLIUserError as exc:
        support_id = _log_support_error(exc)
        console.print(
            Panel(
                f"[bold red]Request failed[/bold red]\n\n{exc}\n\nSupport ID: [bold]{support_id}[/bold]",
                title=f"{APP_NAME} Error",
                border_style="red",
            )
        )
        return 2
    except KeyboardInterrupt:
        console.print("\n[dim]Interrupted by user.[/dim]")
        return 130
    except Exception as exc:  # pylint: disable=broad-except
        support_id = _log_support_error(exc)
        console.print(
            Panel(
                "[bold red]Unexpected failure[/bold red]\n"
                "A diagnostic bundle was written to the workspace error log.\n\n"
                f"Support ID: [bold]{support_id}[/bold]",
                title=f"{APP_NAME} Failure",
                border_style="red",
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
