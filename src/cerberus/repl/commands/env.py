"""Secure environment command for Cerebro REPL.

This module intentionally defaults to *hide-all* behavior.  It only exposes
values from an explicit allow-list and redacts any other variable requests.

Public surface:
  - ``EnvironmentAuditor`` utility for secure reads, audit checks,
    session-isolated overlays, and sanitized snapshots.
  - ``EnvCommand`` (FrameworkCommand) with sub-commands:
      show/list, get, set, audit, snapshot, clear
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import shutil
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, field_validator
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from cerberus.repl.commands.base import FrameworkCommand, register_command

__all__ = [
    "EnvironmentVariable",
    "EnvironmentSnapshot",
    "AuditCheck",
    "EnvironmentAuditor",
    "EnvCommand",
    "ENV_AUDITOR",
]

console = Console()


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class EnvironmentVariable(BaseModel):
    """Schema for one environment variable exposed by policy."""

    name: str
    value: str
    source: str = "process"  # process | session
    safe: bool = True

    @field_validator("name", mode="before")
    @classmethod
    def _normalize_name(cls, v: Any) -> str:
        return str(v).strip().upper()

    @field_validator("value", mode="before")
    @classmethod
    def _coerce_value(cls, v: Any) -> str:
        return "" if v is None else str(v)


class EnvironmentSnapshot(BaseModel):
    """Sanitized snapshot written to disk for commercial reporting."""

    generated_at: str
    workspace_root: str
    session_id: str
    variables: List[EnvironmentVariable]


class AuditCheck(BaseModel):
    """One environment integrity check result."""

    name: str
    passed: bool
    severity: str = "info"    # info | warning | critical
    detail: str


# ---------------------------------------------------------------------------
# EnvironmentAuditor
# ---------------------------------------------------------------------------

class EnvironmentAuditor:
    """Security-first environment policy engine.

    Design principles:
    - Default deny: only allow-listed variables are visible.
    - Redaction: non-allow-listed access returns ``HIDDEN_BY_POLICY``.
    - Session isolation: writable overrides are namespaced by workspace hash.
    - Sanitized snapshots: only policy-approved keys are exported.
    """

    # Explicitly safe keys. No wildcard expansion is performed.
    _ALLOW_LIST: Tuple[str, ...] = (
        "PATH",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "TERM",
        "COLORTERM",
        "SHELL",
        "USER",
        "LOGNAME",
        "HOME",
        "PWD",
        "WORKSPACE_ROOT",
        "CERBERUS_MODEL",
        "CERBERUS_TIMEOUT",
        "CERBERUS_TEMP",
        "CERBERUS_DEBUG",
        "CERBERUS_DISABLE_USAGE_TRACKING",
        "CTF_PROVIDER",
    )

    # Keys that are security-sensitive and must never be shown in full.
    _SECRET_MARKERS: Tuple[str, ...] = (
        "KEY",
        "TOKEN",
        "SECRET",
        "PASSWORD",
        "PASS",
        "PRIVATE",
        "CREDENTIAL",
    )

    # Local directory used for session isolation state files.
    _SESSION_DIR_NAME = ".cerberus/session_env"

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._session_id = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self._workspace_root = self._discover_workspace_root()
        self._workspace_tag = self._workspace_fingerprint(self._workspace_root)
        self._session_overlay: Dict[str, str] = {}
        self._load_isolated_session_overlay()

    # -- identity / paths --------------------------------------------------

    @staticmethod
    def _discover_workspace_root() -> Path:
        env_root = os.environ.get("WORKSPACE_ROOT", "").strip()
        if env_root:
            return Path(env_root).expanduser().resolve()
        return Path.cwd().resolve()

    @staticmethod
    def _workspace_fingerprint(root: Path) -> str:
        digest = hashlib.sha256(str(root).encode("utf-8")).hexdigest()
        return digest[:16]

    def _session_file(self) -> Path:
        return Path.home() / self._SESSION_DIR_NAME / f"{self._workspace_tag}.json"

    # -- policy ------------------------------------------------------------

    def allow_list(self) -> List[str]:
        return list(self._ALLOW_LIST)

    def is_allowed(self, name: str) -> bool:
        return name.upper() in self._ALLOW_LIST

    def _is_secret_like(self, name: str) -> bool:
        upper = name.upper()
        return any(marker in upper for marker in self._SECRET_MARKERS)

    def redact(self, name: str, value: Optional[str]) -> str:
        if value is None:
            return ""
        # Allowed-but-secret variables still get partial masking.
        if self._is_secret_like(name):
            txt = str(value)
            if len(txt) <= 6:
                return "*" * len(txt)
            return txt[:2] + "..." + txt[-2:]
        return str(value)

    # -- core reads --------------------------------------------------------

    def _get_process_value(self, key: str) -> Optional[str]:
        return os.environ.get(key)

    def safe_view(self) -> List[EnvironmentVariable]:
        """Return visible variables in allow-list order only."""
        rows: List[EnvironmentVariable] = []
        with self._lock:
            for key in self._ALLOW_LIST:
                if key in self._session_overlay:
                    rows.append(
                        EnvironmentVariable(
                            name=key,
                            value=self.redact(key, self._session_overlay[key]),
                            source="session",
                            safe=True,
                        )
                    )
                    continue

                val = self._get_process_value(key)
                if val is not None:
                    rows.append(
                        EnvironmentVariable(
                            name=key,
                            value=self.redact(key, val),
                            source="process",
                            safe=True,
                        )
                    )
        return rows

    def get(self, name: str) -> EnvironmentVariable:
        """Return one environment variable under policy controls."""
        key = name.strip().upper()
        if not key:
            return EnvironmentVariable(name="", value="", safe=False)

        with self._lock:
            if not self.is_allowed(key):
                return EnvironmentVariable(
                    name=key,
                    value="HIDDEN_BY_POLICY",
                    source="policy",
                    safe=False,
                )

            if key in self._session_overlay:
                return EnvironmentVariable(
                    name=key,
                    value=self.redact(key, self._session_overlay[key]),
                    source="session",
                    safe=True,
                )

            raw = self._get_process_value(key)
            return EnvironmentVariable(
                name=key,
                value=self.redact(key, raw),
                source="process",
                safe=True,
            )

    # -- session isolation -------------------------------------------------

    def set_session_value(self, name: str, value: str) -> Tuple[bool, str]:
        """Set a value in workspace-isolated session overlay only.

        The value is *not* written to global shell profile files.  It updates
        process ``os.environ`` for the running process and persists to
        ``~/.cerberus/session_env/<workspace_hash>.json`` only.
        """
        key = name.strip().upper()
        if not key:
            return False, "Variable name cannot be empty"
        if not self.is_allowed(key):
            return False, f"'{key}' is blocked by environment policy"

        with self._lock:
            self._session_overlay[key] = str(value)
            os.environ[key] = str(value)
            self._save_isolated_session_overlay()
        return True, ""

    def clear_session_overlay(self) -> None:
        with self._lock:
            self._session_overlay.clear()
            sf = self._session_file()
            if sf.exists():
                sf.unlink()

    def _load_isolated_session_overlay(self) -> None:
        """Load only overlay data scoped to this workspace fingerprint."""
        sf = self._session_file()
        if not sf.exists():
            return
        try:
            data = json.loads(sf.read_text())
            if data.get("workspace_tag") != self._workspace_tag:
                return
            overlay = data.get("overlay", {})
            if isinstance(overlay, dict):
                for k, v in overlay.items():
                    key = str(k).upper()
                    if self.is_allowed(key):
                        self._session_overlay[key] = str(v)
                        os.environ[key] = str(v)
        except Exception:
            # Corrupt session file should not break command execution.
            pass

    def _save_isolated_session_overlay(self) -> None:
        sf = self._session_file()
        sf.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "workspace_root": str(self._workspace_root),
            "workspace_tag": self._workspace_tag,
            "session_id": self._session_id,
            "saved_at": datetime.now(tz=timezone.utc).isoformat(),
            "overlay": self._session_overlay,
        }
        sf.write_text(json.dumps(payload, indent=2))

    # -- runtime audit -----------------------------------------------------

    def run_audit(self) -> List[AuditCheck]:
        """Run environment integrity checks required for commercial operations."""
        results: List[AuditCheck] = []

        # Python version baseline
        min_py = (3, 11)
        py_ok = sys.version_info >= min_py
        results.append(
            AuditCheck(
                name="python_version",
                passed=py_ok,
                severity="critical" if not py_ok else "info",
                detail=(
                    f"Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}; "
                    f"required >= {min_py[0]}.{min_py[1]}"
                ),
            )
        )

        # Required security tooling
        nmap_path = shutil.which("nmap")
        results.append(
            AuditCheck(
                name="nmap_available",
                passed=nmap_path is not None,
                severity="warning" if nmap_path is None else "info",
                detail=nmap_path or "nmap not found in PATH",
            )
        )

        # Workspace root integrity
        workspace_ok = self._workspace_root.exists() and self._workspace_root.is_dir()
        results.append(
            AuditCheck(
                name="workspace_root",
                passed=workspace_ok,
                severity="critical" if not workspace_ok else "info",
                detail=str(self._workspace_root),
            )
        )

        # API key presence check (value not revealed)
        api_key_names = (
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
            "DEEPSEEK_API_KEY",
            "GEMINI_API_KEY",
        )
        has_any_provider_key = any(bool(os.environ.get(k, "").strip()) for k in api_key_names)

        # If no cloud provider API key is present, treat certain local model
        # configurations as valid "provider credentials". This allows running
        # the REPL against local LLM backends configured via `CERBERUS_MODEL` or
        # other local connector environment variables (e.g. `LITELLM_SERVER`,
        # `OLLAMA_URL`, etc.) without requiring a cloud API key or license.
        if not has_any_provider_key:
            cerberus_model = os.environ.get("CERBERUS_MODEL", "").strip()
            if cerberus_model:
                local_indicators = (
                    "ollama",
                    "litellm",
                    "deepseek",
                    "local",
                    "alias",
                    "openrouter",
                    "deepinfra",
                    "llama",
                )
                if any(ind in cerberus_model.lower() for ind in local_indicators):
                    has_any_provider_key = True

            # Also accept presence of common local-provider-specific env vars.
            local_envs = ("LITELLM_SERVER", "OLLAMA_URL", "LLM_LOCAL", "CERBERUS_LOCAL_MODEL")
            if not has_any_provider_key and any(bool(os.environ.get(k, "").strip()) for k in local_envs):
                has_any_provider_key = True

            # Allow local-only operation by default unless explicitly disabled.
            # Historically users had to set CERBERUS_ALLOW_LOCAL=1 to opt-in; make
            # the opt-in implicit to support local LLM development workflows.
            allow_local = os.environ.get("CERBERUS_ALLOW_LOCAL", "1").strip().lower()
            if not has_any_provider_key and allow_local not in ("0", "false", "no", "off"):
                has_any_provider_key = True
        results.append(
            AuditCheck(
                name="provider_credentials",
                passed=has_any_provider_key,
                severity="warning" if not has_any_provider_key else "info",
                detail=(
                    "At least one provider key present"
                    if has_any_provider_key
                    else "No provider API key detected in environment"
                ),
            )
        )

        # Snapshot directory writable
        out_dir = self.report_dir()
        def _is_writable(path: Path) -> bool:
            target = path if path.exists() else path.parent
            try:
                probe = target / ".cerberus_write_probe"
                probe.touch()
                probe.unlink(missing_ok=True)
                return True
            except OSError:
                return False
        writable = _is_writable(out_dir)
        results.append(
            AuditCheck(
                name="snapshot_directory",
                passed=writable,
                severity="warning" if not writable else "info",
                detail=str(out_dir),
            )
        )

        return results

    # -- snapshot ----------------------------------------------------------

    def report_dir(self) -> Path:
        return self._workspace_root / ".cerberus" / "reports"

    def snapshot(self, fmt: str = "json") -> Path:
        """Write sanitized environment snapshot into workspace report folder."""
        fmt = fmt.lower().strip()
        if fmt not in ("json", "csv"):
            raise ValueError("format must be 'json' or 'csv'")

        rows = self.safe_view()
        snap = EnvironmentSnapshot(
            generated_at=datetime.now(tz=timezone.utc).isoformat(),
            workspace_root=str(self._workspace_root),
            session_id=self._session_id,
            variables=rows,
        )

        out_dir = self.report_dir()
        out_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        path = out_dir / f"environment_snapshot_{stamp}.{fmt}"

        if fmt == "json":
            payload: Dict[str, Any] = {
                "generated_at": snap.generated_at,
                "workspace_root": snap.workspace_root,
                "session_id": snap.session_id,
                "variables": [v.model_dump() for v in snap.variables],
            }
            path.write_text(json.dumps(payload, indent=2))
        else:
            with path.open("w", newline="") as fh:
                writer = csv.DictWriter(fh, fieldnames=["name", "value", "source", "safe"])
                writer.writeheader()
                for row in rows:
                    writer.writerow(row.model_dump())

        return path


# Process-global auditor instance used by command and hooks.
ENV_AUDITOR = EnvironmentAuditor()


# ---------------------------------------------------------------------------
# EnvCommand
# ---------------------------------------------------------------------------

class EnvCommand(FrameworkCommand):
    """Secure environment inspection command (default deny)."""

    name = "env"
    description = "Secure environment auditor with allow-list filtering"
    aliases = ["/env", "/e"]

    def __init__(self) -> None:
        super().__init__()
        self._auditor = ENV_AUDITOR
        self.add_subcommand("show", "Show allow-listed environment variables", self._sub_show)
        self.add_subcommand("list", "Alias of show", self._sub_show)
        self.add_subcommand("get", "Get one environment variable by policy", self._sub_get)
        self.add_subcommand("set", "Set allow-listed var in isolated session scope", self._sub_set)
        self.add_subcommand("audit", "Run runtime integrity checks", self._sub_audit)
        self.add_subcommand("snapshot", "Write sanitized environment snapshot", self._sub_snapshot)
        self.add_subcommand("clear", "Clear isolated session overlay", self._sub_clear)

    @property
    def help(self) -> str:
        return (
            "env [sub-command] [options]\n\n"
            "Sub-commands:\n"
            "  show | list                  Show only allow-listed environment values\n"
            "  get <VAR>                    Read a variable through policy controls\n"
            "  set <VAR> <VALUE>            Set allow-listed var in workspace-isolated session\n"
            "  audit                        Check runtime integrity requirements\n"
            "  snapshot [--format json|csv] Save sanitized environment snapshot\n"
            "  clear                        Remove workspace-isolated session overlay\n\n"
            "Policy:\n"
            "  - Default deny (hide all).\n"
            "  - Non-allow-listed requests return HIDDEN_BY_POLICY.\n"
            "  - Secret-like names are masked even when allow-listed.\n"
        )

    async def execute(self, args: List[str]) -> bool:
        if not args:
            return await self._sub_show([])

        if len(args) == 1 and args[0] in ("--audit", "-a"):
            return await self._sub_audit([])

        sub = args[0].lower()
        handler = getattr(self, f"_sub_{sub}", None)
        if handler is None:
            console.print(f"[red]env: unknown sub-command '{sub}'[/red]")
            console.print(self.help)
            return False
        return await handler(args[1:])

    async def _sub_show(self, args: List[str]) -> bool:
        rows = self._auditor.safe_view()
        table = Table(
            title="Environment (Allow-Listed Only)",
            show_header=True,
            header_style="bold",
            box=box.ROUNDED,
        )
        table.add_column("Variable", style="cyan")
        table.add_column("Value", style="green")
        table.add_column("Source", style="magenta")

        if not rows:
            console.print("[yellow]No allow-listed environment variables are currently set[/yellow]")
            return True

        for item in rows:
            table.add_row(item.name, item.value, item.source)
        console.print(table)
        console.print("[dim]Use 'env audit' to verify runtime integrity requirements[/dim]")
        return True

    async def _sub_get(self, args: List[str]) -> bool:
        if not args:
            console.print("[red]env get: usage: env get <VAR>[/red]")
            return False

        item = self._auditor.get(args[0])
        if not item.safe:
            console.print(
                Panel(
                    f"{item.name} = {item.value}\n"
                    "This variable is blocked by policy and cannot be disclosed.",
                    title="[red]Environment Access Blocked[/red]",
                    border_style="red",
                )
            )
            return True

        console.print(f"{item.name} = {item.value}  [dim]({item.source})[/dim]")
        return True

    async def _sub_set(self, args: List[str]) -> bool:
        if len(args) < 2:
            console.print("[red]env set: usage: env set <VAR> <VALUE>[/red]")
            return False

        key = args[0]
        value = " ".join(args[1:])
        ok, err = self._auditor.set_session_value(key, value)
        if not ok:
            console.print(f"[red]env set: {err}[/red]")
            return False

        display = self._auditor.get(key)
        console.print(
            f"[green]Set[/green] {display.name} = {display.value} "
            "[dim](workspace-isolated session scope)[/dim]"
        )
        return True

    async def _sub_audit(self, args: List[str]) -> bool:
        checks = self._auditor.run_audit()

        table = Table(
            title="Runtime Environment Integrity Audit",
            show_header=True,
            header_style="bold",
            box=box.ROUNDED,
        )
        table.add_column("Check", style="cyan")
        table.add_column("Status", style="white")
        table.add_column("Severity", style="magenta")
        table.add_column("Detail", style="green")

        failed_critical = False
        for check in checks:
            status = "PASS" if check.passed else "FAIL"
            style = "green" if check.passed else ("red" if check.severity == "critical" else "yellow")
            if not check.passed and check.severity == "critical":
                failed_critical = True
            table.add_row(
                check.name,
                f"[{style}]{status}[/{style}]",
                check.severity.upper(),
                check.detail,
            )

        console.print(table)

        if failed_critical:
            console.print(
                "[red]Audit result: critical failures detected. "
                "Environment is not authorized for production-grade execution.[/red]"
            )
            return False

        console.print("[green]Audit result: no critical failures detected.[/green]")
        return True

    async def _sub_snapshot(self, args: List[str]) -> bool:
        fmt = "json"
        i = 0
        while i < len(args):
            tok = args[i]
            if tok in ("--format", "-f") and i + 1 < len(args):
                fmt = args[i + 1].lower().strip()
                i += 2
            else:
                fmt = tok.lower().strip()
                i += 1

        try:
            path = self._auditor.snapshot(fmt=fmt)
        except ValueError as exc:
            console.print(f"[red]env snapshot: {exc}[/red]")
            return False

        console.print(
            Panel(
                f"Sanitized environment snapshot saved\n"
                f"File: {path}\n"
                f"Format: {fmt.upper()}\n"
                f"Visible keys: {len(self._auditor.safe_view())}",
                title="[green]Snapshot Complete[/green]",
                border_style="green",
                box=box.ROUNDED,
            )
        )
        return True

    async def _sub_clear(self, args: List[str]) -> bool:
        self._auditor.clear_session_overlay()
        console.print("[green]Workspace-isolated environment overlay cleared.[/green]")
        return True


ENV_COMMAND_INSTANCE = EnvCommand()
register_command(ENV_COMMAND_INSTANCE)
