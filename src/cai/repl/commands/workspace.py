"""Case-isolated workspace command for Cerebro REPL."""

from __future__ import annotations

import asyncio
import base64
from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sys
import tarfile
import tempfile
import threading
from typing import Any, Dict, Iterable, List, Literal, Optional

from pydantic import BaseModel, Field
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from cai.memory import MemoryManager
from cai.memory.logic import clean_data
from cai.repl.commands.base import FrameworkCommand, handle_command as _base_handle_command, register_command

console = Console()

_CASE_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{3,64}$")
_AUDIT_MAGIC = "CEREBRO_AUDIT_V1"
_ARCHIVE_MAGIC = b"CAIARC1"

_ACTIVE_CASE_ROOT: Optional[Path] = None
_ACTIVE_AUDITOR: Optional["AuditTrail"] = None
_AUDIT_HOOK_INSTALLED = False
_COMMAND_HOOK_INSTALLED = False
_ORIGINAL_HANDLE_COMMAND = _base_handle_command
_AUDIT_GUARD = threading.local()


class CaseMetadata(BaseModel):
    name: str
    case_id: str
    root: str
    shared_dir: str
    private_dir: str
    logs_dir: str
    artifacts_dir: str
    reports_dir: str
    audit_file: str
    created_at: str
    updated_at: str
    status: Literal["active", "inactive", "archived"] = "inactive"
    archived_at: Optional[str] = None
    archive_path: Optional[str] = None


class CaseIndex(BaseModel):
    schema_version: str = "2.0"
    cases: List[CaseMetadata] = Field(default_factory=list)


class DashboardStats(BaseModel):
    case_name: str
    root: str
    disk_bytes: int
    artifact_count: int
    shared_dir: str
    private_dir: str


@dataclass
class AuditTrail:
    audit_file: Path
    user: str
    _lock: threading.Lock = threading.Lock()
    _last_hash: str = ""

    def initialize(self, *, case_name: str, case_id: str) -> None:
        self.audit_file.parent.mkdir(parents=True, exist_ok=True)
        if not self.audit_file.exists() or self.audit_file.stat().st_size == 0:
            record = {
                "magic": _AUDIT_MAGIC,
                "ts": datetime.now(tz=UTC).isoformat(),
                "event": "audit_initialized",
                "user": self.user,
                "case_name": case_name,
                "case_id": case_id,
                "details": {"note": "tamper-evident hash chain start"},
                "prev_hash": "0" * 64,
            }
            self._append_record(record)
        else:
            self._last_hash = self._load_last_hash()

    def command(self, command: str, args: Optional[List[str]]) -> None:
        payload = {
            "ts": datetime.now(tz=UTC).isoformat(),
            "event": "command",
            "user": self.user,
            "command": command,
            "args": args or [],
            "prev_hash": self._last_hash or "0" * 64,
        }
        self._append_record(payload)

    def file_touch(self, event_name: str, file_path: Path) -> None:
        payload = {
            "ts": datetime.now(tz=UTC).isoformat(),
            "event": "file_touch",
            "user": self.user,
            "file_event": event_name,
            "path": str(file_path),
            "prev_hash": self._last_hash or "0" * 64,
        }
        self._append_record(payload)

    def _append_record(self, payload: Dict[str, Any]) -> None:
        with self._lock:
            prev_hash = payload.get("prev_hash", self._last_hash or "0" * 64)
            canonical = json.dumps(payload, sort_keys=True, ensure_ascii=True).encode("utf-8")
            digest = hashlib.sha256(prev_hash.encode("utf-8") + canonical).hexdigest()
            payload["hash"] = digest
            payload["prev_hash"] = prev_hash
            _set_audit_guard(True)
            try:
                with self.audit_file.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(payload, ensure_ascii=True) + "\n")
            finally:
                _set_audit_guard(False)
            self._last_hash = digest

    def _load_last_hash(self) -> str:
        try:
            with self.audit_file.open("r", encoding="utf-8") as handle:
                last_line = ""
                for line in handle:
                    if line.strip():
                        last_line = line
                if not last_line:
                    return ""
                payload = json.loads(last_line)
                return str(payload.get("hash", ""))
        except Exception:
            return ""


class CaseManager:
    """Manage workspace case lifecycle with strict path and audit controls."""

    def __init__(self, *, user: str, memory: MemoryManager) -> None:
        self._user = user
        self._memory = memory
        self._base = Path(os.getenv("CEREBRO_WORKSPACE_DIR", str(Path.cwd() / "workspaces"))).expanduser().resolve()
        self._cases_root = self._base / "cases"
        self._meta_root = self._base / ".cai"
        self._index_file = self._meta_root / "case_index.json"
        self._active_file = self._meta_root / "active_case.json"

        self._cases_root.mkdir(parents=True, exist_ok=True)
        self._meta_root.mkdir(parents=True, exist_ok=True)

    def new_case(self, name: str) -> CaseMetadata:
        self._validate_case_name(name)
        case_id = secrets.token_hex(8)
        case_root = self._cases_root / f"{name}__{case_id}"
        case_root = self._guard_case_path(case_root)

        if case_root.exists():
            raise RuntimeError("Case directory collision detected; retry case creation")

        self._init_case_dirs(case_root)
        metadata = self._metadata_from_root(name=name, case_id=case_id, root=case_root)

        index = self._load_index()
        for case in index.cases:
            if case.status == "active":
                case.status = "inactive"
                case.updated_at = datetime.now(tz=UTC).isoformat()
        metadata.status = "active"
        index.cases.append(metadata)
        self._write_index(index)

        self._activate_case(metadata)
        self._record_memory_event("case_created", metadata)
        return metadata

    def switch_case(self, case_name_or_id: str) -> CaseMetadata:
        index = self._load_index()
        target = self._find_case(index, case_name_or_id)
        if target is None:
            raise RuntimeError(f"Case not found: {case_name_or_id}")

        target_root = self._guard_case_path(Path(target.root))
        if not target_root.exists():
            raise RuntimeError(f"Case root is missing: {target_root}")

        previous_payload = self._active_file.read_text(encoding="utf-8") if self._active_file.exists() else ""
        previous_env = {k: os.environ.get(k) for k in self._env_keys()}

        try:
            self._activate_case(target)
            for case in index.cases:
                if case.case_id == target.case_id:
                    case.status = "active"
                    case.updated_at = datetime.now(tz=UTC).isoformat()
                elif case.status == "active":
                    case.status = "inactive"
                    case.updated_at = datetime.now(tz=UTC).isoformat()
            self._write_index(index)
        except Exception:
            self._restore_env(previous_env)
            if previous_payload:
                self._active_file.parent.mkdir(parents=True, exist_ok=True)
                self._active_file.write_text(previous_payload, encoding="utf-8")
            elif self._active_file.exists():
                self._active_file.unlink()
            raise

        self._record_memory_event("case_switched", target)
        return target

    def list_cases(self) -> List[CaseMetadata]:
        index = self._load_index()
        return sorted(index.cases, key=lambda item: item.created_at, reverse=True)

    def active_case(self) -> Optional[CaseMetadata]:
        if not self._active_file.exists():
            return None
        try:
            payload = json.loads(self._active_file.read_text(encoding="utf-8"))
            return CaseMetadata.model_validate(payload)
        except Exception:
            return None

    def archive_case(self, case_name_or_id: str, passphrase: str) -> Path:
        if len(passphrase.strip()) < 8:
            raise RuntimeError("Archive passphrase must be at least 8 characters")

        index = self._load_index()
        case = self._find_case(index, case_name_or_id)
        if case is None:
            raise RuntimeError(f"Case not found: {case_name_or_id}")

        case_root = self._guard_case_path(Path(case.root))
        if not case_root.exists():
            raise RuntimeError(f"Case root is missing: {case_root}")

        archive_dir = self._base / "archives"
        archive_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%SZ")
        target_archive = archive_dir / f"{case.name}_{case.case_id}_{stamp}.carc"

        with tempfile.NamedTemporaryFile(prefix="cai_case_", suffix=".tar.gz", delete=False) as tmp:
            tar_path = Path(tmp.name)

        try:
            with tarfile.open(tar_path, "w:gz") as tar_handle:
                tar_handle.add(case_root, arcname=case_root.name)

            payload = tar_path.read_bytes()
            encrypted = self._encrypt_archive_payload(
                payload=payload,
                passphrase=passphrase,
                associated_data=case.case_id.encode("utf-8"),
            )
            target_archive.write_bytes(encrypted)
        finally:
            if tar_path.exists():
                tar_path.unlink()

        case.status = "archived"
        case.archived_at = datetime.now(tz=UTC).isoformat()
        case.updated_at = case.archived_at
        case.archive_path = str(target_archive)
        self._write_index(index)

        self._record_memory_event("case_archived", case, extra={"archive_path": str(target_archive)})
        return target_archive

    def dashboard(self) -> Optional[DashboardStats]:
        case = self.active_case()
        if case is None:
            return None

        root = self._guard_case_path(Path(case.root))
        disk_bytes = self._dir_size(root)
        artifacts = self._count_artifacts(Path(case.artifacts_dir))
        return DashboardStats(
            case_name=case.name,
            root=str(root),
            disk_bytes=disk_bytes,
            artifact_count=artifacts,
            shared_dir=case.shared_dir,
            private_dir=case.private_dir,
        )

    def _activate_case(self, case: CaseMetadata) -> None:
        root = self._guard_case_path(Path(case.root))
        self._init_case_dirs(root)

        self._atomic_write_json(self._active_file, case.model_dump(mode="json"))

        os.environ["CEREBRO_WORKSPACE"] = case.name
        os.environ["CEREBRO_WORKSPACE_DIR"] = str(self._base)
        os.environ["CEREBRO_WORKSPACE_ACTIVE_ROOT"] = str(root)
        os.environ["WORKSPACE_ROOT"] = str(root)
        os.environ["CEREBRO_SHARED_ROOT"] = str(case.shared_dir)
        os.environ["CEREBRO_PRIVATE_ROOT"] = str(case.private_dir)
        os.environ["CEREBRO_AGENT_WRITE_ROOT"] = str(case.private_dir)

        self.reset_project_space_cache()
        self._install_audit(case)

    def _install_audit(self, case: CaseMetadata) -> None:
        global _ACTIVE_AUDITOR, _ACTIVE_CASE_ROOT
        _ACTIVE_CASE_ROOT = Path(case.root).resolve()
        audit = AuditTrail(audit_file=Path(case.audit_file), user=self._user)
        audit.initialize(case_name=case.name, case_id=case.case_id)
        _ACTIVE_AUDITOR = audit

        self._install_file_touch_hook()
        self._install_command_hook()

    def _install_file_touch_hook(self) -> None:
        global _AUDIT_HOOK_INSTALLED
        if _AUDIT_HOOK_INSTALLED:
            return

        def _audit_callback(event: str, args: tuple[Any, ...]) -> None:
            if _ACTIVE_AUDITOR is None or _ACTIVE_CASE_ROOT is None:
                return
            if _audit_guard_enabled():
                return
            if event not in {
                "open",
                "os.remove",
                "os.rename",
                "os.replace",
                "os.rmdir",
                "os.mkdir",
                "pathlib.Path.unlink",
                "pathlib.Path.rename",
                "pathlib.Path.replace",
            }:
                return

            touched = _extract_path(args)
            if touched is None:
                return

            try:
                resolved = touched.resolve()
            except Exception:
                return

            try:
                resolved.relative_to(_ACTIVE_CASE_ROOT)
            except ValueError:
                return

            _ACTIVE_AUDITOR.file_touch(event_name=event, file_path=resolved)

        sys.addaudithook(_audit_callback)
        _AUDIT_HOOK_INSTALLED = True

    def _install_command_hook(self) -> None:
        global _COMMAND_HOOK_INSTALLED
        if _COMMAND_HOOK_INSTALLED:
            return

        import cai.repl.commands.base as base_module

        def _wrapped_handle_command(command: str, args: Optional[List[str]] = None) -> bool:
            if _ACTIVE_AUDITOR is not None:
                _ACTIVE_AUDITOR.command(command=command, args=args)
            return _ORIGINAL_HANDLE_COMMAND(command, args)

        base_module.handle_command = _wrapped_handle_command
        _COMMAND_HOOK_INSTALLED = True

    def _load_index(self) -> CaseIndex:
        if not self._index_file.exists():
            return CaseIndex()
        try:
            payload = json.loads(self._index_file.read_text(encoding="utf-8"))
            return CaseIndex.model_validate(payload)
        except Exception:
            return CaseIndex()

    def _write_index(self, index: CaseIndex) -> None:
        self._atomic_write_json(self._index_file, index.model_dump(mode="json"))

    def _find_case(self, index: CaseIndex, name_or_id: str) -> Optional[CaseMetadata]:
        needle = name_or_id.strip().lower()
        matches = [
            case for case in index.cases
            if case.case_id.lower() == needle or case.name.lower() == needle
        ]
        if not matches:
            return None
        return sorted(matches, key=lambda item: item.created_at, reverse=True)[0]

    def _metadata_from_root(self, *, name: str, case_id: str, root: Path) -> CaseMetadata:
        now = datetime.now(tz=UTC).isoformat()
        return CaseMetadata(
            name=name,
            case_id=case_id,
            root=str(root),
            shared_dir=str(root / "shared"),
            private_dir=str(root / "private"),
            logs_dir=str(root / "logs"),
            artifacts_dir=str(root / "artifacts"),
            reports_dir=str(root / "reports"),
            audit_file=str(root / "logs" / "session.audit"),
            created_at=now,
            updated_at=now,
            status="inactive",
        )

    def _init_case_dirs(self, root: Path) -> None:
        for rel in ("shared", "private", "logs", "artifacts", "reports", ".cai"):
            self._guard_case_path(root / rel).mkdir(parents=True, exist_ok=True)

    def _guard_case_path(self, path: Path) -> Path:
        resolved = path.resolve()
        try:
            resolved.relative_to(self._cases_root.resolve())
        except ValueError as exc:
            raise RuntimeError(f"Path escapes case root boundary: {resolved}") from exc
        return resolved

    @staticmethod
    def _atomic_write_json(path: Path, payload: Dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as tmp:
            tmp.write(json.dumps(payload, ensure_ascii=True, indent=2))
            tmp_path = Path(tmp.name)
        tmp_path.replace(path)

    @staticmethod
    def _env_keys() -> List[str]:
        return [
            "CEREBRO_WORKSPACE",
            "CEREBRO_WORKSPACE_DIR",
            "CEREBRO_WORKSPACE_ACTIVE_ROOT",
            "WORKSPACE_ROOT",
            "CEREBRO_SHARED_ROOT",
            "CEREBRO_PRIVATE_ROOT",
            "CEREBRO_AGENT_WRITE_ROOT",
        ]

    @staticmethod
    def _restore_env(previous_env: Dict[str, Optional[str]]) -> None:
        for key, value in previous_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    @staticmethod
    def _dir_size(root: Path) -> int:
        total = 0
        for path in root.rglob("*"):
            if path.is_file():
                try:
                    total += path.stat().st_size
                except OSError:
                    continue
        return total

    @staticmethod
    def _count_artifacts(artifacts_dir: Path) -> int:
        suffixes = {".pcap", ".pcapng", ".cap", ".png", ".jpg", ".jpeg", ".webp", ".har"}
        if not artifacts_dir.exists():
            return 0
        count = 0
        for path in artifacts_dir.rglob("*"):
            if path.is_file() and path.suffix.lower() in suffixes:
                count += 1
        return count

    @staticmethod
    def _format_bytes(size: int) -> str:
        value = float(size)
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if value < 1024 or unit == "TB":
                return f"{value:.2f} {unit}"
            value /= 1024.0
        return f"{value:.2f} TB"

    def _record_memory_event(self, event: str, case: CaseMetadata, extra: Optional[Dict[str, Any]] = None) -> None:
        payload = {
            "topic": "workspace-case",
            "finding": f"Case event {event} for {case.name} ({case.case_id})",
            "source": self._user,
            "tags": ["workspace", "case", event],
            "artifacts": {
                "case": case.model_dump(mode="json"),
                "extra": extra or {},
            },
        }
        self._memory.record(clean_data(payload))

    @staticmethod
    def _validate_case_name(name: str) -> None:
        if not _CASE_NAME_RE.match(name):
            raise RuntimeError("Case name must be 3-64 chars: letters, numbers, _ or -")

    @staticmethod
    def _encrypt_archive_payload(*, payload: bytes, passphrase: str, associated_data: bytes) -> bytes:
        try:
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        except Exception as exc:
            raise RuntimeError(
                "Archive encryption requires cryptography package with AESGCM support"
            ) from exc

        salt = os.urandom(16)
        nonce = os.urandom(12)
        iterations = 390000

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
        )
        key = kdf.derive(passphrase.encode("utf-8"))
        ciphertext = AESGCM(key).encrypt(nonce, payload, associated_data)

        header = {
            "version": 1,
            "salt": base64.b64encode(salt).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "iterations": iterations,
            "aad": base64.b64encode(associated_data).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        }
        return _ARCHIVE_MAGIC + json.dumps(header, ensure_ascii=True).encode("utf-8")

    @staticmethod
    def reset_project_space_cache() -> None:
        try:
            from cai.tools import workspace as workspace_module
            workspace_module._ACTIVE_SPACE = None
        except Exception:
            pass


class WorkspaceCommand(FrameworkCommand):
    """Professional case management command with strict isolation."""

    name = "/workspace"
    description = "Manage isolated client engagement cases"
    aliases = ["/ws", "workspace"]

    @property
    def help(self) -> str:
        return (
            "workspace new <name>\n"
            "workspace switch <name|case_id>\n"
            "workspace set <name>   # compat alias (switch if exists, else new)\n"
            "workspace list\n"
            "workspace archive <name|case_id> [--passphrase <secret>]\n"
            "workspace dashboard\n"
            "workspace status\n"
        )

    async def execute(self, args: List[str]) -> bool:
        if not args:
            self._render_dashboard(self._manager().dashboard())
            return True

        sub = args[0].strip().lower()
        manager = self._manager()

        if sub == "new":
            if len(args) < 2:
                raise RuntimeError("workspace new requires a case name")
            case = manager.new_case(args[1].strip())
            self._render_case_panel("Case Created", case)
            return True

        if sub in {"switch", "use"}:
            if len(args) < 2:
                raise RuntimeError("workspace switch requires a case name or id")
            case = manager.switch_case(args[1].strip())
            self._render_case_panel("Case Switched", case)
            return True

        if sub == "set":
            if len(args) < 2:
                raise RuntimeError("workspace set requires a case name")
            needle = args[1].strip()
            existing = manager.active_case()
            all_cases = manager.list_cases()
            target = next((item for item in all_cases if item.name == needle or item.case_id == needle), None)
            if target is not None:
                case = manager.switch_case(needle)
                self._render_case_panel("Case Switched", case)
                return True
            case = manager.new_case(needle)
            self._render_case_panel("Case Created", case)
            return True

        if sub in {"list", "ls"}:
            self._render_case_list(manager.list_cases())
            return True

        if sub in {"dashboard", "status", "get"}:
            self._render_dashboard(manager.dashboard())
            return True

        if sub == "archive":
            if len(args) < 2:
                raise RuntimeError("workspace archive requires a case name or id")
            case_ref = args[1].strip()
            passphrase = self._parse_passphrase(args[2:])
            if passphrase is None:
                passphrase = await asyncio.to_thread(
                    Prompt.ask,
                    "Archive passphrase",
                    password=True,
                )
            archive_path = manager.archive_case(case_ref, passphrase)
            console.print(f"[green]Case archive created:[/green] {archive_path}")
            return True

        raise RuntimeError(f"Unknown workspace subcommand: {sub}")

    def _manager(self) -> CaseManager:
        if isinstance(self.memory, MemoryManager):
            memory = self.memory
        else:
            memory = MemoryManager()
        memory.initialize()

        manager = CaseManager(user=self.session.user, memory=memory)
        manager.reset_project_space_cache()
        return manager

    @staticmethod
    def _parse_passphrase(tokens: List[str]) -> Optional[str]:
        if not tokens:
            return None
        if tokens[0] == "--passphrase" and len(tokens) >= 2:
            return tokens[1]
        return None

    def _render_case_panel(self, title: str, case: CaseMetadata) -> None:
        payload = {
            "name": case.name,
            "case_id": case.case_id,
            "root": case.root,
            "shared": case.shared_dir,
            "private": case.private_dir,
            "status": case.status,
        }
        console.print(
            Panel(
                json.dumps(payload, ensure_ascii=True, indent=2),
                title=title,
                border_style="green",
            )
        )

    def _render_case_list(self, cases: List[CaseMetadata]) -> None:
        table = Table(title="Engagement Cases")
        table.add_column("Name", style="cyan")
        table.add_column("Case ID", style="magenta")
        table.add_column("Status", style="white")
        table.add_column("Created", style="white")
        table.add_column("Size", style="white")

        for case in cases:
            root = Path(case.root)
            size = CaseManager._format_bytes(CaseManager._dir_size(root)) if root.exists() else "missing"
            table.add_row(case.name, case.case_id, case.status, case.created_at, size)

        console.print(table)

    def _render_dashboard(self, stats: Optional[DashboardStats]) -> None:
        if stats is None:
            console.print(Panel("No active case", title="Current Case Dashboard", border_style="yellow"))
            return

        table = Table(title="Current Case Dashboard")
        table.add_column("Metric", style="cyan", no_wrap=True)
        table.add_column("Value", style="white")
        table.add_row("Active root", stats.root)
        table.add_row("Disk usage", CaseManager._format_bytes(stats.disk_bytes))
        table.add_row("Captured artifacts", str(stats.artifact_count))
        table.add_row("Shared directory", stats.shared_dir)
        table.add_row("Private directory", stats.private_dir)
        console.print(table)


def _extract_path(args: Iterable[Any]) -> Optional[Path]:
    for item in args:
        if isinstance(item, Path):
            return item
        if isinstance(item, os.PathLike):
            return Path(item)
        if isinstance(item, bytes):
            try:
                return Path(item.decode("utf-8", errors="ignore"))
            except Exception:
                continue
        if isinstance(item, str):
            candidate = item.strip()
            if not candidate:
                continue
            if "/" in candidate or "\\" in candidate or candidate.startswith("."):
                return Path(candidate)
    return None


def _audit_guard_enabled() -> bool:
    return bool(getattr(_AUDIT_GUARD, "enabled", False))


def _set_audit_guard(enabled: bool) -> None:
    _AUDIT_GUARD.enabled = enabled


WORKSPACE_COMMAND_INSTANCE = WorkspaceCommand()
register_command(WORKSPACE_COMMAND_INSTANCE)
