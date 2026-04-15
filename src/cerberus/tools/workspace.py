"""Workspace management and safe filesystem tooling for Cerberus AI.

This module provides:
1) Backward-compatible workspace helpers used across the codebase.
2) A new async CerebroWorkspaceTool for structured, audited, sandboxed
   filesystem operations with deterministic policy enforcement.

Key guarantees for CerebroWorkspaceTool:
- Strict path sandboxing under active engagement root.
- Read/write zone policy enforcement.
- Atomic file operations and metadata updates.
- Forensic labeling for file touches/moves.
- Async I/O for non-blocking tool operations.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime
import fnmatch
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import tempfile
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

import fcntl
from pydantic import BaseModel, Field

try:
    import aiofiles  # type: ignore
except Exception:
    aiofiles = None

try:
    from cerberus.memory import MemoryManager
except Exception:
    MemoryManager = None

try:
    from cerberus.memory.logic import clean_data
except Exception:
    clean_data = lambda value: value

try:
    from cerberus.repl.ui.logging import get_cerberus_logger
except Exception:
    get_cerberus_logger = None


_WORKSPACE_NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_DEFAULT_TEMP_PATTERNS = ("*.tmp", "*.temp", "*.log", "*.cache")


def _warn(message: str) -> None:
    print(f"[workspace] {message}")


def _is_valid_workspace_name(candidate: str | None) -> bool:
    if not candidate:
        return False
    return bool(_WORKSPACE_NAME_RE.match(candidate))


def _make_run_token() -> str:
    timestamp = datetime.now(tz=UTC).strftime("%Y%m%d-%H%M%S")
    random_part = secrets.token_hex(3)
    return f"run-{timestamp}-{random_part}"


def _fallback_workspace_base() -> Path:
    xdg_cache = os.getenv("XDG_CACHE_HOME")
    if xdg_cache:
        cache_root = Path(xdg_cache).expanduser()
    else:
        cache_root = Path.home() / ".cache"
    return (cache_root / "cerberus" / "workspaces").resolve()


# =============================================================================
# Compatibility workspace container
# =============================================================================


@dataclass(slots=True)
class ProjectSpace:
    """Compatibility workspace manager used by legacy and new tooling."""

    root_base: Path
    session_id: str
    session_root: Path = field(init=False)
    _initialized: bool = field(init=False, default=False)

    def __post_init__(self) -> None:
        self.root_base = self.root_base.expanduser()
        self.session_root = (self.root_base / self.session_id).resolve()

    @classmethod
    def from_environment(cls, env: Mapping[str, str] | None = None) -> ProjectSpace:
        source = env if env is not None else os.environ

        explicit_active = source.get("CERBERUS_WORKSPACE_ACTIVE_ROOT")
        if explicit_active:
            active = Path(explicit_active).expanduser().resolve()
            return cls(root_base=active.parent, session_id=active.name)

        explicit_base = source.get("CERBERUS_WORKSPACE_DIR")
        explicit_name = source.get("CERBERUS_WORKSPACE")

        if explicit_base:
            base_dir = Path(explicit_base).expanduser().resolve()
        else:
            base_dir = (Path.cwd() / "workspaces").resolve()

        if _is_valid_workspace_name(explicit_name):
            run_name = str(explicit_name)
        elif explicit_name:
            _warn(f"Invalid CERBERUS_WORKSPACE '{explicit_name}'. Using auto-generated run directory instead.")
            run_name = _make_run_token()
        else:
            run_name = _make_run_token()

        return cls(root_base=base_dir, session_id=run_name)

    def initialize(self) -> Path:
        try:
            self.session_root.mkdir(parents=True, exist_ok=True)
            self._initialized = True
            return self.session_root
        except OSError as exc:
            if isinstance(exc, PermissionError):
                fallback_base = _fallback_workspace_base()
                fallback_root = (fallback_base / self.session_id).resolve()
                try:
                    fallback_root.mkdir(parents=True, exist_ok=True)
                except OSError as fallback_exc:
                    raise RuntimeError(
                        f"Unable to initialize workspace at '{self.session_root}' and fallback '{fallback_root}': {fallback_exc}"
                    ) from fallback_exc

                _warn(
                    f"Workspace path '{self.session_root}' was not writable. Falling back to '{fallback_root}'."
                )
                self.root_base = fallback_base
                self.session_root = fallback_root
                os.environ["CERBERUS_WORKSPACE_ACTIVE_ROOT"] = str(fallback_root)
                self._initialized = True
                return self.session_root
            raise RuntimeError(f"Unable to initialize workspace at '{self.session_root}': {exc}") from exc

    def ensure_initialized(self) -> Path:
        if not self._initialized:
            return self.initialize()
        return self.session_root

    def _enforce_sandbox(self, candidate: Path) -> Path:
        root = self.ensure_initialized().resolve()
        resolved = candidate.resolve()
        try:
            resolved.relative_to(root)
        except ValueError as exc:
            raise ValueError(f"Path '{resolved}' escapes workspace sandbox '{root}'") from exc
        return resolved

    def get_path(self, *segments: str | os.PathLike[str], create_parent: bool = False) -> Path:
        target = self.ensure_initialized().joinpath(*[Path(segment) for segment in segments])
        safe_target = self._enforce_sandbox(target)
        if create_parent:
            safe_target.parent.mkdir(parents=True, exist_ok=True)
        return safe_target

    def cleanup(self, patterns: Iterable[str] | None = None, remove_empty_dirs: bool = True) -> int:
        roots = self.ensure_initialized()
        removed = 0
        matchers = tuple(patterns or _DEFAULT_TEMP_PATTERNS)

        for pattern in matchers:
            for hit in roots.rglob(pattern):
                if hit.is_file():
                    safe_hit = self._enforce_sandbox(hit)
                    safe_hit.unlink(missing_ok=True)
                    removed += 1

        if remove_empty_dirs:
            self._prune_empty_dirs()

        return removed

    def _prune_empty_dirs(self) -> None:
        root = self.ensure_initialized()
        all_dirs = sorted([d for d in root.rglob("*") if d.is_dir()], key=lambda p: len(p.parts), reverse=True)
        for directory in all_dirs:
            safe_dir = self._enforce_sandbox(directory)
            try:
                safe_dir.rmdir()
            except OSError:
                continue

    def archive(self, destination: str | os.PathLike[str] | None = None) -> Path:
        root = self.ensure_initialized()

        if destination is None:
            archive_target = (self.root_base / f"{self.session_id}.zip").resolve()
        else:
            archive_target = Path(destination).expanduser().resolve()
            if archive_target.suffix.lower() != ".zip":
                archive_target = archive_target.with_suffix(".zip")

        archive_target.parent.mkdir(parents=True, exist_ok=True)
        generated_path = shutil.make_archive(
            base_name=str(archive_target.with_suffix("")),
            format="zip",
            root_dir=str(root),
            base_dir=".",
        )
        return Path(generated_path).resolve()

    def freeze(self, destination: str | os.PathLike[str] | None = None) -> Path:
        return self.archive(destination=destination)


# =============================================================================
# Cerebro workspace schemas
# =============================================================================


class AssetNode(BaseModel):
    path: str
    kind: str
    size_bytes: int = 0
    modified_at: str
    tags: List[str] = Field(default_factory=list)


class AssetTree(BaseModel):
    workspace_root: str
    generated_at: str
    logs: List[AssetNode] = Field(default_factory=list)
    artifacts: List[AssetNode] = Field(default_factory=list)
    findings: List[AssetNode] = Field(default_factory=list)
    evidence: List[AssetNode] = Field(default_factory=list)
    work: List[AssetNode] = Field(default_factory=list)


class WorkspaceSummary(BaseModel):
    workspace_root: str
    case_name: str
    total_files: int
    total_size_bytes: int
    last_modified: str


class RetentionStageRecord(BaseModel):
    path: str
    stage: str  # trash | critical_evidence
    reason: str = ""
    staged_at: str
    staged_by: str = "unknown"


class ArtifactCategorizationResult(BaseModel):
    source: str
    destination: str
    moved: bool
    metadata_written: bool


# =============================================================================
# Cerebro workspace tool
# =============================================================================


class CerebroWorkspaceTool:
    """Structured, safe, and audited filesystem interaction tool."""

    READ_ONLY_ZONES = {"targets", "config"}
    READ_WRITE_ZONES = {"work", "evidence"}
    AUX_READ_ZONES = {"logs", "artifacts", "findings", "reports", "shared", "private", ".cerberus"}
    FORENSIC_FILE = ".cerberus/workspace/forensic_labels.jsonl"
    RETENTION_FILE = ".cerberus/workspace/retention_stage.json"
    LOCK_FILE = ".cerberus/workspace/ops.lock"

    def __init__(self, workspace: Optional[ProjectSpace] = None) -> None:
        self._space = workspace or get_project_space()
        self._root = self._space.ensure_initialized().resolve()
        self._memory = MemoryManager() if MemoryManager else None
        self._logger = get_cerberus_logger() if get_cerberus_logger else None
        self._ensure_layout()

    def _ensure_layout(self) -> None:
        # Ensure explicit zone layout exists.
        for zone in ("work", "evidence", "targets", "config", "logs", "artifacts", "findings"):
            (self._root / zone).mkdir(parents=True, exist_ok=True)
        (self._root / ".cerberus" / "workspace").mkdir(parents=True, exist_ok=True)

    def _now(self) -> str:
        return datetime.now(tz=UTC).isoformat()

    def _rel_path(self, path: Path) -> str:
        return str(path.resolve().relative_to(self._root))

    def _safe_resolve(self, candidate: str | os.PathLike[str]) -> Path:
        path = Path(candidate)
        if not path.is_absolute():
            path = self._root / path
        resolved = path.expanduser().resolve()
        try:
            resolved.relative_to(self._root)
        except ValueError as exc:
            raise ValueError(f"Path escapes workspace sandbox: {resolved}") from exc
        return resolved

    def _zone_of(self, path: Path) -> str:
        rel = path.resolve().relative_to(self._root)
        if not rel.parts:
            return ""
        return rel.parts[0]

    def _assert_read_allowed(self, path: Path) -> None:
        # Reads are allowed within root; write restrictions are stricter.
        _ = self._safe_resolve(path)

    def _assert_write_allowed(self, path: Path) -> None:
        resolved = self._safe_resolve(path)
        zone = self._zone_of(resolved)
        if zone not in self.READ_WRITE_ZONES:
            raise PermissionError(
                f"Write denied for zone '{zone}'. Allowed write zones: {sorted(self.READ_WRITE_ZONES)}"
            )

    def _lock_path(self) -> Path:
        return self._safe_resolve(self.LOCK_FILE)

    def _retention_path(self) -> Path:
        return self._safe_resolve(self.RETENTION_FILE)

    def _forensic_path(self) -> Path:
        return self._safe_resolve(self.FORENSIC_FILE)

    async def _acquire_lock(self) -> Any:
        lock_path = self._lock_path()
        lock_path.parent.mkdir(parents=True, exist_ok=True)

        def _open_and_lock() -> Any:
            handle = open(lock_path, "a+", encoding="utf-8")
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            return handle

        return await asyncio.to_thread(_open_and_lock)

    async def _release_lock(self, handle: Any) -> None:
        def _unlock() -> None:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            finally:
                handle.close()

        await asyncio.to_thread(_unlock)

    async def _atomic_write_json(self, path: Path, payload: Dict[str, Any]) -> None:
        encoded = json.dumps(payload, ensure_ascii=True, indent=2).encode("utf-8")

        def _write() -> None:
            path.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as tmp:
                tmp.write(encoded)
                tmp_path = Path(tmp.name)
            tmp_path.replace(path)

        await asyncio.to_thread(_write)

    async def _read_json(self, path: Path, default: Dict[str, Any]) -> Dict[str, Any]:
        if not path.exists():
            return default

        def _read() -> Dict[str, Any]:
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                return default

        return await asyncio.to_thread(_read)

    async def _append_forensic_label(
        self,
        *,
        path: Path,
        agent_id: str,
        tool_source: str,
        action: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        forensic = self._forensic_path()
        record = {
            "timestamp": self._now(),
            "path": self._rel_path(path),
            "agent_id": agent_id,
            "tool_source": tool_source,
            "action": action,
            "metadata": clean_data(metadata or {}),
        }

        # Atomic append: read existing, append, rewrite.
        existing = []
        if forensic.exists():
            def _read_lines() -> List[str]:
                return forensic.read_text(encoding="utf-8").splitlines()
            existing = await asyncio.to_thread(_read_lines)

        existing.append(json.dumps(record, ensure_ascii=True))

        def _rewrite() -> None:
            forensic.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile("w", dir=forensic.parent, delete=False, encoding="utf-8") as tmp:
                tmp.write("\n".join(existing) + "\n")
                tmp_path = Path(tmp.name)
            tmp_path.replace(forensic)

        await asyncio.to_thread(_rewrite)

        if self._logger is not None:
            try:
                self._logger.audit(
                    "Workspace forensic label appended",
                    actor=agent_id,
                    data={"path": self._rel_path(path), "action": action, "tool_source": tool_source},
                    tags=["workspace", "forensic", action],
                )
            except Exception:
                pass

    def _is_probably_text(self, path: Path) -> bool:
        if path.suffix.lower() in {
            ".txt", ".log", ".json", ".jsonl", ".md", ".yaml", ".yml", ".ini", ".cfg", ".csv", ".xml", ".html", ".py", ".sh", ".conf"
        }:
            return True
        if path.suffix.lower() in {".pcap", ".pcapng", ".png", ".jpg", ".jpeg", ".gif", ".zip", ".gz", ".tar", ".pdf", ".bin", ".exe"}:
            return False
        return True

    def _build_asset_node(self, path: Path) -> AssetNode:
        stat = path.stat()
        return AssetNode(
            path=self._rel_path(path),
            kind="file" if path.is_file() else "dir",
            size_bytes=int(stat.st_size) if path.is_file() else 0,
            modified_at=datetime.fromtimestamp(stat.st_mtime, tz=UTC).isoformat(),
            tags=[],
        )

    async def _list_zone_files(self, zone: str) -> List[AssetNode]:
        zone_root = self._safe_resolve(zone)
        if not zone_root.exists():
            return []

        def _collect() -> List[AssetNode]:
            nodes: List[AssetNode] = []
            for path in zone_root.rglob("*"):
                if path.is_file():
                    try:
                        nodes.append(self._build_asset_node(path))
                    except Exception:
                        continue
            nodes.sort(key=lambda n: n.path)
            return nodes

        return await asyncio.to_thread(_collect)

    async def list_assets(self) -> Dict[str, Any]:
        """Return structured workspace tree for logs/artifacts/findings and zones."""
        lock = await self._acquire_lock()
        try:
            tree = AssetTree(
                workspace_root=str(self._root),
                generated_at=self._now(),
                logs=await self._list_zone_files("logs"),
                artifacts=await self._list_zone_files("artifacts"),
                findings=await self._list_zone_files("findings"),
                evidence=await self._list_zone_files("evidence"),
                work=await self._list_zone_files("work"),
            )
            return tree.model_dump(mode="json")
        finally:
            await self._release_lock(lock)

    async def categorize_artifact(
        self,
        *,
        source_path: str,
        category_subpath: str,
        agent_id: str = "unknown",
        tool_source: str = "workspace_tool",
    ) -> Dict[str, Any]:
        """Move raw file into /evidence/<category_subpath> atomically with forensic labeling."""
        lock = await self._acquire_lock()
        try:
            source = self._safe_resolve(source_path)
            if not source.exists() or not source.is_file():
                raise FileNotFoundError(f"Artifact source not found: {source_path}")

            # Normalize destination under evidence zone.
            relative_category = str(Path(category_subpath)).strip().strip("/")
            if relative_category.startswith("evidence/"):
                relative_category = relative_category[len("evidence/") :]

            destination_dir = self._safe_resolve(Path("evidence") / relative_category)
            self._assert_write_allowed(destination_dir / "_probe")
            destination_dir.mkdir(parents=True, exist_ok=True)

            destination = destination_dir / source.name
            self._assert_write_allowed(destination)

            # Atomic move in same filesystem when possible.
            def _move() -> None:
                source.replace(destination)

            await asyncio.to_thread(_move)

            await self._append_forensic_label(
                path=destination,
                agent_id=agent_id,
                tool_source=tool_source,
                action="categorize_artifact",
                metadata={"source": source_path, "destination": self._rel_path(destination)},
            )

            result = ArtifactCategorizationResult(
                source=source_path,
                destination=self._rel_path(destination),
                moved=True,
                metadata_written=True,
            )
            return result.model_dump(mode="json")
        finally:
            await self._release_lock(lock)

    async def get_summary(self) -> Dict[str, Any]:
        """Return workspace metadata summary (counts, size, recency, case)."""
        lock = await self._acquire_lock()
        try:
            def _scan() -> WorkspaceSummary:
                total_files = 0
                total_size = 0
                last_mtime = 0.0

                for path in self._root.rglob("*"):
                    if not path.is_file():
                        continue
                    total_files += 1
                    try:
                        stat = path.stat()
                    except OSError:
                        continue
                    total_size += int(stat.st_size)
                    if stat.st_mtime > last_mtime:
                        last_mtime = stat.st_mtime

                last_modified = (
                    datetime.fromtimestamp(last_mtime, tz=UTC).isoformat()
                    if last_mtime > 0
                    else self._now()
                )

                case_name = os.getenv("CERBERUS_WORKSPACE") or self._root.name
                return WorkspaceSummary(
                    workspace_root=str(self._root),
                    case_name=case_name,
                    total_files=total_files,
                    total_size_bytes=total_size,
                    last_modified=last_modified,
                )

            summary = await asyncio.to_thread(_scan)
            return summary.model_dump(mode="json")
        finally:
            await self._release_lock(lock)

    async def semantic_search(
        self,
        *,
        keywords: Sequence[str],
        max_results: int = 30,
        include_globs: Optional[Sequence[str]] = None,
    ) -> Dict[str, Any]:
        """Lightweight keyword search across text-like workspace files."""
        lock = await self._acquire_lock()
        try:
            needles = [item.strip().lower() for item in keywords if str(item).strip()]
            if not needles:
                return {"results": [], "count": 0}

            patterns = tuple(include_globs or ["**/*"])

            def _iter_candidates() -> Iterable[Path]:
                seen: set[Path] = set()
                for pattern in patterns:
                    for path in self._root.glob(pattern):
                        rp = path.resolve()
                        if rp in seen:
                            continue
                        seen.add(rp)
                        if rp.is_file():
                            yield rp

            async def _read_text(path: Path) -> str:
                if not self._is_probably_text(path):
                    return ""

                if aiofiles is not None:
                    try:
                        async with aiofiles.open(path, "r", encoding="utf-8", errors="ignore") as handle:
                            return await handle.read()
                    except Exception:
                        return ""

                def _sync_read() -> str:
                    try:
                        return path.read_text(encoding="utf-8", errors="ignore")
                    except Exception:
                        return ""

                return await asyncio.to_thread(_sync_read)

            results: List[Dict[str, Any]] = []
            for candidate in _iter_candidates():
                text = await _read_text(candidate)
                if not text:
                    continue

                lowered = text.lower()
                hits = sum(1 for needle in needles if needle in lowered)
                if hits == 0:
                    continue

                first_line = ""
                for line in text.splitlines():
                    low = line.lower()
                    if any(needle in low for needle in needles):
                        first_line = line.strip()[:240]
                        break

                results.append(
                    {
                        "path": self._rel_path(candidate),
                        "score": hits,
                        "snippet": first_line,
                    }
                )

                if len(results) >= max_results:
                    break

            results.sort(key=lambda item: (-int(item["score"]), str(item["path"])))
            return {"count": len(results), "results": results}
        finally:
            await self._release_lock(lock)

    async def stage_for_archive(
        self,
        *,
        file_path: str,
        stage: str,
        reason: str = "",
        agent_id: str = "unknown",
        tool_source: str = "workspace_tool",
    ) -> Dict[str, Any]:
        """Flag files for retention policy: trash or critical_evidence."""
        lock = await self._acquire_lock()
        try:
            normalized_stage = stage.strip().lower()
            if normalized_stage not in {"trash", "critical_evidence"}:
                raise ValueError("stage must be one of: trash, critical_evidence")

            target = self._safe_resolve(file_path)
            self._assert_read_allowed(target)
            if not target.exists() or not target.is_file():
                raise FileNotFoundError(f"File not found for staging: {file_path}")

            retention_path = self._retention_path()
            payload = await self._read_json(retention_path, default={"records": []})
            records = payload.get("records", []) if isinstance(payload, dict) else []
            if not isinstance(records, list):
                records = []

            rel_path = self._rel_path(target)
            records = [item for item in records if str(item.get("path", "")) != rel_path]

            record = RetentionStageRecord(
                path=rel_path,
                stage=normalized_stage,
                reason=reason,
                staged_at=self._now(),
                staged_by=agent_id,
            )
            records.append(record.model_dump(mode="json"))

            await self._atomic_write_json(retention_path, {"records": records})

            await self._append_forensic_label(
                path=target,
                agent_id=agent_id,
                tool_source=tool_source,
                action="stage_for_archive",
                metadata={"stage": normalized_stage, "reason": reason},
            )

            return {"status": "ok", "record": record.model_dump(mode="json")}
        finally:
            await self._release_lock(lock)


# =============================================================================
# Module-level compatibility helpers
# =============================================================================


_ACTIVE_SPACE: ProjectSpace | None = None


def _current_space() -> ProjectSpace:
    global _ACTIVE_SPACE
    desired = ProjectSpace.from_environment()
    if _ACTIVE_SPACE is None:
        _ACTIVE_SPACE = desired
        _ACTIVE_SPACE.initialize()
        return _ACTIVE_SPACE

    # Rehydrate cache when environment selects a different workspace root.
    if _ACTIVE_SPACE.session_root.resolve() != desired.session_root.resolve():
        _ACTIVE_SPACE = desired
        _ACTIVE_SPACE.initialize()
    return _ACTIVE_SPACE


def _get_workspace_dir() -> str:
    workspace_active_root = os.getenv("CERBERUS_WORKSPACE_ACTIVE_ROOT")
    if workspace_active_root:
        try:
            return str(Path(workspace_active_root).expanduser().resolve())
        except Exception:
            pass

    workspace_name = os.getenv("CERBERUS_WORKSPACE")
    workspace_base = os.getenv("CERBERUS_WORKSPACE_DIR")

    if not workspace_name and not workspace_base:
        return str(Path.cwd())

    try:
        return str(_current_space().session_root)
    except RuntimeError as exc:
        _warn(f"{exc}. Falling back to current directory.")
        return str(Path.cwd())


def _get_container_workspace_path() -> str:
    workspace_name = os.getenv("CERBERUS_WORKSPACE")

    if workspace_name and _is_valid_workspace_name(workspace_name):
        return f"/workspace/workspaces/{workspace_name}"

    if workspace_name:
        _warn(f"Invalid CERBERUS_WORKSPACE '{workspace_name}' for container path. Using '/'.")

    return "/"


def get_project_space() -> ProjectSpace:
    return _current_space()


def resolve_workspace_path(*segments: str | os.PathLike[str], create_parent: bool = False) -> str:
    return str(_current_space().get_path(*segments, create_parent=create_parent))


def get_workspace_tool() -> CerebroWorkspaceTool:
    return CerebroWorkspaceTool(workspace=_current_space())


# Async wrappers for tool registration and direct use.


async def list_assets() -> Dict[str, Any]:
    return await get_workspace_tool().list_assets()


async def categorize_artifact(
    source_path: str,
    category_subpath: str,
    agent_id: str = "unknown",
    tool_source: str = "workspace_tool",
) -> Dict[str, Any]:
    return await get_workspace_tool().categorize_artifact(
        source_path=source_path,
        category_subpath=category_subpath,
        agent_id=agent_id,
        tool_source=tool_source,
    )


async def get_summary() -> Dict[str, Any]:
    return await get_workspace_tool().get_summary()


async def semantic_search(
    keywords: Sequence[str],
    max_results: int = 30,
    include_globs: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    return await get_workspace_tool().semantic_search(
        keywords=keywords,
        max_results=max_results,
        include_globs=include_globs,
    )


async def stage_for_archive(
    file_path: str,
    stage: str,
    reason: str = "",
    agent_id: str = "unknown",
    tool_source: str = "workspace_tool",
) -> Dict[str, Any]:
    return await get_workspace_tool().stage_for_archive(
        file_path=file_path,
        stage=stage,
        reason=reason,
        agent_id=agent_id,
        tool_source=tool_source,
    )


__all__ = [
    "ProjectSpace",
    "CerebroWorkspaceTool",
    "AssetNode",
    "AssetTree",
    "WorkspaceSummary",
    "RetentionStageRecord",
    "ArtifactCategorizationResult",
    "get_project_space",
    "resolve_workspace_path",
    "get_workspace_tool",
    "list_assets",
    "categorize_artifact",
    "get_summary",
    "semantic_search",
    "stage_for_archive",
    "_get_workspace_dir",
    "_get_container_workspace_path",
    "_current_space",
]
