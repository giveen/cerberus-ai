"""Hardened path navigator for workspace-scoped filesystem discovery."""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
import errno
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import tempfile
import threading
from typing import Any, Dict, Iterable, List, Optional, Sequence

try:
    import aiofiles  # type: ignore
except Exception:  # pragma: no cover - optional dependency.
    aiofiles = None

from cai.memory.logic import clean_data
from cai.repl.ui.logging import get_cerebro_logger
from cai.sdk.agents import function_tool
from cai.tools.validation import sanitize_tool_output
from cai.tools.workspace import get_project_space


_MAX_LIST_DEPTH = 6
_MAX_SEARCH_DEPTH = 8
_DEFAULT_READ_BYTES = 8192
_MAX_READ_BYTES = 64 * 1024
_MAX_SAFE_READ_SIZE = 10 * 1024 * 1024
_HEAD_TAIL_BYTES = 4096
_MAX_RESULTS = 250
_HASH_CHUNK_SIZE = 1024 * 1024
_TEXT_EXTENSIONS = {
    ".cfg", ".cnf", ".conf", ".csv", ".env", ".ini", ".json", ".jsonl", ".log",
    ".md", ".py", ".service", ".sh", ".sql", ".txt", ".xml", ".yaml", ".yml",
}
_SENSITIVE_READ_NAMES = {"shadow", "gshadow", "passwd", "master.passwd", "sam", "security", "ntds.dit"}
_PII_PATTERNS = (
    (re.compile(r"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b"), "[REDACTED_EMAIL]"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED_SSN]"),
)


@dataclass(frozen=True)
class SemanticError:
    code: str
    message: str
    retryable: bool
    category: str


@dataclass(frozen=True)
class FileRecord:
    path: str
    name: str
    kind: str
    depth: int
    size: int
    permissions: str
    modified_at: str
    interesting: List[str]
    priority: str


class PathGuard:
    """Workspace boundary validator for all filesystem requests."""

    def __init__(self, workspace_root: Path, audit_callback: Any) -> None:
        self._root = workspace_root.resolve()
        self._audit_callback = audit_callback
        self._temp_roots = self._build_temp_roots()

    def resolve(self, candidate: str | os.PathLike[str], *, action: str) -> Path:
        return self.validate_path(candidate, action=action, mode="read")

    def validate_path(self, candidate: str | os.PathLike[str], *, action: str, mode: str) -> Path:
        raw = Path(candidate).expanduser() if str(candidate).strip() else self._root
        resolved = (self._root / raw).resolve() if not raw.is_absolute() else raw.resolve()
        if mode == "read" and self._is_sensitive_system_path(resolved):
            self._audit_callback(
                "sensitive_file_blocked",
                {
                    "action": action,
                    "requested_path": str(raw),
                    "resolved_path": str(resolved),
                    "message": "Sensitive file read blocked",
                },
            )
            raise PermissionError("Sensitive file access blocked by PathGuard policy")

        if self._is_within(self._root, resolved):
            return resolved

        if mode == "read" and any(self._is_within(temp_root, resolved) for temp_root in self._temp_roots):
            return resolved

        try:
            resolved.relative_to(self._root)
        except ValueError:
            self._audit_callback(
                "boundary_violation",
                {
                    "action": action,
                    "requested_path": str(raw),
                    "resolved_path": str(resolved),
                    "message": "Boundary Violation",
                    "mode": mode,
                },
            )
            raise PermissionError("Boundary Violation: requested path escapes the active workspace sandbox")
        return resolved

    @staticmethod
    def _is_within(root: Path, candidate: Path) -> bool:
        try:
            candidate.relative_to(root)
            return True
        except ValueError:
            return False

    @staticmethod
    def _is_sensitive_system_path(path: Path) -> bool:
        lowered = path.name.lower()
        if lowered in _SENSITIVE_READ_NAMES:
            return True
        posix_text = str(path).lower().replace("\\", "/")
        return posix_text in {
            "/etc/shadow",
            "/etc/gshadow",
            "/etc/passwd",
            "/windows/system32/config/sam",
            "/windows/system32/config/security",
        }

    @staticmethod
    def _build_temp_roots() -> List[Path]:
        roots = {
            Path(tempfile.gettempdir()).resolve(),
            Path("/var/tmp").resolve(),
        }
        env_tmp = os.getenv("TMPDIR", "").strip()
        if env_tmp:
            with_tmp = Path(env_tmp).expanduser()
            if with_tmp.exists():
                roots.add(with_tmp.resolve())
        return sorted(roots)


class CerebroFilesystemTool:
    """Structured, sandboxed filesystem discovery with forensic logging."""

    def __init__(self) -> None:
        self._workspace = get_project_space().ensure_initialized().resolve()
        self._logger = get_cerebro_logger()
        self._audit_path = (self._workspace / ".cai" / "audit" / "filesystem_audit.jsonl").resolve()
        self._hash_log_path = (self._workspace / "evidence" / "discovery" / "filesystem" / "file_hashes.jsonl").resolve()
        self._audit_path.parent.mkdir(parents=True, exist_ok=True)
        self._hash_log_path.parent.mkdir(parents=True, exist_ok=True)
        self._guard = PathGuard(self._workspace, self._audit)
        self._loop = asyncio.new_event_loop()
        self._loop_thread = threading.Thread(target=self._run_loop, daemon=True)
        self._loop_thread.start()

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def _run_coro(self, coro: Any, timeout: float = 120.0) -> Dict[str, Any]:
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return future.result(timeout=timeout)

    def list_directory(
        self,
        *,
        path: str = ".",
        max_depth: int = 1,
        include_hidden: bool = True,
        interesting_only: bool = False,
    ) -> Dict[str, Any]:
        return self._run_coro(
            self._list_directory_async(
                path=path,
                max_depth=max_depth,
                include_hidden=include_hidden,
                interesting_only=interesting_only,
            )
        )

    def search_files(
        self,
        *,
        path: str = ".",
        pattern: str = "*",
        max_depth: int = 3,
        content_contains: str = "",
        include_hidden: bool = True,
        max_results: int = 100,
    ) -> Dict[str, Any]:
        return self._run_coro(
            self._search_files_async(
                path=path,
                pattern=pattern,
                max_depth=max_depth,
                content_contains=content_contains,
                include_hidden=include_hidden,
                max_results=max_results,
            )
        )

    def get_file_hash(self, *, file_path: str, algorithm: str = "sha256") -> Dict[str, Any]:
        return self._run_coro(self._get_file_hash_async(file_path=file_path, algorithm=algorithm))

    def read_file(self, *, file_path: str, max_bytes: int = _DEFAULT_READ_BYTES) -> Dict[str, Any]:
        return self._run_coro(self._read_file_async(file_path=file_path, max_bytes=max_bytes))

    def read_file_preview(self, *, file_path: str, max_bytes: int = _DEFAULT_READ_BYTES) -> Dict[str, Any]:
        return self._run_coro(self._read_file_preview_async(file_path=file_path, max_bytes=max_bytes))

    def write_file(self, *, file_path: str, content: str, encoding: str = "utf-8") -> Dict[str, Any]:
        return self._run_coro(self._write_file_async(file_path=file_path, content=content, encoding=encoding))

    def pwd(self) -> str:
        return self._redact_text(str(self._workspace))

    async def _list_directory_async(
        self,
        *,
        path: str,
        max_depth: int,
        include_hidden: bool,
        interesting_only: bool,
    ) -> Dict[str, Any]:
        try:
            root = self._guard.resolve(path, action="list_directory")
            if not root.exists():
                raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), str(root))
            if not root.is_dir():
                raise NotADirectoryError(errno.ENOTDIR, os.strerror(errno.ENOTDIR), str(root))

            depth_limit = max(0, min(int(max_depth), _MAX_LIST_DEPTH))
            entries = await self._walk_directory(root, depth_limit, include_hidden)
            if interesting_only:
                entries = [item for item in entries if item.interesting]
            response = {
                "ok": True,
                "listed_path": self._display_path(root),
                "max_depth": depth_limit,
                "entry_count": len(entries),
                "entries": [asdict(item) for item in entries],
                "interesting_paths": [item.path for item in entries if item.interesting],
            }
            await self._audit_async("list_directory", {"path": self._display_path(root), "max_depth": depth_limit, "entry_count": len(entries)})
            return clean_data(response)
        except OSError as exc:
            semantic = self._semantic_os_error(exc, action="list directory")
            return self._error(semantic)

    async def _search_files_async(
        self,
        *,
        path: str,
        pattern: str,
        max_depth: int,
        content_contains: str,
        include_hidden: bool,
        max_results: int,
    ) -> Dict[str, Any]:
        try:
            root = self._guard.resolve(path, action="search_files")
            if not root.exists():
                raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), str(root))
            if not root.is_dir():
                raise NotADirectoryError(errno.ENOTDIR, os.strerror(errno.ENOTDIR), str(root))

            depth_limit = max(0, min(int(max_depth), _MAX_SEARCH_DEPTH))
            result_cap = max(1, min(int(max_results), _MAX_RESULTS))
            matches = await self._search_walk(
                root=root,
                pattern=(pattern or "*").strip() or "*",
                max_depth=depth_limit,
                content_contains=content_contains.strip(),
                include_hidden=include_hidden,
                max_results=result_cap,
            )
            response = {
                "ok": True,
                "searched_path": self._display_path(root),
                "pattern": pattern or "*",
                "content_contains": self._redact_text(content_contains.strip()),
                "max_depth": depth_limit,
                "count": len(matches),
                "results": matches,
            }
            await self._audit_async(
                "search_files",
                {
                    "path": self._display_path(root),
                    "pattern": pattern or "*",
                    "content_query": bool(content_contains.strip()),
                    "count": len(matches),
                },
            )
            return clean_data(response)
        except OSError as exc:
            semantic = self._semantic_os_error(exc, action="search files")
            return self._error(semantic)

    async def _get_file_hash_async(self, *, file_path: str, algorithm: str) -> Dict[str, Any]:
        try:
            candidate = self._guard.resolve(file_path, action="get_file_hash")
            if not candidate.exists():
                raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), str(candidate))
            if not candidate.is_file():
                raise IsADirectoryError(errno.EISDIR, os.strerror(errno.EISDIR), str(candidate))
            algo = (algorithm or "sha256").strip().lower()
            if algo != "sha256":
                semantic = SemanticError(
                    code="unsupported_algorithm",
                    message="Only SHA-256 is supported for forensic hashing.",
                    retryable=False,
                    category="validation",
                )
                return self._error(semantic)

            digest = await self._hash_file(candidate)
            stat_result = await asyncio.to_thread(candidate.stat)
            evidence = {
                "timestamp": datetime.now(tz=UTC).isoformat(),
                "path": self._display_path(candidate),
                "sha256": digest,
                "size": int(stat_result.st_size),
                "modified_at": datetime.fromtimestamp(stat_result.st_mtime, tz=UTC).isoformat(),
            }
            await self._append_jsonl(self._hash_log_path, evidence)
            await self._audit_async("get_file_hash", {"path": evidence["path"], "sha256": digest})
            return clean_data({"ok": True, **evidence, "evidence_log": self._display_path(self._hash_log_path)})
        except OSError as exc:
            semantic = self._semantic_os_error(exc, action="hash file")
            return self._error(semantic)

    async def _read_file_preview_async(self, *, file_path: str, max_bytes: int) -> Dict[str, Any]:
        try:
            candidate = self._guard.validate_path(file_path, action="cat_file", mode="read")
            if not candidate.exists():
                raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), str(candidate))
            if not candidate.is_file():
                raise IsADirectoryError(errno.EISDIR, os.strerror(errno.EISDIR), str(candidate))
            limit = max(128, min(int(max_bytes), _MAX_READ_BYTES))
            preview = await self._read_preview(candidate, limit)
            stat_result = await asyncio.to_thread(candidate.stat)
            response = {
                "ok": True,
                "path": self._display_path(candidate),
                "size": int(stat_result.st_size),
                "truncated": int(stat_result.st_size) > limit,
                "preview": clean_data(self._scrub_content(preview)),
            }
            await self._audit_async("read_file_preview", {"path": response["path"], "bytes": limit})
            return clean_data(response)
        except OSError as exc:
            semantic = self._semantic_os_error(exc, action="read file")
            return self._error(semantic)

    async def _read_file_async(self, *, file_path: str, max_bytes: int) -> Dict[str, Any]:
        try:
            candidate = self._guard.validate_path(file_path, action="read_file", mode="read")
            if not candidate.exists():
                raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), str(candidate))
            if not candidate.is_file():
                raise IsADirectoryError(errno.EISDIR, os.strerror(errno.EISDIR), str(candidate))
            stat_result = await asyncio.to_thread(candidate.stat)
            file_size = int(stat_result.st_size)
            limit = max(128, min(int(max_bytes), _MAX_READ_BYTES))
            if file_size > _MAX_SAFE_READ_SIZE:
                summary = await self._head_tail_summary(candidate, file_size=file_size)
                response = {
                    "ok": False,
                    "path": self._display_path(candidate),
                    "size": file_size,
                    "mode": "summary",
                    "summary": summary,
                    "error": {
                        "code": "file_too_large",
                        "message": "File exceeds 10MB guardrail. Returning head/tail summary instead of full content.",
                        "retryable": False,
                        "category": "size_limit",
                    },
                }
                await self._audit_async("read_file_summary", {"path": response["path"], "size": file_size})
                return clean_data(response)

            content = await self._read_full_text(candidate, limit=limit)
            response = {
                "ok": True,
                "path": self._display_path(candidate),
                "size": file_size,
                "mode": "content",
                "content": clean_data(self._scrub_content(content)),
                "truncated": False,
            }
            await self._audit_async("read_file", {"path": response["path"], "size": file_size})
            return clean_data(response)
        except OSError as exc:
            semantic = self._semantic_os_error(exc, action="read file")
            return self._error(semantic)

    async def _write_file_async(self, *, file_path: str, content: str, encoding: str) -> Dict[str, Any]:
        try:
            candidate = self._guard.validate_path(file_path, action="write_file", mode="write")
            candidate.parent.mkdir(parents=True, exist_ok=True)
            payload = content if isinstance(content, str) else str(content)
            await self._write_text(candidate, payload, encoding=encoding or "utf-8")
            stat_result = await asyncio.to_thread(candidate.stat)
            digest = await self._hash_file(candidate)
            evidence = {
                "timestamp": datetime.now(tz=UTC).isoformat(),
                "path": self._display_path(candidate),
                "sha256": digest,
                "size": int(stat_result.st_size),
                "modified_at": datetime.fromtimestamp(stat_result.st_mtime, tz=UTC).isoformat(),
                "action": "write_file",
            }
            await self._append_jsonl(self._hash_log_path, evidence)
            await self._audit_async("write_file", {"path": evidence["path"], "sha256": digest, "size": evidence["size"]})
            return clean_data({"ok": True, **evidence, "evidence_log": self._display_path(self._hash_log_path)})
        except OSError as exc:
            semantic = self._semantic_os_error(exc, action="write file")
            return self._error(semantic)

    async def _walk_directory(self, root: Path, max_depth: int, include_hidden: bool) -> List[FileRecord]:
        queue: List[tuple[Path, int]] = [(root, 0)]
        records: List[FileRecord] = []
        while queue:
            current, depth = queue.pop(0)
            if depth >= max_depth:
                continue
            try:
                children = await asyncio.to_thread(lambda: sorted(current.iterdir(), key=lambda item: item.name.lower()))
            except OSError:
                continue
            for child in children:
                try:
                    is_dir = await asyncio.to_thread(child.is_dir)
                    markers = self._interesting_markers(child, is_dir=is_dir)
                    if not include_hidden and child.name.startswith(".") and not markers:
                        continue
                    stat_result = await asyncio.to_thread(child.stat)
                except OSError:
                    continue
                record = FileRecord(
                    path=self._display_path(child),
                    name=self._redact_text(child.name),
                    kind="directory" if is_dir else "file",
                    depth=depth + 1,
                    size=int(stat_result.st_size),
                    permissions=stat.filemode(stat_result.st_mode),
                    modified_at=datetime.fromtimestamp(stat_result.st_mtime, tz=UTC).isoformat(),
                    interesting=markers,
                    priority=self._priority_for_markers(markers),
                )
                records.append(record)
                if is_dir:
                    queue.append((child, depth + 1))
        records.sort(key=lambda item: (item.depth, item.path))
        return records

    async def _search_walk(
        self,
        *,
        root: Path,
        pattern: str,
        max_depth: int,
        content_contains: str,
        include_hidden: bool,
        max_results: int,
    ) -> List[Dict[str, Any]]:
        queue: List[tuple[Path, int]] = [(root, 0)]
        results: List[Dict[str, Any]] = []
        query_lower = content_contains.lower()
        while queue and len(results) < max_results:
            current, depth = queue.pop(0)
            if depth > max_depth:
                continue
            try:
                children = await asyncio.to_thread(lambda: sorted(current.iterdir(), key=lambda item: item.name.lower()))
            except OSError:
                continue
            for child in children:
                if len(results) >= max_results:
                    break
                try:
                    is_dir = await asyncio.to_thread(child.is_dir)
                except OSError:
                    continue
                markers = self._interesting_markers(child, is_dir=is_dir)
                if not include_hidden and child.name.startswith(".") and not markers:
                    continue
                rel_path = self._display_path(child)
                name_match = fnmatch.fnmatch(child.name, pattern) or fnmatch.fnmatch(rel_path, pattern)
                text_match = False
                snippet = ""
                if content_contains and not is_dir:
                    snippet = await self._find_text_snippet(child, query_lower)
                    text_match = bool(snippet)
                if name_match or text_match:
                    try:
                        stat_result = await asyncio.to_thread(child.stat)
                    except OSError:
                        continue
                    results.append(
                        clean_data(
                            {
                                "path": rel_path,
                                "name": self._redact_text(child.name),
                                "kind": "directory" if is_dir else "file",
                                "depth": depth + 1,
                                "size": int(stat_result.st_size),
                                "permissions": stat.filemode(stat_result.st_mode),
                                "modified_at": datetime.fromtimestamp(stat_result.st_mtime, tz=UTC).isoformat(),
                                "interesting": markers,
                                "priority": self._priority_for_markers(markers),
                                "match_reason": "content" if text_match and not name_match else "name",
                                "snippet": clean_data(self._redact_text(snippet[:240])) if snippet else "",
                            }
                        )
                    )
                if is_dir and depth < max_depth:
                    queue.append((child, depth + 1))
        return results

    async def _find_text_snippet(self, path: Path, query_lower: str) -> str:
        if not query_lower or path.suffix.lower() not in _TEXT_EXTENSIONS:
            return ""
        if aiofiles is not None:
            try:
                async with aiofiles.open(path, "r", encoding="utf-8", errors="ignore") as handle:
                    async for line in handle:
                        if query_lower in line.lower():
                            return line.strip()
                return ""
            except Exception:
                return ""

        def _sync_scan() -> str:
            try:
                with path.open("r", encoding="utf-8", errors="ignore") as handle:
                    for line in handle:
                        if query_lower in line.lower():
                            return line.strip()
            except Exception:
                return ""
            return ""

        return await asyncio.to_thread(_sync_scan)

    async def _read_preview(self, path: Path, max_bytes: int) -> str:
        if aiofiles is not None:
            try:
                async with aiofiles.open(path, "rb") as handle:
                    raw = await handle.read(max_bytes)
                    return raw.decode("utf-8", errors="replace")
            except Exception:
                pass

        def _sync_read() -> str:
            with path.open("rb") as handle:
                return handle.read(max_bytes).decode("utf-8", errors="replace")

        return await asyncio.to_thread(_sync_read)

    async def _read_full_text(self, path: Path, limit: int) -> str:
        if aiofiles is not None:
            try:
                async with aiofiles.open(path, "rb") as handle:
                    raw = await handle.read(_MAX_SAFE_READ_SIZE)
                    return raw[:limit if len(raw) > limit else len(raw)].decode("utf-8", errors="replace") if limit < len(raw) else raw.decode("utf-8", errors="replace")
            except Exception:
                pass

        def _sync_read() -> str:
            with path.open("rb") as handle:
                raw = handle.read(_MAX_SAFE_READ_SIZE)
                return raw.decode("utf-8", errors="replace")

        return await asyncio.to_thread(_sync_read)

    async def _head_tail_summary(self, path: Path, *, file_size: int) -> Dict[str, Any]:
        if aiofiles is not None:
            try:
                async with aiofiles.open(path, "rb") as handle:
                    head = await handle.read(_HEAD_TAIL_BYTES)
                    await handle.seek(max(0, file_size - _HEAD_TAIL_BYTES))
                    tail = await handle.read(_HEAD_TAIL_BYTES)
                    return {
                        "head": clean_data(self._scrub_content(head.decode("utf-8", errors="replace"))),
                        "tail": clean_data(self._scrub_content(tail.decode("utf-8", errors="replace"))),
                    }
            except Exception:
                pass

        def _sync_summary() -> Dict[str, Any]:
            with path.open("rb") as handle:
                head = handle.read(_HEAD_TAIL_BYTES)
                handle.seek(max(0, file_size - _HEAD_TAIL_BYTES))
                tail = handle.read(_HEAD_TAIL_BYTES)
                return {
                    "head": clean_data(self._scrub_content(head.decode("utf-8", errors="replace"))),
                    "tail": clean_data(self._scrub_content(tail.decode("utf-8", errors="replace"))),
                }

        return await asyncio.to_thread(_sync_summary)

    async def _write_text(self, path: Path, content: str, encoding: str) -> None:
        if aiofiles is not None:
            try:
                async with aiofiles.open(path, "w", encoding=encoding) as handle:
                    await handle.write(content)
                return
            except Exception:
                pass

        def _sync_write() -> None:
            path.write_text(content, encoding=encoding)

        await asyncio.to_thread(_sync_write)

    async def _hash_file(self, path: Path) -> str:
        digest = hashlib.sha256()
        if aiofiles is not None:
            try:
                async with aiofiles.open(path, "rb") as handle:
                    while True:
                        chunk = await handle.read(_HASH_CHUNK_SIZE)
                        if not chunk:
                            break
                        digest.update(chunk)
                return digest.hexdigest()
            except Exception:
                pass

        def _sync_hash() -> str:
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(_HASH_CHUNK_SIZE), b""):
                    digest.update(chunk)
            return digest.hexdigest()

        return await asyncio.to_thread(_sync_hash)

    async def _append_jsonl(self, path: Path, row: Dict[str, Any]) -> None:
        payload = json.dumps(clean_data(row), ensure_ascii=True, default=str) + "\n"
        if aiofiles is not None:
            try:
                async with aiofiles.open(path, "a", encoding="utf-8") as handle:
                    await handle.write(payload)
                return
            except Exception:
                pass

        def _sync_append() -> None:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as handle:
                handle.write(payload)

        await asyncio.to_thread(_sync_append)

    def _interesting_markers(self, path: Path, *, is_dir: bool) -> List[str]:
        name = path.name.lower()
        markers: List[str] = []
        if is_dir and name == ".git":
            markers.append("git_repository")
        if name in {".env", ".env.local", ".env.production", ".npmrc", ".dockerconfigjson"}:
            markers.append("environment_secret_material")
        if name in {"id_rsa", "id_dsa", "authorized_keys", "known_hosts"}:
            markers.append("ssh_artifact")
        if path.suffix.lower() in {".pem", ".key", ".p12", ".kdbx"}:
            markers.append("credential_material")
        if name in {"docker-compose.yaml", "docker-compose.yml", "config.yaml", "config.yml"}:
            markers.append("configuration_artifact")
        if name.endswith((".conf", ".cfg", ".service", ".ini")):
            markers.append("configuration_file")
        if "backup" in name or name.endswith((".bak", ".old", ".orig")):
            markers.append("backup_artifact")
        return markers

    @staticmethod
    def _priority_for_markers(markers: Sequence[str]) -> str:
        if any(marker in markers for marker in {"environment_secret_material", "ssh_artifact", "credential_material"}):
            return "high"
        if markers:
            return "medium"
        return "normal"

    def _display_path(self, path: Path) -> str:
        try:
            rel = path.resolve().relative_to(self._workspace)
            return self._redact_text(str(rel) if str(rel) else ".")
        except ValueError:
            return self._redact_text(str(path.resolve()))

    def _redact_text(self, value: str) -> str:
        text = str(value)
        replacements = self._path_redactions()
        for raw, replacement in replacements:
            if raw:
                text = text.replace(raw, replacement)
        username_tokens = {os.getenv("USER", ""), os.getenv("LOGNAME", "")}
        for token in username_tokens:
            if token:
                text = text.replace(token, "[REDACTED_USER]")
        return text

    def _scrub_content(self, value: str) -> str:
        text = self._redact_text(value)
        for pattern, replacement in _PII_PATTERNS:
            text = pattern.sub(replacement, text)
        return clean_data(text)

    def _path_redactions(self) -> List[tuple[str, str]]:
        values = [
            (str(self._workspace), "[WORKSPACE_ROOT]"),
            (str(Path.home()), "[HOME]"),
            (os.getenv("USERPROFILE", ""), "[HOME]"),
            (os.getenv("CEREBRO_PRIVATE_ROOT", ""), "[PRIVATE_ROOT]"),
            (os.getenv("CEREBRO_AGENT_WRITE_ROOT", ""), "[PRIVATE_ROOT]"),
        ]
        return sorted([(raw, replacement) for raw, replacement in values if raw], key=lambda item: len(item[0]), reverse=True)

    def _semantic_os_error(self, exc: OSError, *, action: str) -> SemanticError:
        path = self._redact_text(str(getattr(exc, "filename", "") or ""))
        if "Boundary Violation" in str(exc):
            return SemanticError(
                code="boundary_violation",
                message="Boundary Violation: the requested path is outside the active workspace sandbox.",
                retryable=False,
                category="sandbox",
            )
        if "Sensitive file access blocked" in str(exc):
            return SemanticError(
                code="sensitive_file_blocked",
                message="Sensitive system files are blocked by PathGuard policy and cannot be read through this tool.",
                retryable=False,
                category="policy",
            )
        if isinstance(exc, PermissionError) or exc.errno in {errno.EACCES, errno.EPERM}:
            return SemanticError(
                code="permission_denied",
                message=f"The current user does not have read access to this directory or file: {path}",
                retryable=False,
                category="authorization",
            )
        if isinstance(exc, FileNotFoundError) or exc.errno == errno.ENOENT:
            return SemanticError(
                code="path_not_found",
                message=f"The requested path does not exist inside the active workspace: {path}",
                retryable=False,
                category="missing_resource",
            )
        if isinstance(exc, NotADirectoryError) or exc.errno == errno.ENOTDIR:
            return SemanticError(
                code="not_a_directory",
                message=f"The requested path is not a directory and cannot be used for {action}: {path}",
                retryable=False,
                category="validation",
            )
        if isinstance(exc, IsADirectoryError) or exc.errno == errno.EISDIR:
            return SemanticError(
                code="is_a_directory",
                message=f"The requested path is a directory. Provide a file path for {action}: {path}",
                retryable=False,
                category="validation",
            )
        return SemanticError(
            code="filesystem_error",
            message=f"Filesystem access failed during {action}: {self._redact_text(str(exc))}",
            retryable=True,
            category="os_error",
        )

    async def _audit_async(self, event: str, data: Dict[str, Any]) -> None:
        row = {
            "timestamp": datetime.now(tz=UTC).isoformat(),
            "event": event,
            "data": clean_data({key: self._redact_text(str(value)) if isinstance(value, str) else value for key, value in data.items()}),
        }
        await self._append_jsonl(self._audit_path, row)
        if self._logger is not None:
            try:
                self._logger.audit("filesystem event", actor="filesystem", data=row, tags=["filesystem", event])
            except Exception:
                pass

    def _audit(self, event: str, data: Dict[str, Any]) -> None:
        try:
            running_loop = asyncio.get_running_loop()
        except RuntimeError:
            running_loop = None

        if running_loop is self._loop:
            self._loop.create_task(self._audit_async(event, data))
            return

        future = asyncio.run_coroutine_threadsafe(self._audit_async(event, data), self._loop)
        future.result(timeout=30.0)

    @staticmethod
    def _error(semantic: SemanticError) -> Dict[str, Any]:
        return clean_data(
            {
                "ok": False,
                "error": {
                    "code": semantic.code,
                    "message": semantic.message,
                    "retryable": semantic.retryable,
                    "category": semantic.category,
                },
            }
        )


FILESYSTEM_TOOL = CerebroFilesystemTool()


def _json_result(payload: Dict[str, Any]) -> str:
    return sanitize_tool_output("filesystem", json.dumps(clean_data(payload), ensure_ascii=True, indent=2))


def _parse_args(args: str) -> Dict[str, Any]:
    tokens = shlex.split(args or "")
    parsed: Dict[str, Any] = {
        "max_depth": None,
        "pattern": None,
        "include_hidden": True,
        "interesting_only": False,
        "content_contains": "",
        "max_bytes": None,
    }
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token in {"-maxdepth", "--max-depth", "--depth"} and index + 1 < len(tokens):
            parsed["max_depth"] = tokens[index + 1]
            index += 2
            continue
        if token in {"-name", "--name", "--pattern"} and index + 1 < len(tokens):
            parsed["pattern"] = tokens[index + 1]
            index += 2
            continue
        if token in {"-i", "--interesting"}:
            parsed["interesting_only"] = True
            index += 1
            continue
        if token in {"--content", "--grep", "--contains"} and index + 1 < len(tokens):
            parsed["content_contains"] = tokens[index + 1]
            index += 2
            continue
        if token in {"-n", "--bytes", "--max-bytes"} and index + 1 < len(tokens):
            parsed["max_bytes"] = tokens[index + 1]
            index += 2
            continue
        if token in {"--no-hidden"}:
            parsed["include_hidden"] = False
            index += 1
            continue
        index += 1
    return parsed


@function_tool
def list_dir(path: str, args: str = "", ctf=None) -> str:
    _ = ctf
    parsed = _parse_args(args)
    result = FILESYSTEM_TOOL.list_directory(
        path=path,
        max_depth=int(parsed["max_depth"] or 1),
        include_hidden=bool(parsed["include_hidden"]),
        interesting_only=bool(parsed["interesting_only"]),
    )
    return _json_result(result)


@function_tool
def cat_file(file_path: str, args: str = "", ctf=None) -> str:
    _ = ctf
    parsed = _parse_args(args)
    result = FILESYSTEM_TOOL.read_file(
        file_path=file_path,
        max_bytes=int(parsed["max_bytes"] or _DEFAULT_READ_BYTES),
    )
    if not result.get("ok"):
        if result.get("mode") == "summary":
            summary = result.get("summary") or {}
            rendered = (
                f"[SUMMARY ONLY]\nhead:\n{summary.get('head', '')}\n\n"
                f"tail:\n{summary.get('tail', '')}"
            )
            return sanitize_tool_output("cat_file", rendered)
        return str((result.get("error") or {}).get("message", "Unable to read file"))
    content = str(result.get("content", ""))
    return sanitize_tool_output("cat_file", content)


@function_tool
def read_file(file_path: str, max_bytes: int = _DEFAULT_READ_BYTES) -> str:
    return _json_result(FILESYSTEM_TOOL.read_file(file_path=file_path, max_bytes=max_bytes))


@function_tool
def pwd_command(ctf=None) -> str:
    _ = ctf
    return FILESYSTEM_TOOL.pwd()


@function_tool
def find_file(file_path: str, args: str = "", ctf=None) -> str:
    _ = ctf
    parsed = _parse_args(args)
    result = FILESYSTEM_TOOL.search_files(
        path=file_path,
        pattern=str(parsed["pattern"] or "*"),
        max_depth=int(parsed["max_depth"] or 3),
        content_contains=str(parsed["content_contains"] or ""),
        include_hidden=bool(parsed["include_hidden"]),
    )
    return _json_result(result)


@function_tool
def get_file_hash(file_path: str, algorithm: str = "sha256") -> str:
    return _json_result(FILESYSTEM_TOOL.get_file_hash(file_path=file_path, algorithm=algorithm))


@function_tool
def write_file(file_path: str, content: str, encoding: str = "utf-8") -> str:
    return _json_result(FILESYSTEM_TOOL.write_file(file_path=file_path, content=content, encoding=encoding))


__all__ = [
    "SemanticError",
    "PathGuard",
    "CerebroFilesystemTool",
    "FILESYSTEM_TOOL",
    "list_dir",
    "cat_file",
    "read_file",
    "pwd_command",
    "find_file",
    "get_file_hash",
    "write_file",
]
