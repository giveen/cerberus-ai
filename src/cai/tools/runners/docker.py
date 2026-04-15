"""Hardened Docker orchestration gateway for ephemeral container execution.

This module replaces shell-based docker invocation with a Docker SDK backed
controller that can create, start, exec, collect artifacts from, and reap
short-lived containers under strict policy controls.
"""

from __future__ import annotations

import asyncio
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import queue
import shlex
import threading
import time
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
import uuid
import tarfile

from pydantic import BaseModel, Field

try:
    from cai.memory.logic import clean_data
except Exception:
    clean_data = lambda value: value  # type: ignore[misc,assignment]

try:
    from cai.repl.commands.config import CONFIG_STORE
except Exception:
    CONFIG_STORE = None  # type: ignore[assignment]

try:
    from cai.repl.ui.logging import get_cerebro_logger
except Exception:
    get_cerebro_logger = None  # type: ignore[assignment]

from cai.tools.validation import sanitize_tool_output
from cai.tools.workspace import get_project_space

try:
    import docker as docker_sdk  # type: ignore[import-not-found]
    from docker.errors import APIError, DockerException, ImageNotFound, NotFound  # type: ignore[import-not-found]
except Exception:
    docker_sdk = None  # type: ignore[assignment]

    class DockerException(Exception):
        """Fallback Docker exception when SDK is unavailable."""

    class APIError(DockerException):
        """Fallback Docker API error."""

    class ImageNotFound(APIError):
        """Fallback image-not-found error."""

    class NotFound(APIError):
        """Fallback not-found error."""


_DEFAULT_SAFE_IMAGES = [
    "kalilinux/kali-rolling:latest",
    "alpine:latest",
    "ubuntu:24.04",
    "ubuntu:latest",
    "python:3.12-slim",
]
_IMAGE_ALIASES = {
    "kali-rolling": "kalilinux/kali-rolling:latest",
    "kalilinux/kali-rolling": "kalilinux/kali-rolling:latest",
    "alpine": "alpine:latest",
    "ubuntu": "ubuntu:24.04",
    "ubuntu-minimal": "ubuntu:24.04",
}
_DEFAULT_NETWORK = "cai-internal-no-egress"
_DEFAULT_TTL_SECONDS = 900
_DEFAULT_MEM_LIMIT_MB = 512
_DEFAULT_NANO_CPUS = 500_000_000
_MAX_MEM_LIMIT_MB = 512
_MAX_NANO_CPUS = 500_000_000
_CONTAINER_TMPFS = {
    "/tmp": "rw,nosuid,nodev,noexec,size=128m",
    "/loot": "rw,nosuid,nodev,size=256m",
    "/run": "rw,nosuid,nodev,noexec,size=32m",
}
_REAPER_INTERVAL_SECONDS = 5
_ARTIFACT_PATHS = ("/loot", "/tmp")
_OUTPUT_CAPTURE_LIMIT_CHARS = max(10_000, int(os.getenv("CEREBRO_TOOL_OUTPUT_CAPTURE_LIMIT_CHARS", "120000")))
_OUTPUT_HEAD_CHARS = max(1_000, int(os.getenv("CEREBRO_TOOL_OUTPUT_HEAD_CHARS", "8000")))
_OUTPUT_TAIL_CHARS = max(1_000, int(os.getenv("CEREBRO_TOOL_OUTPUT_TAIL_CHARS", "8000")))


class ArtifactRecord(BaseModel):
    path: str
    sha256: str
    size_bytes: int
    source_dir: str
    recovered_at: str


class ContainerLifecycleReport(BaseModel):
    ok: bool
    container_id: str = ""
    image: str = ""
    status: str = ""
    internet_access: bool = False
    network_mode: str = ""
    workspace_mount: str = ""
    container_workspace: str = ""
    ttl_seconds: int = 0
    expires_at: str = ""
    command_history: List[str] = Field(default_factory=list)
    exit_status: Optional[int] = None
    artifacts: List[ArtifactRecord] = Field(default_factory=list)
    error: Optional[Dict[str, Any]] = None


class ExecResult(BaseModel):
    ok: bool
    container_id: str
    command: str
    exit_code: Optional[int]
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    streamed: bool = False
    error: Optional[Dict[str, Any]] = None


@dataclass
class _ContainerState:
    container_id: str
    image: str
    created_at: float
    ttl_seconds: int
    expires_at: float
    internet_access: bool
    network_mode: str
    workspace_mount: str
    container_workspace: str
    command_history: List[str] = field(default_factory=list)
    artifact_hashes: List[ArtifactRecord] = field(default_factory=list)
    exit_status: Optional[int] = None
    managed: bool = True


class CerebroDockerTool:
    """Docker SDK backed sandbox runner with TTL reaping and artifact recovery."""

    def __init__(self) -> None:
        self._workspace = get_project_space().ensure_initialized().resolve()
        self._artifact_root = (self._workspace / "evidence" / "containers").resolve()
        self._audit_log = (self._workspace / ".cai" / "audit" / "docker_gateway.jsonl").resolve()
        self._logger = get_cerebro_logger() if get_cerebro_logger is not None else None
        self._artifact_root.mkdir(parents=True, exist_ok=True)
        self._audit_log.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._managed: Dict[str, _ContainerState] = {}
        self._client: Any = None
        self._client_error: Optional[str] = None
        self._network_name = self._config_get("CEREBRO_DOCKER_INTERNAL_NETWORK", _DEFAULT_NETWORK) or _DEFAULT_NETWORK
        self._stop_event = threading.Event()
        self._reaper = threading.Thread(target=self._reaper_loop, name="cerebro-docker-reaper", daemon=True)
        self._reaper.start()

    @staticmethod
    def _compact_output(text: str) -> tuple[str, bool, str]:
        if len(text) <= _OUTPUT_CAPTURE_LIMIT_CHARS:
            return text, False, ""

        head = min(_OUTPUT_HEAD_CHARS, _OUTPUT_CAPTURE_LIMIT_CHARS // 2)
        tail = min(_OUTPUT_TAIL_CHARS, _OUTPUT_CAPTURE_LIMIT_CHARS - head)
        omitted = max(0, len(text) - head - tail)
        summary = f"Output truncated: omitted {omitted} chars from {len(text)} total chars."
        compact = text[:head] + "\n\n...[" + summary + "]...\n\n" + text[-tail:]
        return compact, True, summary

    def create_container(
        self,
        *,
        image: str,
        command: str = "sleep infinity",
        internet_access: bool = False,
        ttl_seconds: Optional[int] = None,
        mem_limit_mb: Optional[int] = None,
        nano_cpus: Optional[int] = None,
        read_only: bool = True,
        environment: Optional[Mapping[str, str]] = None,
    ) -> Dict[str, Any]:
        normalized = self._normalize_image(image)
        if not self._is_image_allowed(normalized):
            return self._error(
                "image_not_allowed",
                f"Image '{normalized}' is not in the safe allowlist: {', '.join(self._safe_images())}",
            )

        client, error = self._client_or_error()
        if error:
            return self._error("missing_dependency", error)

        ttl_value = self._ttl_seconds(ttl_seconds)
        mem_value = self._mem_limit_mb(mem_limit_mb)
        cpu_value = self._nano_cpus(nano_cpus)
        container_workspace = self._resolve_container_workspace()
        workspace_mount = str(self._workspace)
        try:
            network_name = "bridge" if internet_access else self._ensure_internal_network(client)
        except RuntimeError as exc:
            return self._error("network_setup_failed", str(exc))

        labels = {
            "cai.gateway": "1",
            "cai.gateway.managed": "1",
            "cai.gateway.created_at": datetime.now(tz=UTC).isoformat(),
            "cai.gateway.ttl": str(ttl_value),
            "cai.gateway.internet_access": "1" if internet_access else "0",
        }
        create_kwargs = {
            "image": normalized,
            "command": command or "sleep infinity",
            "detach": True,
            "tty": True,
            "stdin_open": True,
            "working_dir": container_workspace,
            "environment": dict(environment or {}),
            "labels": labels,
            "volumes": {workspace_mount: {"bind": container_workspace, "mode": "rw"}},
            "mem_limit": f"{mem_value}m",
            "nano_cpus": cpu_value,
            "read_only": bool(read_only),
            "tmpfs": dict(_CONTAINER_TMPFS),
            "security_opt": ["no-new-privileges:true"],
            "cap_drop": ["ALL"],
            "pids_limit": 256,
            "network": network_name,
        }

        try:
            container = client.containers.create(**create_kwargs)
        except ImageNotFound:
            return self._error("image_not_found", f"Docker image '{normalized}' is not present locally or pullable")
        except APIError as exc:
            return self._error("docker_api_error", str(exc))
        except DockerException as exc:
            return self._error("docker_error", str(exc))

        state = _ContainerState(
            container_id=str(container.id),
            image=normalized,
            created_at=time.time(),
            ttl_seconds=ttl_value,
            expires_at=time.time() + ttl_value,
            internet_access=internet_access,
            network_mode=network_name,
            workspace_mount=workspace_mount,
            container_workspace=container_workspace,
        )
        with self._lock:
            self._managed[state.container_id] = state

        self._audit(
            "container_created",
            {
                "container_id": state.container_id,
                "image": normalized,
                "network_mode": network_name,
                "internet_access": internet_access,
                "ttl_seconds": ttl_value,
                "workspace_mount": workspace_mount,
                "container_workspace": container_workspace,
                "mem_limit_mb": mem_value,
                "nano_cpus": cpu_value,
                "read_only": bool(read_only),
            },
        )
        if internet_access:
            self._audit(
                "risk_warning",
                {
                    "container_id": state.container_id,
                    "warning": "Container requested internet access and was attached to bridge network.",
                    "image": normalized,
                },
            )

        return clean_data(
            ContainerLifecycleReport(
                ok=True,
                container_id=state.container_id,
                image=normalized,
                status="created",
                internet_access=internet_access,
                network_mode=network_name,
                workspace_mount=workspace_mount,
                container_workspace=container_workspace,
                ttl_seconds=ttl_value,
                expires_at=datetime.fromtimestamp(state.expires_at, tz=UTC).isoformat(),
                command_history=[],
                exit_status=None,
                artifacts=[],
            ).model_dump()
        )

    def start_container(self, container_id: str) -> Dict[str, Any]:
        client, error = self._client_or_error()
        if error:
            return self._error("missing_dependency", error)
        container, error = self._get_container(client, container_id)
        if error:
            return self._error("container_not_found", error)
        try:
            container.start()
            container.reload()
        except APIError as exc:
            return self._error("docker_api_error", str(exc))
        except DockerException as exc:
            return self._error("docker_error", str(exc))

        state = self._state_for(str(container.id))
        self._audit(
            "container_started",
            {"container_id": container.id, "status": container.status, "image": state.image if state else ""},
        )
        return clean_data(
            ContainerLifecycleReport(
                ok=True,
                container_id=str(container.id),
                image=state.image if state else "",
                status=str(container.status),
                internet_access=state.internet_access if state else False,
                network_mode=state.network_mode if state else "",
                workspace_mount=state.workspace_mount if state else "",
                container_workspace=state.container_workspace if state else self._resolve_container_workspace(),
                ttl_seconds=state.ttl_seconds if state else 0,
                expires_at=datetime.fromtimestamp(state.expires_at, tz=UTC).isoformat() if state else "",
                command_history=list(state.command_history) if state else [],
                exit_status=state.exit_status if state else None,
                artifacts=list(state.artifact_hashes) if state else [],
            ).model_dump()
        )

    def collect_artifacts(self, container_id: str) -> Dict[str, Any]:
        client, error = self._client_or_error()
        if error:
            return self._error("missing_dependency", error)
        container, error = self._get_container(client, container_id)
        if error:
            return self._error("container_not_found", error)

        destination = (self._artifact_root / container_id[:12]).resolve()
        destination.mkdir(parents=True, exist_ok=True)
        artifacts: List[ArtifactRecord] = []
        for source_dir in _ARTIFACT_PATHS:
            try:
                bits, _stat = container.get_archive(source_dir)
            except APIError:
                continue
            except DockerException:
                continue
            extracted = self._extract_archive(bits, destination / source_dir.strip("/"), source_dir=source_dir)
            artifacts.extend(extracted)

        with self._lock:
            state = self._managed.get(container_id)
            if state is not None:
                state.artifact_hashes = artifacts

        self._audit(
            "artifacts_collected",
            {
                "container_id": container_id,
                "artifact_dir": self._display_path(destination),
                "artifact_count": len(artifacts),
                "artifact_hashes": [item.model_dump() for item in artifacts],
            },
        )
        return clean_data(
            {
                "ok": True,
                "container_id": container_id,
                "artifact_dir": self._display_path(destination),
                "artifacts": [item.model_dump() for item in artifacts],
            }
        )

    def prune_container(self, container_id: str, *, reason: str = "manual_prune") -> Dict[str, Any]:
        client, error = self._client_or_error()
        if error:
            return self._error("missing_dependency", error)
        container, error = self._get_container(client, container_id)
        if error:
            return self._error("container_not_found", error)

        artifacts_result = self.collect_artifacts(container_id)
        artifacts = [ArtifactRecord.model_validate(item) for item in artifacts_result.get("artifacts", [])] if artifacts_result.get("ok") else []

        exit_status: Optional[int] = None
        with suppress(Exception):
            container.reload()
            exit_status = container.attrs.get("State", {}).get("ExitCode")
        with suppress(Exception):
            if container.status == "running":
                container.stop(timeout=2)
        with suppress(Exception):
            container.reload()
            exit_status = container.attrs.get("State", {}).get("ExitCode")
        try:
            container.remove(force=True, v=True)
        except APIError as exc:
            return self._error("docker_api_error", str(exc))
        except DockerException as exc:
            return self._error("docker_error", str(exc))

        with self._lock:
            state = self._managed.pop(container_id, None)
            if state is not None:
                state.exit_status = exit_status
                if artifacts:
                    state.artifact_hashes = artifacts

        self._audit(
            "container_pruned",
            {
                "container_id": container_id,
                "reason": reason,
                "exit_status": exit_status,
                "command_history": list(state.command_history) if state else [],
                "artifacts": [item.model_dump() for item in artifacts],
            },
        )
        return clean_data(
            ContainerLifecycleReport(
                ok=True,
                container_id=container_id,
                image=state.image if state else "",
                status="pruned",
                internet_access=state.internet_access if state else False,
                network_mode=state.network_mode if state else "",
                workspace_mount=state.workspace_mount if state else "",
                container_workspace=state.container_workspace if state else "",
                ttl_seconds=state.ttl_seconds if state else 0,
                expires_at=datetime.fromtimestamp(state.expires_at, tz=UTC).isoformat() if state else "",
                command_history=list(state.command_history) if state else [],
                exit_status=exit_status,
                artifacts=artifacts,
            ).model_dump()
        )

    def run_command(
        self,
        *,
        command: str,
        container_id: Optional[str],
        timeout: int = 100,
        stream: bool = False,
        call_id: Optional[str] = None,
        tool_name: Optional[str] = None,
        args: Any = None,
    ) -> Dict[str, Any]:
        client, error = self._client_or_error()
        if error:
            return ExecResult(ok=False, container_id=container_id or "", command=command, exit_code=None, error={"code": "missing_dependency", "message": error}).model_dump()

        ephemeral_id: Optional[str] = None
        target_id = (container_id or "").strip()
        if not target_id:
            created = self._create_for_compat(args=args)
            if not created.get("ok"):
                return created
            target_id = str(created.get("container_id", ""))
            ephemeral_id = target_id
            started = self.start_container(target_id)
            if not started.get("ok"):
                return ExecResult(ok=False, container_id=target_id, command=command, exit_code=None, error=started.get("error")).model_dump()

        result = self._exec_sync(
            client=client,
            container_id=target_id,
            command=command,
            timeout=timeout,
            stream=stream,
            call_id=call_id,
            tool_name=tool_name,
            args=args,
        )
        if ephemeral_id:
            self.prune_container(ephemeral_id, reason="ephemeral_run_complete")
        return result

    async def run_command_async(
        self,
        *,
        command: str,
        container_id: Optional[str],
        timeout: int = 100,
        stream: bool = False,
        call_id: Optional[str] = None,
        tool_name: Optional[str] = None,
        args: Any = None,
    ) -> Dict[str, Any]:
        client, error = self._client_or_error()
        if error:
            return ExecResult(ok=False, container_id=container_id or "", command=command, exit_code=None, error={"code": "missing_dependency", "message": error}).model_dump()

        ephemeral_id: Optional[str] = None
        target_id = (container_id or "").strip()
        if not target_id:
            created = self._create_for_compat(args=args)
            if not created.get("ok"):
                return created
            target_id = str(created.get("container_id", ""))
            ephemeral_id = target_id
            started = self.start_container(target_id)
            if not started.get("ok"):
                return ExecResult(ok=False, container_id=target_id, command=command, exit_code=None, error=started.get("error")).model_dump()

        try:
            if stream:
                result = await self._exec_async_stream(
                    client=client,
                    container_id=target_id,
                    command=command,
                    timeout=timeout,
                    call_id=call_id,
                    tool_name=tool_name,
                    args=args,
                )
            else:
                result = await asyncio.to_thread(
                    self._exec_sync,
                    client=client,
                    container_id=target_id,
                    command=command,
                    timeout=timeout,
                    stream=False,
                    call_id=call_id,
                    tool_name=tool_name,
                    args=args,
                )
        finally:
            if ephemeral_id:
                await asyncio.to_thread(self.prune_container, ephemeral_id, reason="ephemeral_run_complete")
        return result

    def shutdown(self) -> None:
        self._stop_event.set()

    def _create_for_compat(self, *, args: Any) -> Dict[str, Any]:
        payload = args if isinstance(args, dict) else {}
        image = str(payload.get("image") or self._config_get("CEREBRO_DOCKER_DEFAULT_IMAGE", "alpine:latest"))
        created = self.create_container(
            image=image,
            command=str(payload.get("container_command") or "sleep infinity"),
            internet_access=bool(payload.get("internet_access", False)),
            ttl_seconds=int(payload.get("ttl_seconds") or self._ttl_seconds(None)),
            mem_limit_mb=int(payload.get("mem_limit_mb") or self._mem_limit_mb(None)),
            nano_cpus=int(payload.get("nano_cpus") or self._nano_cpus(None)),
            read_only=bool(payload.get("read_only", True)),
            environment=payload.get("environment") if isinstance(payload.get("environment"), dict) else None,
        )
        if created.get("ok"):
            return created
        return ExecResult(
            ok=False,
            container_id="",
            command=str(payload.get("command") or ""),
            exit_code=None,
            error=created.get("error"),
        ).model_dump()

    def _client_or_error(self) -> Tuple[Any, Optional[str]]:
        if docker_sdk is None:
            return None, "docker Python SDK is not installed"
        if self._client is not None:
            return self._client, None
        if self._client_error is not None:
            return None, self._client_error
        try:
            client = docker_sdk.from_env()
            client.ping()
            self._client = client
            return client, None
        except Exception as exc:
            self._client_error = str(exc)
            return None, self._client_error

    def _ensure_internal_network(self, client: Any) -> str:
        try:
            network = client.networks.get(self._network_name)
            return str(network.name)
        except NotFound:
            pass
        except DockerException:
            return self._network_name

        try:
            network = client.networks.create(
                self._network_name,
                driver="bridge",
                internal=True,
                attachable=False,
                labels={"cai.gateway": "1", "cai.gateway.network": "internal"},
            )
            self._audit("network_created", {"network": network.name, "internal": True})
            return str(network.name)
        except DockerException as exc:
            raise RuntimeError(f"Unable to create internal Docker network '{self._network_name}': {exc}") from exc

    def _get_container(self, client: Any, container_id: str) -> Tuple[Any, Optional[str]]:
        try:
            container = client.containers.get(container_id)
            return container, None
        except NotFound:
            return None, f"Container '{container_id}' not found"
        except DockerException as exc:
            return None, str(exc)

    def _exec_sync(
        self,
        *,
        client: Any,
        container_id: str,
        command: str,
        timeout: int,
        stream: bool,
        call_id: Optional[str],
        tool_name: Optional[str],
        args: Any,
    ) -> Dict[str, Any]:
        container, error = self._get_container(client, container_id)
        if error:
            return ExecResult(ok=False, container_id=container_id, command=command, exit_code=None, error={"code": "container_not_found", "message": error}).model_dump()

        try:
            container.reload()
            if container.status != "running":
                container.start()
                container.reload()
        except DockerException as exc:
            return ExecResult(ok=False, container_id=container_id, command=command, exit_code=None, error={"code": "docker_error", "message": str(exc)}).model_dump()

        self._record_command(container_id, command)
        state = self._state_for(container_id)
        workdir = state.container_workspace if state else self._resolve_container_workspace()
        self._prepare_container_paths(client=client, container_id=container_id, workdir=workdir)

        if stream:
            return self._exec_stream_sync(
                client=client,
                container_id=container_id,
                command=command,
                timeout=timeout,
                call_id=call_id,
                tool_name=tool_name,
                args=args,
            )

        try:
            exec_id = client.api.exec_create(
                container=container_id,
                cmd=["sh", "-lc", command],
                workdir=workdir,
                stdout=True,
                stderr=True,
                tty=False,
            )["Id"]
            stdout_raw, stderr_raw = client.api.exec_start(exec_id, demux=True)
            info = client.api.exec_inspect(exec_id)
        except DockerException as exc:
            return ExecResult(ok=False, container_id=container_id, command=command, exit_code=None, error={"code": "docker_exec_error", "message": str(exc)}).model_dump()

        stdout = (stdout_raw or b"").decode("utf-8", errors="replace")
        stderr = (stderr_raw or b"").decode("utf-8", errors="replace")
        exit_code = info.get("ExitCode")
        self._update_exit_status(container_id, exit_code)
        self._audit(
            "exec_completed",
            {"container_id": container_id, "command": command, "exit_code": exit_code, "streamed": False},
        )
        return ExecResult(
            ok=(exit_code or 0) == 0,
            container_id=container_id,
            command=command,
            exit_code=exit_code,
            stdout=sanitize_tool_output(command, stdout),
            stderr=sanitize_tool_output(command, stderr),
            streamed=False,
            error=None if (exit_code or 0) == 0 else {"code": "command_failed", "message": f"Container command exited with code {exit_code}"},
        ).model_dump()

    async def _exec_async_stream(
        self,
        *,
        client: Any,
        container_id: str,
        command: str,
        timeout: int,
        call_id: Optional[str],
        tool_name: Optional[str],
        args: Any,
    ) -> Dict[str, Any]:
        container, error = self._get_container(client, container_id)
        if error:
            return ExecResult(ok=False, container_id=container_id, command=command, exit_code=None, error={"code": "container_not_found", "message": error}).model_dump()

        try:
            container.reload()
            if container.status != "running":
                await asyncio.to_thread(container.start)
                await asyncio.to_thread(container.reload)
        except DockerException as exc:
            return ExecResult(ok=False, container_id=container_id, command=command, exit_code=None, error={"code": "docker_error", "message": str(exc)}).model_dump()

        self._record_command(container_id, command)
        state = self._state_for(container_id)
        workdir = state.container_workspace if state else self._resolve_container_workspace()
        await asyncio.to_thread(self._prepare_container_paths, client=client, container_id=container_id, workdir=workdir)

        try:
            exec_id = await asyncio.to_thread(
                lambda: client.api.exec_create(
                    container=container_id,
                    cmd=["sh", "-lc", command],
                    workdir=workdir,
                    stdout=True,
                    stderr=True,
                    tty=False,
                )["Id"]
            )
        except DockerException as exc:
            return ExecResult(ok=False, container_id=container_id, command=command, exit_code=None, error={"code": "docker_exec_error", "message": str(exc)}).model_dump()

        token_info = None
        start_streaming = update_streaming = finish_streaming = None
        if tool_name:
            with suppress(Exception):
                from cai.tools.agent_info import _get_agent_token_info
                from cai.util import start_tool_streaming, update_tool_streaming, finish_tool_streaming

                token_info = _get_agent_token_info()
                start_streaming = start_tool_streaming
                update_streaming = update_tool_streaming
                finish_streaming = finish_tool_streaming

        parts = command.strip().split(" ", 1)
        tool_args = args.copy() if isinstance(args, dict) else {
            "command": parts[0] if parts else command,
            "args": parts[1] if len(parts) > 1 else "",
            "full_command": command,
            "container": container_id[:12],
            "environment": "Container",
            "workspace": workdir,
        }
        stream_call_id = call_id
        if start_streaming and tool_name:
            stream_call_id = start_streaming(tool_name, tool_args, call_id, token_info)

        loop = asyncio.get_running_loop()
        buffer: "queue.Queue[Tuple[str, Optional[str]]]" = queue.Queue()
        stop_flag = threading.Event()

        def _worker() -> None:
            try:
                for item in client.api.exec_start(exec_id, stream=True, demux=True):
                    if stop_flag.is_set():
                        break
                    out_chunk, err_chunk = item if isinstance(item, tuple) else (item, None)
                    if out_chunk:
                        loop.call_soon_threadsafe(buffer.put_nowait, ("stdout", out_chunk.decode("utf-8", errors="replace")))
                    if err_chunk:
                        loop.call_soon_threadsafe(buffer.put_nowait, ("stderr", err_chunk.decode("utf-8", errors="replace")))
            except Exception as exc:
                loop.call_soon_threadsafe(buffer.put_nowait, ("error", str(exc)))
            finally:
                loop.call_soon_threadsafe(buffer.put_nowait, ("done", None))

        thread = threading.Thread(target=_worker, name=f"docker-stream-{container_id[:12]}", daemon=True)
        thread.start()

        stdout_chunks: List[str] = []
        stderr_chunks: List[str] = []
        stdout_len = 0
        stderr_len = 0
        stdout_capped = False
        stderr_capped = False
        last_update = time.time()
        deadline = time.time() + float(timeout)
        timed_out = False

        while True:
            remaining = max(0.2, deadline - time.time())
            try:
                kind, payload = await asyncio.wait_for(asyncio.to_thread(buffer.get), timeout=remaining)
            except asyncio.TimeoutError:
                timed_out = True
                stop_flag.set()
                with suppress(Exception):
                    await asyncio.to_thread(container.kill)
                stderr_chunks.append("Execution timed out; container was killed by policy.")
                break

            if kind == "done":
                break
            if kind == "error" and payload:
                stderr_chunks.append(payload)
                break
            if payload:
                if kind == "stdout":
                    if not stdout_capped:
                        remaining = _OUTPUT_CAPTURE_LIMIT_CHARS - stdout_len
                        if remaining > 0:
                            if len(payload) > remaining:
                                stdout_chunks.append(payload[:remaining])
                                stdout_len = _OUTPUT_CAPTURE_LIMIT_CHARS
                                stdout_capped = True
                                stdout_chunks.append("\n...[stdout capture capped by policy]...")
                            else:
                                stdout_chunks.append(payload)
                                stdout_len += len(payload)
                        else:
                            stdout_capped = True
                elif kind == "stderr":
                    if not stderr_capped:
                        remaining = _OUTPUT_CAPTURE_LIMIT_CHARS - stderr_len
                        if remaining > 0:
                            if len(payload) > remaining:
                                stderr_chunks.append(payload[:remaining])
                                stderr_len = _OUTPUT_CAPTURE_LIMIT_CHARS
                                stderr_capped = True
                                stderr_chunks.append("\n...[stderr capture capped by policy]...")
                            else:
                                stderr_chunks.append(payload)
                                stderr_len += len(payload)
                        else:
                            stderr_capped = True

            if update_streaming and tool_name and stream_call_id and (time.time() - last_update) >= 1.0:
                streaming_snapshot = "".join(stdout_chunks + stderr_chunks)
                if len(streaming_snapshot) > 8000:
                    streaming_snapshot = streaming_snapshot[-8000:]
                update_streaming(tool_name, tool_args, streaming_snapshot, stream_call_id, token_info)
                last_update = time.time()

        info = await asyncio.to_thread(client.api.exec_inspect, exec_id)
        exit_code = info.get("ExitCode")
        self._update_exit_status(container_id, exit_code)
        stdout_text = sanitize_tool_output(command, "".join(stdout_chunks))
        stderr_text = sanitize_tool_output(command, "".join(stderr_chunks))
        stdout_text, _stdout_truncated, stdout_summary = self._compact_output(stdout_text)
        stderr_text, _stderr_truncated, stderr_summary = self._compact_output(stderr_text)
        execution_info = {
            "status": "completed" if (exit_code or 0) == 0 and not timed_out else "error",
            "return_code": exit_code,
            "environment": "Container",
            "host": container_id[:12],
            "tool_time": 0,
        }
        final_stream_payload = (stdout_text + ("\n" + stderr_text if stderr_text else "")).strip()
        if stdout_summary or stderr_summary:
            final_stream_payload = (final_stream_payload + "\n\n" + " ".join(item for item in (stdout_summary, stderr_summary) if item)).strip()
        if finish_streaming and tool_name and stream_call_id:
            finish_streaming(tool_name, tool_args, final_stream_payload, stream_call_id, execution_info, token_info)
        self._audit(
            "exec_completed",
            {"container_id": container_id, "command": command, "exit_code": exit_code, "streamed": True, "timed_out": timed_out},
        )
        return ExecResult(
            ok=(exit_code or 0) == 0 and not timed_out,
            container_id=container_id,
            command=command,
            exit_code=exit_code,
            stdout=stdout_text,
            stderr=stderr_text,
            timed_out=timed_out,
            streamed=True,
            error=None if (exit_code or 0) == 0 and not timed_out else {"code": "command_failed" if not timed_out else "timeout", "message": f"Container command exited with code {exit_code}" if not timed_out else "Execution timed out by policy"},
        ).model_dump()

    def _exec_stream_sync(
        self,
        *,
        client: Any,
        container_id: str,
        command: str,
        timeout: int,
        call_id: Optional[str],
        tool_name: Optional[str],
        args: Any,
    ) -> Dict[str, Any]:
        state = self._state_for(container_id)
        try:
            exec_id = client.api.exec_create(
                container=container_id,
                cmd=["sh", "-lc", command],
                workdir=state.container_workspace if state else self._resolve_container_workspace(),
                stdout=True,
                stderr=True,
                tty=False,
            )["Id"]
        except DockerException as exc:
            return ExecResult(ok=False, container_id=container_id, command=command, exit_code=None, error={"code": "docker_exec_error", "message": str(exc)}).model_dump()

        token_info = None
        start_streaming = update_streaming = finish_streaming = None
        if tool_name:
            with suppress(Exception):
                from cai.tools.agent_info import _get_agent_token_info
                from cai.util import start_tool_streaming, update_tool_streaming, finish_tool_streaming

                token_info = _get_agent_token_info()
                start_streaming = start_tool_streaming
                update_streaming = update_tool_streaming
                finish_streaming = finish_tool_streaming

        parts = command.strip().split(" ", 1)
        tool_args = args.copy() if isinstance(args, dict) else {
            "command": parts[0] if parts else command,
            "args": parts[1] if len(parts) > 1 else "",
            "full_command": command,
            "container": container_id[:12],
            "environment": "Container",
            "workspace": state.container_workspace if state else self._resolve_container_workspace(),
        }
        stream_call_id = call_id
        if start_streaming and tool_name:
            stream_call_id = start_streaming(tool_name, tool_args, call_id, token_info)

        stdout_chunks: List[str] = []
        stderr_chunks: List[str] = []
        stdout_len = 0
        stderr_len = 0
        stdout_capped = False
        stderr_capped = False
        start_time = time.time()
        timed_out = False
        try:
            for item in client.api.exec_start(exec_id, stream=True, demux=True):
                out_chunk, err_chunk = item if isinstance(item, tuple) else (item, None)
                if out_chunk:
                    if not stdout_capped:
                        payload = out_chunk.decode("utf-8", errors="replace")
                        remaining = _OUTPUT_CAPTURE_LIMIT_CHARS - stdout_len
                        if remaining > 0:
                            if len(payload) > remaining:
                                stdout_chunks.append(payload[:remaining])
                                stdout_len = _OUTPUT_CAPTURE_LIMIT_CHARS
                                stdout_capped = True
                                stdout_chunks.append("\n...[stdout capture capped by policy]...")
                            else:
                                stdout_chunks.append(payload)
                                stdout_len += len(payload)
                        else:
                            stdout_capped = True
                if err_chunk:
                    if not stderr_capped:
                        payload = err_chunk.decode("utf-8", errors="replace")
                        remaining = _OUTPUT_CAPTURE_LIMIT_CHARS - stderr_len
                        if remaining > 0:
                            if len(payload) > remaining:
                                stderr_chunks.append(payload[:remaining])
                                stderr_len = _OUTPUT_CAPTURE_LIMIT_CHARS
                                stderr_capped = True
                                stderr_chunks.append("\n...[stderr capture capped by policy]...")
                            else:
                                stderr_chunks.append(payload)
                                stderr_len += len(payload)
                        else:
                            stderr_capped = True
                if update_streaming and tool_name and stream_call_id:
                    streaming_snapshot = "".join(stdout_chunks + stderr_chunks)
                    if len(streaming_snapshot) > 8000:
                        streaming_snapshot = streaming_snapshot[-8000:]
                    update_streaming(tool_name, tool_args, streaming_snapshot, stream_call_id, token_info)
                if (time.time() - start_time) > float(timeout):
                    timed_out = True
                    raise TimeoutError("Container command timed out")
        except TimeoutError:
            with suppress(Exception):
                client.containers.get(container_id).kill()
            stderr_chunks.append("Execution timed out; container was killed by policy.")
        except DockerException as exc:
            stderr_chunks.append(str(exc))

        info = client.api.exec_inspect(exec_id)
        exit_code = info.get("ExitCode")
        self._update_exit_status(container_id, exit_code)
        stdout_text = sanitize_tool_output(command, "".join(stdout_chunks))
        stderr_text = sanitize_tool_output(command, "".join(stderr_chunks))
        stdout_text, _stdout_truncated, stdout_summary = self._compact_output(stdout_text)
        stderr_text, _stderr_truncated, stderr_summary = self._compact_output(stderr_text)
        execution_info = {
            "status": "completed" if (exit_code or 0) == 0 and not timed_out else "error",
            "return_code": exit_code,
            "environment": "Container",
            "host": container_id[:12],
            "tool_time": time.time() - start_time,
        }
        final_stream_payload = (stdout_text + ("\n" + stderr_text if stderr_text else "")).strip()
        if stdout_summary or stderr_summary:
            final_stream_payload = (final_stream_payload + "\n\n" + " ".join(item for item in (stdout_summary, stderr_summary) if item)).strip()
        if finish_streaming and tool_name and stream_call_id:
            finish_streaming(tool_name, tool_args, final_stream_payload, stream_call_id, execution_info, token_info)
        self._audit(
            "exec_completed",
            {"container_id": container_id, "command": command, "exit_code": exit_code, "streamed": True, "timed_out": timed_out},
        )
        return ExecResult(
            ok=(exit_code or 0) == 0 and not timed_out,
            container_id=container_id,
            command=command,
            exit_code=exit_code,
            stdout=stdout_text,
            stderr=stderr_text,
            streamed=True,
            timed_out=timed_out,
            error=None if (exit_code or 0) == 0 and not timed_out else {"code": "command_failed" if not timed_out else "timeout", "message": f"Container command exited with code {exit_code}" if not timed_out else "Execution timed out by policy"},
        ).model_dump()

    def _prepare_container_paths(self, *, client: Any, container_id: str, workdir: str) -> None:
        with suppress(Exception):
            prep_id = client.api.exec_create(
                container=container_id,
                cmd=["sh", "-lc", f"mkdir -p {shlex.quote(workdir)} /loot /tmp"],
                workdir="/",
                stdout=False,
                stderr=False,
                tty=False,
            )["Id"]
            client.api.exec_start(prep_id, demux=True)

    def _extract_archive(self, bits: Iterable[bytes], destination: Path, *, source_dir: str) -> List[ArtifactRecord]:
        destination.mkdir(parents=True, exist_ok=True)
        buffer = io.BytesIO()
        for chunk in bits:
            buffer.write(chunk)
        buffer.seek(0)

        artifacts: List[ArtifactRecord] = []
        with tarfile.open(fileobj=buffer, mode="r:*") as archive:
            for member in archive.getmembers():
                if not member.isfile():
                    continue
                member_path = PurePosixPath(member.name.lstrip("./"))
                if member_path.is_absolute() or ".." in member_path.parts:
                    continue
                target = (destination / Path(*member_path.parts)).resolve()
                try:
                    target.relative_to(destination.resolve())
                except ValueError:
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                extracted = archive.extractfile(member)
                if extracted is None:
                    continue
                digest = hashlib.sha256()
                size = 0
                with target.open("wb") as handle:
                    while True:
                        chunk = extracted.read(65536)
                        if not chunk:
                            break
                        handle.write(chunk)
                        digest.update(chunk)
                        size += len(chunk)
                artifacts.append(
                    ArtifactRecord(
                        path=self._display_path(target),
                        sha256=digest.hexdigest(),
                        size_bytes=size,
                        source_dir=source_dir,
                        recovered_at=datetime.now(tz=UTC).isoformat(),
                    )
                )
        return artifacts

    def _record_command(self, container_id: str, command: str) -> None:
        with self._lock:
            state = self._managed.get(container_id)
            if state is not None:
                state.command_history.append(command)
                state.expires_at = time.time() + state.ttl_seconds

    def _update_exit_status(self, container_id: str, exit_code: Optional[int]) -> None:
        with self._lock:
            state = self._managed.get(container_id)
            if state is not None:
                state.exit_status = exit_code

    def _state_for(self, container_id: str) -> Optional[_ContainerState]:
        with self._lock:
            return self._managed.get(container_id)

    def _ttl_seconds(self, candidate: Optional[int]) -> int:
        raw = candidate if candidate is not None else self._config_int("CEREBRO_DOCKER_TTL_SECONDS", _DEFAULT_TTL_SECONDS)
        return max(30, int(raw or _DEFAULT_TTL_SECONDS))

    def _mem_limit_mb(self, candidate: Optional[int]) -> int:
        raw = candidate if candidate is not None else self._config_int("CEREBRO_DOCKER_MEM_LIMIT_MB", _DEFAULT_MEM_LIMIT_MB)
        return max(64, min(_MAX_MEM_LIMIT_MB, int(raw or _DEFAULT_MEM_LIMIT_MB)))

    def _nano_cpus(self, candidate: Optional[int]) -> int:
        raw = candidate if candidate is not None else self._config_int("CEREBRO_DOCKER_NANO_CPUS", _DEFAULT_NANO_CPUS)
        return max(100_000_000, min(_MAX_NANO_CPUS, int(raw or _DEFAULT_NANO_CPUS)))

    def _safe_images(self) -> List[str]:
        raw = self._config_get("CEREBRO_SAFE_DOCKER_IMAGES") or self._config_get("CEREBRO_DOCKER_SAFE_IMAGES")
        if not raw or str(raw).strip() in {"", "Not set"}:
            return list(_DEFAULT_SAFE_IMAGES)
        return [self._normalize_image(entry.strip()) for entry in str(raw).split(",") if entry.strip()]

    def _normalize_image(self, image: str) -> str:
        raw = (image or "").strip()
        if not raw:
            return ""
        alias = _IMAGE_ALIASES.get(raw.lower())
        if alias:
            return alias
        if ":" in raw or "@" in raw:
            return raw
        return f"{raw}:latest"

    def _is_image_allowed(self, image: str) -> bool:
        normalized = self._normalize_image(image)
        if not normalized:
            return False
        allowed = {self._normalize_image(item) for item in self._safe_images()}
        if normalized in allowed:
            return True
        repo = normalized.split(":", 1)[0]
        return any(repo == allowed_item.split(":", 1)[0] for allowed_item in allowed)

    def _resolve_container_workspace(self) -> str:
        try:
            return f"/workspace/workspaces/{get_project_space().session_id}"
        except Exception:
            return "/workspace/workspaces/default"

    def _display_path(self, path: Path) -> str:
        try:
            return str(path.resolve().relative_to(self._workspace))
        except ValueError:
            return str(path.resolve())

    def _config_get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        value = os.getenv(key)
        if value not in {None, ""}:
            return value
        if CONFIG_STORE is not None:
            with suppress(Exception):
                resolved = CONFIG_STORE.get(key)
                if resolved not in {None, "", "Not set"}:
                    return str(resolved)
        return default

    def _config_int(self, key: str, default: int) -> int:
        raw = self._config_get(key, str(default))
        try:
            return int(str(raw))
        except (TypeError, ValueError):
            return int(default)

    def _audit(self, event: str, data: Dict[str, Any]) -> None:
        payload = {
            "timestamp": datetime.now(tz=UTC).isoformat(),
            "event": event,
            **clean_data(data),
        }
        line = json.dumps(payload, ensure_ascii=True) + "\n"
        with self._audit_log.open("a", encoding="utf-8") as handle:
            handle.write(line)
        if self._logger is not None:
            with suppress(Exception):
                self._logger.audit("docker gateway event", actor="docker", data=payload, tags=["docker", event])

    def _error(self, code: str, message: str) -> Dict[str, Any]:
        return {"ok": False, "error": {"code": code, "message": message}}

    def _reaper_loop(self) -> None:
        while not self._stop_event.wait(_REAPER_INTERVAL_SECONDS):
            expired: List[str] = []
            now = time.time()
            with self._lock:
                for container_id, state in self._managed.items():
                    if state.managed and state.expires_at <= now:
                        expired.append(container_id)
            for container_id in expired:
                with suppress(Exception):
                    self.prune_container(container_id, reason="ttl_expired")


DOCKER_TOOL = CerebroDockerTool()


def _format_compat_output(result: Dict[str, Any]) -> str:
    if not result.get("ok"):
        error = result.get("error") or {}
        return str(error.get("message", "Docker execution failed"))

    stdout = str(result.get("stdout", "") or "").strip()
    stderr = str(result.get("stderr", "") or "").strip()
    exit_code = result.get("exit_code")
    if stdout and stderr:
        return f"{stdout}\n{stderr}".strip()
    if stdout:
        return stdout
    if stderr:
        return stderr
    if exit_code not in {None, 0}:
        return f"Command exited with code {exit_code}"
    return ""


async def run_docker_async(command, container_id=None, stdout=False, timeout=100, stream=False, call_id=None, tool_name=None, args=None):
    result = await DOCKER_TOOL.run_command_async(
        command=str(command),
        container_id=container_id,
        timeout=int(timeout),
        stream=bool(stream),
        call_id=call_id,
        tool_name=tool_name,
        args=args,
    )
    output = _format_compat_output(result)
    if stdout and output:
        container_ref = str((container_id or result.get("container_id") or "")[:12])
        print(f"(docker:{container_ref}:{DOCKER_TOOL._resolve_container_workspace()}) $ {command}\n{output}")
    return output


def run_docker(command, container_id=None, stdout=False, timeout=100, stream=False, call_id=None, tool_name=None, args=None):
    result = DOCKER_TOOL.run_command(
        command=str(command),
        container_id=container_id,
        timeout=int(timeout),
        stream=bool(stream),
        call_id=call_id,
        tool_name=tool_name,
        args=args,
    )
    output = _format_compat_output(result)
    if stdout and output:
        container_ref = str((container_id or result.get("container_id") or "")[:12])
        print(f"(docker:{container_ref}:{DOCKER_TOOL._resolve_container_workspace()}) $ {command}\n{output}")
    return output


__all__ = ["CerebroDockerTool", "DOCKER_TOOL", "run_docker", "run_docker_async"]
