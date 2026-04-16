"""Cerebro Atomic Task Runner (CATR).

High-efficiency stateless single-tool executor with strict argument validation,
subprocess isolation, structured extraction, and audit telemetry.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
import hashlib
import inspect
import json
import multiprocessing as mp
import os
from pathlib import Path
import re
import resource
import time
from typing import Any, Dict, Iterable, List, Mapping, NotRequired, Optional, Sequence, TypedDict

from dotenv import load_dotenv
from openai import AsyncOpenAI

from cerberus.agents import Agent, FunctionTool, OpenAIChatCompletionsModel, function_tool
from cerberus.tools.all_tools import get_all_tools, get_tool
from cerberus.tools.workspace import get_project_space
from cerberus.util.config import get_effective_api_base, get_effective_api_key, get_effective_model
from cerberus.util import create_system_prompt_renderer


class ResourceUsage(TypedDict):
  wall_ms: int
  cpu_user_ms: int
  cpu_sys_ms: int
  max_rss_kb: int


class AtomicTelemetry(TypedDict):
  execution_id: str
  tool_name: str
  start_time: str
  end_time: str
  exit_code: int
  retry_count: int
  resource_usage: ResourceUsage


class ExtractedFile(TypedDict):
  path: str
  sha256: str
  size: int
  preview: str


class ExtractedArtifact(TypedDict):
  matches: Dict[str, List[str]]
  files: List[ExtractedFile]


class AtomicExecutionResult(TypedDict):
  ok: bool
  tool_name: str
  params: Dict[str, Any]
  result: Any
  error: NotRequired[str]
  telemetry: AtomicTelemetry
  artifact: ExtractedArtifact


class ExtractionRequest(TypedDict, total=False):
  regex: Dict[str, str]
  output_files: List[str]
  preview_bytes: int
  max_matches_per_pattern: int


class CerebroAtomicRunner:
  """Stateless single-tool runner with deterministic validation and retry policy."""

  _FORBIDDEN_PATTERN = re.compile(r"[;&|`$><\n\r]")
  _TRANSIENT_ERRORS = (
    "timeout",
    "timed out",
    "temporarily unavailable",
    "resource busy",
    "file lock",
    "connection reset",
    "try again",
  )

  def __init__(self, *, workspace_root: Optional[str] = None) -> None:
    self.workspace_root = self._resolve_workspace(workspace_root)
    self.audit_log = (self.workspace_root / "audit" / "atomic_runner.jsonl").resolve()
    self.audit_log.parent.mkdir(parents=True, exist_ok=True)

  def execute_atomic(
    self,
    *,
    tool_name: str,
    parameters: Mapping[str, Any],
    extraction: Optional[ExtractionRequest] = None,
    retry_limit: int = 1,
    isolation_timeout_seconds: int = 45,
  ) -> AtomicExecutionResult:
    start_ts = datetime.now(tz=UTC)
    start_perf = time.perf_counter()
    execution_id = hashlib.sha256(f"{tool_name}:{start_ts.isoformat()}".encode("utf-8")).hexdigest()[:16]

    try:
      tool_callable = get_tool(tool_name)
    except Exception as exc:
      return self._build_failure(
        execution_id=execution_id,
        tool_name=tool_name,
        params=dict(parameters),
        start_ts=start_ts,
        start_perf=start_perf,
        exit_code=127,
        retry_count=0,
        message=f"Unknown or unavailable tool: {exc}",
      )

    schema = self._extract_schema(tool_callable)
    validation_error = self._validate_parameters(schema=schema, params=parameters)
    if validation_error:
      return self._build_failure(
        execution_id=execution_id,
        tool_name=tool_name,
        params=dict(parameters),
        start_ts=start_ts,
        start_perf=start_perf,
        exit_code=2,
        retry_count=0,
        message=validation_error,
      )

    try:
      sanitized = self._sanitize_mapping(dict(parameters))
    except ValueError as exc:
      return self._build_failure(
        execution_id=execution_id,
        tool_name=tool_name,
        params=dict(parameters),
        start_ts=start_ts,
        start_perf=start_perf,
        exit_code=2,
        retry_count=0,
        message=str(exc),
      )

    attempt = 0
    last_error = ""
    final_result: Any = {}
    exit_code = 1

    proc_result: Dict[str, Any] = {
      "ok": False,
      "error": "execution did not start",
      "exit_code": 1,
      "resource_usage": {"cpu_user_ms": 0, "cpu_sys_ms": 0, "max_rss_kb": 0},
    }

    while attempt <= max(0, int(retry_limit)):
      proc_result = self._run_isolated(
        tool_name=tool_name,
        params=sanitized,
        timeout_seconds=max(5, int(isolation_timeout_seconds)),
      )

      ok = bool(proc_result.get("ok", False))
      if ok:
        exit_code = 0
        final_result = proc_result.get("result")
        break

      exit_code = int(proc_result.get("exit_code", 1) or 1)
      last_error = str(proc_result.get("error", "execution failed"))
      if attempt >= max(0, int(retry_limit)):
        break
      if not self._is_transient_error(last_error):
        break
      sanitized = self._soft_retry_params(schema=schema, params=sanitized)
      attempt += 1

    artifact = self._extract_artifacts(
      raw_result=final_result if exit_code == 0 else last_error,
      extraction=extraction or {},
    )

    end_ts = datetime.now(tz=UTC)
    usage = self._resource_usage(start_perf=start_perf, worker_usage=proc_result.get("resource_usage"))
    telemetry: AtomicTelemetry = {
      "execution_id": execution_id,
      "tool_name": tool_name,
      "start_time": start_ts.isoformat(),
      "end_time": end_ts.isoformat(),
      "exit_code": exit_code,
      "retry_count": attempt,
      "resource_usage": usage,
    }
    self._write_audit(telemetry=telemetry, params=sanitized, ok=(exit_code == 0), error=last_error)

    if exit_code != 0:
      return {
        "ok": False,
        "tool_name": tool_name,
        "params": sanitized,
        "result": final_result,
        "error": last_error,
        "telemetry": telemetry,
        "artifact": artifact,
      }

    return {
      "ok": True,
      "tool_name": tool_name,
      "params": sanitized,
      "result": final_result,
      "telemetry": telemetry,
      "artifact": artifact,
    }

  def _extract_schema(self, tool_callable: Any) -> Dict[str, Any]:
    try:
      signature = inspect.signature(tool_callable)
    except (TypeError, ValueError):
      return {"required": set(), "allowed": set()}

    required: set[str] = set()
    allowed: set[str] = set()
    for name, param in signature.parameters.items():
      if param.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.VAR_POSITIONAL):
        continue
      allowed.add(name)
      if param.default is inspect._empty and param.kind in (
        inspect.Parameter.POSITIONAL_OR_KEYWORD,
        inspect.Parameter.KEYWORD_ONLY,
      ):
        required.add(name)
    return {"required": required, "allowed": allowed}

  def _validate_parameters(self, *, schema: Mapping[str, Any], params: Mapping[str, Any]) -> str:
    required: set[str] = set(schema.get("required") or set())
    allowed: set[str] = set(schema.get("allowed") or set())

    missing = sorted(name for name in required if name not in params)
    if missing:
      return f"Missing required parameters: {', '.join(missing)}"

    if allowed:
      unknown = sorted(name for name in params if name not in allowed)
      if unknown:
        return f"Unknown parameters: {', '.join(unknown)}"
    return ""

  def _sanitize_mapping(self, params: Mapping[str, Any]) -> Dict[str, Any]:
    sanitized: Dict[str, Any] = {}
    for key, value in params.items():
      if not re.fullmatch(r"[A-Za-z0-9_\-]{1,64}", str(key)):
        raise ValueError(f"Invalid parameter key: {key}")
      sanitized[str(key)] = self._sanitize_value(value)
    return sanitized

  def _sanitize_value(self, value: Any) -> Any:
    if isinstance(value, str):
      if self._FORBIDDEN_PATTERN.search(value):
        raise ValueError("Unsafe characters detected in parameter value")
      return value.strip()
    if isinstance(value, Mapping):
      return {str(k): self._sanitize_value(v) for k, v in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray, str)):
      return [self._sanitize_value(item) for item in value]
    return value

  def _run_isolated(self, *, tool_name: str, params: Dict[str, Any], timeout_seconds: int) -> Dict[str, Any]:
    queue: mp.Queue[Dict[str, Any]] = mp.get_context("spawn").Queue(maxsize=1)
    proc = mp.get_context("spawn").Process(
      target=_atomic_worker,
      args=(tool_name, params, queue),
      daemon=True,
    )
    proc.start()
    proc.join(timeout=max(1, int(timeout_seconds)))
    if proc.is_alive():
      proc.terminate()
      proc.join(timeout=2)
      return {
        "ok": False,
        "error": "Worker timeout",
        "exit_code": 124,
        "resource_usage": {"cpu_user_ms": 0, "cpu_sys_ms": 0, "max_rss_kb": 0},
      }

    if proc.exitcode not in (0, None):
      return {
        "ok": False,
        "error": f"Worker exited with code {proc.exitcode}",
        "exit_code": int(proc.exitcode or 1),
        "resource_usage": {"cpu_user_ms": 0, "cpu_sys_ms": 0, "max_rss_kb": 0},
      }

    if queue.empty():
      return {
        "ok": False,
        "error": "Worker returned no payload",
        "exit_code": 1,
        "resource_usage": {"cpu_user_ms": 0, "cpu_sys_ms": 0, "max_rss_kb": 0},
      }
    return dict(queue.get_nowait())

  @staticmethod
  def _is_transient_error(message: str) -> bool:
    low = message.lower()
    return any(marker in low for marker in CerebroAtomicRunner._TRANSIENT_ERRORS)

  def _soft_retry_params(self, *, schema: Mapping[str, Any], params: Dict[str, Any]) -> Dict[str, Any]:
    allowed = set(schema.get("allowed") or set())
    patched = dict(params)

    for key in ("timeout", "timeout_seconds", "connect_timeout", "read_timeout"):
      if key in patched and isinstance(patched[key], (int, float)):
        patched[key] = min(int(patched[key] * 1.5) + 2, 300)
        return patched
    for key in ("timeout", "timeout_seconds"):
      if not allowed or key in allowed:
        patched[key] = 30
        return patched
    return patched

  def _extract_artifacts(self, *, raw_result: Any, extraction: ExtractionRequest) -> ExtractedArtifact:
    matches: Dict[str, List[str]] = {}
    files: List[ExtractedFile] = []

    text = self._normalize_result_text(raw_result)
    regex_map = dict(extraction.get("regex") or {})
    max_hits = max(1, int(extraction.get("max_matches_per_pattern", 10) or 10))
    for label, pattern in regex_map.items():
      try:
        found = re.findall(pattern, text, flags=re.MULTILINE)
      except re.error:
        found = []
      if found:
        normalized: List[str] = []
        for item in found[:max_hits]:
          if isinstance(item, tuple):
            normalized.append("".join(str(x) for x in item))
          else:
            normalized.append(str(item))
        matches[label] = normalized

    preview_bytes = max(64, min(8192, int(extraction.get("preview_bytes", 2048) or 2048)))
    for file_path in list(extraction.get("output_files") or [])[:20]:
      extracted = self._extract_file(file_path=file_path, preview_bytes=preview_bytes)
      if extracted is not None:
        files.append(extracted)

    return {"matches": matches, "files": files}

  def _extract_file(self, *, file_path: str, preview_bytes: int) -> Optional[ExtractedFile]:
    path = Path(file_path).expanduser()
    if not path.is_absolute():
      path = (self.workspace_root / path).resolve()
    else:
      path = path.resolve()

    if not str(path).startswith(str(self.workspace_root)):
      return None
    if not path.exists() or not path.is_file():
      return None

    data = path.read_bytes()
    preview = data[:preview_bytes].decode("utf-8", errors="replace")
    return {
      "path": str(path),
      "sha256": hashlib.sha256(data).hexdigest(),
      "size": len(data),
      "preview": preview,
    }

  @staticmethod
  def _normalize_result_text(raw_result: Any) -> str:
    if raw_result is None:
      return ""
    if isinstance(raw_result, str):
      return raw_result
    if isinstance(raw_result, Mapping):
      parts: List[str] = []
      for key in ("output", "stdout", "result", "message", "error"):
        if key in raw_result:
          parts.append(str(raw_result.get(key, "")))
      if parts:
        return "\n".join(parts)
      return json.dumps(raw_result, ensure_ascii=True)
    return str(raw_result)

  def _resource_usage(self, *, start_perf: float, worker_usage: Optional[Mapping[str, Any]]) -> ResourceUsage:
    return {
      "wall_ms": int((time.perf_counter() - start_perf) * 1000),
      "cpu_user_ms": int(float((worker_usage or {}).get("cpu_user_ms", 0))),
      "cpu_sys_ms": int(float((worker_usage or {}).get("cpu_sys_ms", 0))),
      "max_rss_kb": int(float((worker_usage or {}).get("max_rss_kb", 0))),
    }

  def _write_audit(self, *, telemetry: AtomicTelemetry, params: Mapping[str, Any], ok: bool, error: str) -> None:
    row = {
      "timestamp": datetime.now(tz=UTC).isoformat(),
      "ok": bool(ok),
      "telemetry": telemetry,
      "params": params,
      "error": error,
    }
    with self.audit_log.open("a", encoding="utf-8") as handle:
      handle.write(json.dumps(row, ensure_ascii=True) + "\n")

  def _build_failure(
    self,
    *,
    execution_id: str,
    tool_name: str,
    params: Dict[str, Any],
    start_ts: datetime,
    start_perf: float,
    exit_code: int,
    retry_count: int,
    message: str,
  ) -> AtomicExecutionResult:
    end_ts = datetime.now(tz=UTC)
    telemetry: AtomicTelemetry = {
      "execution_id": execution_id,
      "tool_name": tool_name,
      "start_time": start_ts.isoformat(),
      "end_time": end_ts.isoformat(),
      "exit_code": int(exit_code),
      "retry_count": int(retry_count),
      "resource_usage": {
        "wall_ms": int((time.perf_counter() - start_perf) * 1000),
        "cpu_user_ms": 0,
        "cpu_sys_ms": 0,
        "max_rss_kb": 0,
      },
    }
    artifact: ExtractedArtifact = {"matches": {}, "files": []}
    self._write_audit(telemetry=telemetry, params=params, ok=False, error=message)
    return {
      "ok": False,
      "tool_name": tool_name,
      "params": params,
      "result": {},
      "error": message,
      "telemetry": telemetry,
      "artifact": artifact,
    }

  @staticmethod
  def _resolve_workspace(workspace_root: Optional[str]) -> Path:
    if workspace_root:
      return Path(workspace_root).expanduser().resolve()
    try:
      return get_project_space().ensure_initialized().resolve()
    except Exception:
      return Path.cwd().resolve()


def _atomic_worker(tool_name: str, params: Dict[str, Any], queue: mp.Queue[Dict[str, Any]]) -> None:
  start = time.perf_counter()
  try:
    # Lightweight resource caps protect host stability when tools misbehave.
    resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
    mem_limit = 1024 * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_AS, (mem_limit, mem_limit))
  except Exception:
    pass

  try:
    tool_callable = get_tool(tool_name)
    result = _invoke_tool(tool_callable, params)
    usage = resource.getrusage(resource.RUSAGE_SELF)
    queue.put(
      {
        "ok": True,
        "result": result,
        "exit_code": 0,
        "resource_usage": {
          "cpu_user_ms": int(usage.ru_utime * 1000),
          "cpu_sys_ms": int(usage.ru_stime * 1000),
          "max_rss_kb": int(usage.ru_maxrss),
          "worker_wall_ms": int((time.perf_counter() - start) * 1000),
        },
      }
    )
  except Exception as exc:
    usage = resource.getrusage(resource.RUSAGE_SELF)
    queue.put(
      {
        "ok": False,
        "error": str(exc),
        "exit_code": 1,
        "resource_usage": {
          "cpu_user_ms": int(usage.ru_utime * 1000),
          "cpu_sys_ms": int(usage.ru_stime * 1000),
          "max_rss_kb": int(usage.ru_maxrss),
          "worker_wall_ms": int((time.perf_counter() - start) * 1000),
        },
      }
    )


def _invoke_tool(tool_callable: Any, params: Dict[str, Any]) -> Any:
  if inspect.iscoroutinefunction(tool_callable):
    return asyncio.run(tool_callable(**params))
  result = tool_callable(**params)
  if inspect.isawaitable(result):
    return asyncio.run(_await_any(result))
  return result


async def _await_any(awaitable: Any) -> Any:
  return await awaitable


load_dotenv()
_one_tool_prompt = """You are a Cybersecurity expert Leader facing a CTF challenge.

INSTRUCTIONS:
1. Execute the generic_linux_command tool without any explanation.
2. Never assume the flag format; it could be any string.
3. Use generic_linux_command for system-level operations such as nmap, curl, grep, and shell session management.
4. When you have a candidate flag, verify it before presenting it.

## generic_linux_command usage
- To start a new session: use generic_linux_command with commands like ssh.
- To list active sessions: generic_linux_command("session", "list")
- To get session output: generic_linux_command("session", "output <session_id>")
- To send input to a session: generic_linux_command("<command>", "<args>", session_id="<session_id>")
- To terminate a session: generic_linux_command("session", "kill <session_id>")
"""


def _normalize_agent_tool(tool_name: str, tool_obj: Any, description: str) -> Any:
  """Ensure the one-tool runtime agent exposes SDK FunctionTool objects."""
  if isinstance(tool_obj, FunctionTool):
    return tool_obj
  if callable(tool_obj):
    return function_tool(
      name_override=tool_name,
      description_override=description or str(getattr(tool_obj, "__doc__", "") or ""),
    )(tool_obj)
  return tool_obj

_tools = []
for _meta in get_all_tools():
  if not getattr(_meta, "enabled", False):
    continue
  try:
    _tools.append(_normalize_agent_tool(_meta.name, get_tool(_meta.name), getattr(_meta, "description", "")))
  except Exception:
    continue


def _build_one_tool_agent() -> Agent:
  return Agent(
    name="CTF agent",
    description="Agent focused on conquering security challenges using generic linux commands.",
    instructions=create_system_prompt_renderer(_one_tool_prompt),
    tools=_tools,
    model=OpenAIChatCompletionsModel(
      model=get_effective_model(),
      openai_client=AsyncOpenAI(
        api_key=get_effective_api_key(),
        base_url=get_effective_api_base(),
      ),
      agent_name="CTF agent",
      agent_type="one_tool_agent",
    ),
  )


one_tool_agent = _build_one_tool_agent()


cerebro_atomic_runner = CerebroAtomicRunner()


def transfer_to_one_tool_agent(**kwargs: Any) -> Agent:
  _ = kwargs
  return _build_one_tool_agent()


__all__ = [
  "ResourceUsage",
  "AtomicTelemetry",
  "ExtractedFile",
  "ExtractedArtifact",
  "AtomicExecutionResult",
  "ExtractionRequest",
  "CerebroAtomicRunner",
  "cerebro_atomic_runner",
  "one_tool_agent",
  "transfer_to_one_tool_agent",
]
