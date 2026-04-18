"""MCP command module for Cerebro REPL.

This module provides a modern, framework-native MCP integration with:
- async server lifecycle orchestration (connect/list/disconnect)
- tool bridging into a process-wide MCP tool registry
- security gatekeeper checks for every MCP tool invocation
- MCP resource context injection into MemoryManager
"""

from __future__ import annotations

import asyncio
import concurrent.futures
from dataclasses import dataclass, field
from datetime import UTC, datetime
import json
import logging
import os
from pathlib import Path
import re
import threading
from typing import Any, Awaitable, Dict, List, Mapping, MutableMapping, Optional, Sequence, Set, Tuple, cast

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from cerberus.agents import get_available_agents
from cerberus.config import get_settings
from cerberus.memory import MemoryManager
from cerberus.mcp_bootstrap import ManagedMCPServerSettings, prepare_managed_mcp_server, resolve_managed_mcp_endpoint, resolve_mcp_bootstrap_root
from cerberus.repl.commands.base import FrameworkCommand, register_command
from cerberus.agents.tool import FunctionTool
from cerberus.tools.workspace import get_project_space


console = Console()
_log = logging.getLogger(__name__)


# Optional backend: existing Cerebro MCP wrappers (if available in runtime environment).
try:
    from cerberus.agents.mcp import MCPServerSse, MCPServerStdio
except Exception:  # pragma: no cover - optional runtime dependency
    MCPServerSse = None
    MCPServerStdio = None


_JSON_OBJECT = Dict[str, Any]

# Legacy compatibility registries still referenced by tests and a few runtime paths.
_GLOBAL_MCP_SERVERS: Dict[str, Any] = {}
_AGENT_MCP_ASSOCIATIONS: Dict[str, List[str]] = {}


def _utc_now() -> str:
    return datetime.now(tz=UTC).isoformat()


@dataclass(frozen=True)
class MCPToolMeta:
    """Normalized MCP tool metadata for local registration."""

    alias: str
    name: str
    description: str
    schema: _JSON_OBJECT = field(default_factory=dict)


@dataclass(frozen=True)
class MCPResourceMeta:
    """Normalized MCP resource metadata."""

    alias: str
    uri: str
    name: str
    description: str


@dataclass
class MCPConnection:
    """Runtime MCP connection state."""

    alias: str
    transport: str
    endpoint: str
    server: Any
    tools: List[MCPToolMeta] = field(default_factory=list)
    resources: List[MCPResourceMeta] = field(default_factory=list)
    connected_at: str = field(default_factory=_utc_now)


@dataclass(frozen=True)
class GatekeeperDecision:
    """Result of a gatekeeper policy evaluation."""

    allowed: bool
    reason: str


class Gatekeeper:
    """Security policy evaluator for MCP tool/resource access."""

    _SHELL_META = re.compile(r"[;&|`$<>]")

    def __init__(self, workspace_root: Path) -> None:
        self._workspace_root = workspace_root.resolve()
        blocked = os.getenv("CERBERUS_MCP_BLOCKED_TOOLS", "")
        self._blocked_tools: Set[str] = {
            item.strip().lower() for item in blocked.split(",") if item.strip()
        }

    def check_tool_call(self, *, alias: str, tool_name: str, payload: Mapping[str, Any]) -> GatekeeperDecision:
        name_l = tool_name.lower().strip()
        if name_l in self._blocked_tools:
            return GatekeeperDecision(False, f"Tool '{tool_name}' blocked by policy")

        path_decision = self._validate_pathlike_fields(payload)
        if not path_decision.allowed:
            return path_decision

        command_decision = self._validate_commandlike_fields(payload)
        if not command_decision.allowed:
            return command_decision

        return GatekeeperDecision(True, f"Allowed for alias '{alias}'")

    def check_resource_uri(self, resource_uri: str) -> GatekeeperDecision:
        if resource_uri.startswith("file://"):
            maybe_path = Path(resource_uri.replace("file://", "", 1))
            if not self._is_path_within_workspace(maybe_path):
                return GatekeeperDecision(False, "Resource path escapes workspace boundary")

        if resource_uri.startswith("/") or resource_uri.startswith("./"):
            maybe_path = Path(resource_uri)
            if not self._is_path_within_workspace(maybe_path):
                return GatekeeperDecision(False, "Resource path escapes workspace boundary")

        return GatekeeperDecision(True, "Resource URI accepted")

    def _validate_commandlike_fields(self, payload: Mapping[str, Any]) -> GatekeeperDecision:
        command_keys = {"cmd", "command", "shell", "script", "exec"}
        for key, value in payload.items():
            if key.lower() not in command_keys:
                continue
            if isinstance(value, str) and self._SHELL_META.search(value):
                return GatekeeperDecision(False, f"Command field '{key}' contains disallowed shell metacharacters")
        return GatekeeperDecision(True, "No command policy violations")

    def _validate_pathlike_fields(self, payload: Mapping[str, Any]) -> GatekeeperDecision:
        path_keys = {
            "path",
            "file",
            "filepath",
            "directory",
            "cwd",
            "output_path",
            "target_path",
            "filename",
        }
        for key, value in payload.items():
            if key.lower() not in path_keys:
                continue
            if not isinstance(value, str):
                continue
            if value.startswith("http://") or value.startswith("https://"):
                continue
            if not self._is_path_within_workspace(Path(value)):
                return GatekeeperDecision(False, f"Path field '{key}' escapes workspace boundary")
        return GatekeeperDecision(True, "No path policy violations")

    def _is_path_within_workspace(self, value: Path) -> bool:
        candidate = value.expanduser()
        if not candidate.is_absolute():
            candidate = self._workspace_root / candidate
        try:
            candidate.resolve().relative_to(self._workspace_root)
            return True
        except Exception:
            return False


class MCPManager:
    """Async MCP orchestrator for server lifecycle, tool bridge, and context injection."""

    def __init__(self, *, memory: MemoryManager, workspace_root: Path) -> None:
        self._memory = memory
        self._workspace_root = workspace_root.resolve()
        self._gatekeeper = Gatekeeper(self._workspace_root)
        self._connections: Dict[str, MCPConnection] = {}
        self._tool_registry: Dict[str, FunctionTool] = {}
        self._audit_file = self._workspace_root / ".cerberus" / "audit" / "mcp_actions.jsonl"

    @property
    def connections(self) -> Mapping[str, MCPConnection]:
        return self._connections

    @property
    def tool_registry(self) -> Mapping[str, FunctionTool]:
        return self._tool_registry

    async def connect(
        self,
        *,
        alias: str,
        endpoint: str,
        headers: Optional[Mapping[str, str]] = None,
        associate_agents: Optional[Sequence[str]] = None,
    ) -> MCPConnection:
        if alias in self._connections:
            raise ValueError(f"Alias '{alias}' is already connected")

        server, transport = await self._create_server(endpoint=endpoint, alias=alias, headers=headers)

        try:
            await self._safe_connect(server)
            tools_raw = await self._safe_list_tools(server)
            resources_raw = await self._safe_list_resources(server)
        except Exception:
            await self._safe_cleanup(server)
            raise

        tools = self._normalize_tools(alias=alias, raw_tools=tools_raw)
        resources = self._normalize_resources(alias=alias, raw_resources=resources_raw)

        conn = MCPConnection(
            alias=alias,
            transport=transport,
            endpoint=endpoint,
            server=server,
            tools=tools,
            resources=resources,
        )
        self._connections[alias] = conn
        _GLOBAL_MCP_SERVERS[alias] = server

        self._register_connection_tools(conn)
        self._auto_attach_tools_to_agents(conn, associate_agents=associate_agents)
        associate_mcp_server_with_agents(alias, associate_agents)

        self._audit("connect", {"alias": alias, "transport": transport, "endpoint": endpoint, "tools": len(tools)})
        return conn

    async def disconnect(self, alias: str) -> bool:
        conn = self._connections.get(alias)
        if conn is None:
            return False

        await self._safe_cleanup(conn.server)
        self._connections.pop(alias, None)
        _GLOBAL_MCP_SERVERS.pop(alias, None)

        # Remove bridged tools for this alias from registry and existing agents.
        prefix = f"mcp::{alias}::"
        to_drop = [name for name in self._tool_registry.keys() if name.startswith(prefix)]
        for name in to_drop:
            self._tool_registry.pop(name, None)

        remove_mcp_server_from_all_agents(alias)

        for agent in _safe_get_available_agents().values():
            tools = getattr(agent, "tools", None)
            if not isinstance(tools, list):
                continue
            agent.tools = [tool for tool in tools if getattr(tool, "name", "").startswith(prefix) is False]

        self._audit("disconnect", {"alias": alias, "removed_tools": len(to_drop)})
        return True

    async def refresh_inventory(self, alias: str) -> Tuple[List[MCPToolMeta], List[MCPResourceMeta]]:
        conn = self._require_connection(alias)
        tools_raw = await self._safe_list_tools(conn.server)
        resources_raw = await self._safe_list_resources(conn.server)
        conn.tools = self._normalize_tools(alias=alias, raw_tools=tools_raw)
        conn.resources = self._normalize_resources(alias=alias, raw_resources=resources_raw)
        self._register_connection_tools(conn)
        self._auto_attach_tools_to_agents(conn, associate_agents=get_agents_for_mcp_server(alias) or None)
        return conn.tools, conn.resources

    async def inject_resource_context(
        self,
        *,
        alias: str,
        resource_uri: str,
        topic: str,
        target_agent: Optional[str] = None,
    ) -> str:
        conn = self._require_connection(alias)

        resource_check = self._gatekeeper.check_resource_uri(resource_uri)
        if not resource_check.allowed:
            raise PermissionError(resource_check.reason)

        content = await self._read_resource(conn.server, resource_uri)
        payload = {
            "topic": topic,
            "finding": f"MCP resource context injected from {alias}:{resource_uri}",
            "source": "mcp.resource",
            "tags": ["mcp", "context", alias],
            "artifacts": {
                "alias": alias,
                "resource_uri": resource_uri,
                "content_preview": content[:1200],
                "target_agent": target_agent,
            },
        }
        self._memory.record(payload)
        self._audit("inject_context", {"alias": alias, "resource_uri": resource_uri, "topic": topic})
        return content

    async def call_tool(self, *, alias: str, tool_name: str, arguments: Mapping[str, Any]) -> Any:
        conn = self._require_connection(alias)

        decision = self._gatekeeper.check_tool_call(alias=alias, tool_name=tool_name, payload=arguments)
        if not decision.allowed:
            self._audit(
                "tool_call_denied",
                {"alias": alias, "tool": tool_name, "reason": decision.reason, "args_keys": sorted(arguments.keys())},
            )
            raise PermissionError(decision.reason)

        result = await self._invoke_tool(conn.server, tool_name, dict(arguments))
        self._audit("tool_call", {"alias": alias, "tool": tool_name, "allowed": True})
        return result

    async def _create_server(
        self,
        *,
        endpoint: str,
        alias: str,
        headers: Optional[Mapping[str, str]],
    ) -> Tuple[Any, str]:
        if MCPServerSse is None or MCPServerStdio is None:
            raise RuntimeError(
                "MCP backend is unavailable. Install Cerebro MCP dependencies before using /mcp."
            )

        endpoint = endpoint.strip()
        if endpoint.startswith("stdio:"):
            command_spec = endpoint.replace("stdio:", "", 1).strip()
            if not command_spec:
                raise ValueError("stdio endpoint requires a command, e.g. stdio:python server.py")
            parts = command_spec.split()
            command = parts[0]
            args = parts[1:]
            server = MCPServerStdio({"command": command, "args": args}, name=alias, cache_tools_list=True)
            return server, "stdio"

        if endpoint.startswith("http://") or endpoint.startswith("https://"):
            params: Dict[str, Any] = {
                "url": endpoint,
                "timeout": 10,
                "sse_read_timeout": 300,
            }
            if headers:
                params["headers"] = dict(headers)
            server = MCPServerSse(cast(Any, params), name=alias, cache_tools_list=True)
            return server, "sse"

        # Treat plain shell command as stdio for convenience.
        parts = endpoint.split()
        if not parts:
            raise ValueError("Invalid endpoint")
        server = MCPServerStdio({"command": parts[0], "args": parts[1:]}, name=alias, cache_tools_list=True)
        return server, "stdio"

    async def _safe_connect(self, server: Any) -> None:
        try:
            await server.connect()
        except TimeoutError as exc:
            raise TimeoutError("MCP server connection timed out") from exc
        except Exception as exc:
            raise RuntimeError(f"Failed to connect MCP server: {exc}") from exc

    async def _safe_list_tools(self, server: Any) -> Sequence[Any]:
        try:
            return await server.list_tools()
        except TimeoutError as exc:
            raise TimeoutError("MCP list_tools timed out") from exc
        except Exception as exc:
            raise RuntimeError(f"Malformed/failed MCP tools response: {exc}") from exc

    async def _safe_list_resources(self, server: Any) -> Sequence[Any]:
        if not hasattr(server, "list_resources"):
            return []
        try:
            return await server.list_resources()
        except Exception:
            return []

    async def _safe_cleanup(self, server: Any) -> None:
        try:
            await server.cleanup()
        except Exception:
            pass

    async def _invoke_tool(self, server: Any, tool_name: str, arguments: MutableMapping[str, Any]) -> Any:
        if hasattr(server, "call_tool"):
            return await server.call_tool(tool_name, arguments)
        raise RuntimeError("MCP backend does not support tool invocation")

    async def _read_resource(self, server: Any, resource_uri: str) -> str:
        if hasattr(server, "read_resource"):
            result = await server.read_resource(resource_uri)
            return self._extract_resource_text(result)

        if hasattr(server, "get_resource"):
            result = await server.get_resource(resource_uri)
            return self._extract_resource_text(result)

        raise RuntimeError("MCP backend does not expose resource read operations")

    @staticmethod
    def _extract_resource_text(result: Any) -> str:
        if result is None:
            return ""
        if isinstance(result, str):
            return result
        if isinstance(result, Mapping):
            if isinstance(result.get("text"), str):
                return result["text"]
            return json.dumps(dict(result), ensure_ascii=False)

        content = getattr(result, "content", None)
        if isinstance(content, list) and content:
            first = content[0]
            text = getattr(first, "text", None)
            if isinstance(text, str):
                return text
            try:
                if hasattr(first, "model_dump"):
                    return json.dumps(first.model_dump(), ensure_ascii=False)
            except Exception:
                pass
        return str(result)

    def _normalize_tools(self, *, alias: str, raw_tools: Sequence[Any]) -> List[MCPToolMeta]:
        normalized: List[MCPToolMeta] = []
        for tool in raw_tools:
            name = str(getattr(tool, "name", "")).strip()
            if not name:
                continue
            description = str(getattr(tool, "description", "") or "")
            schema = getattr(tool, "inputSchema", None)
            if not isinstance(schema, dict):
                schema = {}
            normalized.append(MCPToolMeta(alias=alias, name=name, description=description, schema=schema))
        return normalized

    def _normalize_resources(self, *, alias: str, raw_resources: Sequence[Any]) -> List[MCPResourceMeta]:
        normalized: List[MCPResourceMeta] = []
        for resource in raw_resources:
            uri = str(getattr(resource, "uri", "")).strip()
            if not uri:
                continue
            name = str(getattr(resource, "name", uri))
            description = str(getattr(resource, "description", "") or "")
            normalized.append(MCPResourceMeta(alias=alias, uri=uri, name=name, description=description))
        return normalized

    def _register_connection_tools(self, conn: MCPConnection) -> None:
        for tool_meta in conn.tools:
            fq_name = f"mcp::{conn.alias}::{tool_meta.name}"
            self._tool_registry[fq_name] = self._build_function_tool(conn.alias, tool_meta)

    def _auto_attach_tools_to_agents(
        self,
        conn: MCPConnection,
        *,
        associate_agents: Optional[Sequence[str]] = None,
    ) -> None:
        mcp_tools = [self._tool_registry[f"mcp::{conn.alias}::{tool.name}"] for tool in conn.tools]
        if not mcp_tools:
            return

        for agent in _iter_current_target_agents(associate_agents).values():
            existing = getattr(agent, "tools", None)
            if not isinstance(existing, list):
                continue
            existing_names = {getattr(t, "name", "") for t in existing}
            for tool in mcp_tools:
                if tool.name not in existing_names:
                    existing.append(tool)

    def _build_function_tool(self, alias: str, tool_meta: MCPToolMeta) -> FunctionTool:
        async def _invoke(_ctx: Any, input_json: str) -> Any:
            payload: Dict[str, Any]
            if input_json.strip():
                try:
                    decoded = json.loads(input_json)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"Invalid JSON input for {tool_meta.name}: {exc}") from exc
                if not isinstance(decoded, dict):
                    raise ValueError("MCP tool payload must be a JSON object")
                payload = decoded
            else:
                payload = {}

            result = await self.call_tool(alias=alias, tool_name=tool_meta.name, arguments=payload)

            if isinstance(result, str):
                return result
            if hasattr(result, "content"):
                try:
                    content = getattr(result, "content")
                    if isinstance(content, list):
                        return json.dumps([getattr(c, "model_dump", lambda: str(c))() for c in content])
                except Exception:
                    pass
            try:
                return json.dumps(result, default=str)
            except Exception:
                return str(result)

        return FunctionTool(
            name=f"mcp::{alias}::{tool_meta.name}",
            description=tool_meta.description or f"MCP tool {tool_meta.name} from {alias}",
            params_json_schema=tool_meta.schema,
            on_invoke_tool=_invoke,
            strict_json_schema=False,
        )

    def _require_connection(self, alias: str) -> MCPConnection:
        conn = self._connections.get(alias)
        if conn is None:
            raise KeyError(f"MCP alias '{alias}' is not connected")
        return conn

    def _audit(self, action: str, details: Mapping[str, Any]) -> None:
        payload = {
            "timestamp": _utc_now(),
            "action": action,
            "details": dict(details),
        }
        try:
            self._audit_file.parent.mkdir(parents=True, exist_ok=True)
            with self._audit_file.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(payload, ensure_ascii=False) + "\n")
        except Exception as exc:
            _log.debug("MCP audit write failed: %s", exc)


_GLOBAL_MCP_MANAGER: Optional[MCPManager] = None
_MCP_AUTOLOAD_LOCK = threading.RLock()
_MCP_AUTOLOAD_ATTEMPTED = False
_MCP_AUTOLOAD_STATUS: List[Dict[str, Any]] = []


def get_mcp_manager(memory: Optional[MemoryManager] = None, *, bootstrap: bool = True) -> MCPManager:
    global _GLOBAL_MCP_MANAGER
    if _GLOBAL_MCP_MANAGER is None:
        mem = memory or MemoryManager()
        workspace_root = get_project_space().ensure_initialized().resolve()
        _GLOBAL_MCP_MANAGER = MCPManager(memory=mem, workspace_root=workspace_root)
    if bootstrap:
        ensure_configured_mcp_servers(manager=_GLOBAL_MCP_MANAGER)
    return _GLOBAL_MCP_MANAGER


def _run_awaitable_sync(awaitable: Awaitable[Any]) -> Any:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(awaitable)

    def _runner() -> Any:
        loop = asyncio.new_event_loop()
        try:
            asyncio.set_event_loop(loop)
            return loop.run_until_complete(awaitable)
        finally:
            loop.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        return executor.submit(_runner).result(timeout=10)


def get_mcp_servers_for_agent(agent_name: str) -> List[str]:
    return list(_AGENT_MCP_ASSOCIATIONS.get(agent_name.lower(), []))


def get_agents_for_mcp_server(server_name: str) -> List[str]:
    return sorted(agent_name for agent_name, servers in _AGENT_MCP_ASSOCIATIONS.items() if server_name in servers)


def _safe_get_available_agents() -> Dict[str, Any]:
    try:
        return get_available_agents()
    except Exception:
        return {}


def add_mcp_server_to_agent(agent_name: str, server_name: str) -> None:
    agent_name_lower = agent_name.lower()
    if agent_name_lower not in _AGENT_MCP_ASSOCIATIONS:
        _AGENT_MCP_ASSOCIATIONS[agent_name_lower] = []
    if server_name not in _AGENT_MCP_ASSOCIATIONS[agent_name_lower]:
        _AGENT_MCP_ASSOCIATIONS[agent_name_lower].append(server_name)


def remove_mcp_server_from_agent(agent_name: str, server_name: str) -> None:
    agent_name_lower = agent_name.lower()
    if agent_name_lower not in _AGENT_MCP_ASSOCIATIONS:
        return
    if server_name in _AGENT_MCP_ASSOCIATIONS[agent_name_lower]:
        _AGENT_MCP_ASSOCIATIONS[agent_name_lower].remove(server_name)
    if not _AGENT_MCP_ASSOCIATIONS[agent_name_lower]:
        _AGENT_MCP_ASSOCIATIONS.pop(agent_name_lower, None)


def remove_mcp_server_from_all_agents(server_name: str) -> None:
    for agent_name in list(_AGENT_MCP_ASSOCIATIONS.keys()):
        remove_mcp_server_from_agent(agent_name, server_name)


def associate_mcp_server_with_agents(server_name: str, agent_names: Optional[Sequence[str]] = None) -> List[str]:
    targets = _normalize_association_targets(agent_names)
    for agent_name in targets:
        add_mcp_server_to_agent(agent_name, server_name)
    return targets


def reset_mcp_bootstrap_state() -> None:
    global _MCP_AUTOLOAD_ATTEMPTED, _MCP_AUTOLOAD_STATUS
    with _MCP_AUTOLOAD_LOCK:
        _MCP_AUTOLOAD_ATTEMPTED = False
        _MCP_AUTOLOAD_STATUS = []


def ensure_configured_mcp_servers(
    manager: Optional[MCPManager] = None,
    *,
    force: bool = False,
) -> List[Dict[str, Any]]:
    global _MCP_AUTOLOAD_ATTEMPTED, _MCP_AUTOLOAD_STATUS

    settings = get_settings()
    if not settings.mcp_autoload_enabled and not force:
        return []

    with _MCP_AUTOLOAD_LOCK:
        if _MCP_AUTOLOAD_ATTEMPTED and not force:
            return list(_MCP_AUTOLOAD_STATUS)

        active_manager = manager or get_mcp_manager(bootstrap=False)
        _MCP_AUTOLOAD_STATUS = _run_awaitable_sync(
            _bootstrap_configured_mcp_servers(active_manager, settings.mcp_managed_servers, settings.mcp_bootstrap_root)
        )
        _MCP_AUTOLOAD_ATTEMPTED = True
        return list(_MCP_AUTOLOAD_STATUS)


async def _bootstrap_configured_mcp_servers(
    manager: MCPManager,
    server_specs: Sequence[ManagedMCPServerSettings],
    bootstrap_root: str,
) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    resolved_root = resolve_mcp_bootstrap_root(bootstrap_root)

    for spec in server_specs:
        if not spec.enabled:
            continue

        result: Dict[str, Any] = {
            "alias": spec.alias,
            "transport": spec.transport,
            "management_mode": spec.management_mode,
        }
        try:
            missing_env = [key for key in spec.required_env if not os.getenv(key, "").strip()]
            if missing_env:
                result["status"] = "skipped"
                result["reason"] = f"missing_required_env:{','.join(missing_env)}"
                results.append(result)
                continue

            # For external servers, skip cleanly when no endpoint/command is configured yet.
            if spec.management_mode == "external":
                endpoint_candidate = (spec.endpoint or "").strip()
                if not endpoint_candidate and spec.endpoint_env:
                    endpoint_candidate = os.getenv(spec.endpoint_env, "").strip()
                if not endpoint_candidate:
                    result["status"] = "skipped"
                    result["reason"] = "missing_endpoint"
                    results.append(result)
                    continue

            if spec.management_mode == "managed":
                result.update(await asyncio.to_thread(prepare_managed_mcp_server, spec, resolved_root))

            endpoint = await asyncio.to_thread(resolve_managed_mcp_endpoint, spec, resolved_root)
            if spec.alias in manager.connections:
                associate_mcp_server_with_agents(spec.alias, spec.agents)
                result["status"] = "already_connected"
            else:
                await manager.connect(alias=spec.alias, endpoint=endpoint, associate_agents=spec.agents)
                result["status"] = "connected"
            result["agents"] = associate_mcp_server_with_agents(spec.alias, spec.agents)
        except Exception as exc:
            result["status"] = "error"
            result["error"] = str(exc)
            _log.debug("Configured MCP bootstrap failed for '%s': %s", spec.alias, exc)
        results.append(result)

    return results


def _normalize_association_targets(agent_names: Optional[Sequence[str]] = None) -> List[str]:
    if not agent_names or any(name.strip() == "*" for name in agent_names if isinstance(name, str)):
        return sorted(name.lower() for name in _safe_get_available_agents().keys())

    return sorted({name.strip().lower() for name in agent_names if isinstance(name, str) and name.strip()})


def _iter_current_target_agents(agent_names: Optional[Sequence[str]] = None) -> Dict[str, Any]:
    available_agents = _safe_get_available_agents()
    if not agent_names or any(name.strip() == "*" for name in agent_names if isinstance(name, str)):
        return {name.lower(): agent for name, agent in available_agents.items()}

    normalized_targets = {name.strip().lower() for name in agent_names if isinstance(name, str) and name.strip()}
    return {name.lower(): agent for name, agent in available_agents.items() if name.lower() in normalized_targets}


def _make_legacy_tool(server_name: str, tool: Any) -> FunctionTool:
    async def _invoke(_ctx: Any, input_json: str) -> Any:
        server = _GLOBAL_MCP_SERVERS.get(server_name)
        if server is None:
            raise RuntimeError(f"MCP server '{server_name}' is not connected")

        payload: Dict[str, Any] = {}
        if input_json.strip():
            decoded = json.loads(input_json)
            if not isinstance(decoded, dict):
                raise ValueError("MCP tool payload must be a JSON object")
            payload = decoded

        if hasattr(server, "call_tool"):
            result = await server.call_tool(tool.name, payload)
        elif hasattr(server, "invoke_tool"):
            result = await server.invoke_tool(tool.name, payload)
        else:
            raise RuntimeError(f"MCP server '{server_name}' does not support tool invocation")

        if isinstance(result, str):
            return result
        try:
            return json.dumps(result, default=str)
        except Exception:
            return str(result)

    schema = getattr(tool, "inputSchema", None)
    if not isinstance(schema, dict):
        schema = {}
    description = str(getattr(tool, "description", "") or f"MCP tool {tool.name}")
    return FunctionTool(
        name=str(getattr(tool, "name", "")),
        description=description,
        params_json_schema=schema,
        on_invoke_tool=_invoke,
        strict_json_schema=False,
    )


def get_mcp_tools_for_agent(agent_name: str) -> List[FunctionTool]:
    try:
        ensure_configured_mcp_servers()
    except Exception as exc:
        _log.debug("Configured MCP bootstrap failed while resolving tools for '%s': %s", agent_name, exc)

    tools: List[FunctionTool] = []
    for server_name in get_mcp_servers_for_agent(agent_name):
        server = _GLOBAL_MCP_SERVERS.get(server_name)
        if server is None or not hasattr(server, "list_tools"):
            continue
        try:
            raw_tools = _run_awaitable_sync(server.list_tools())
        except Exception as exc:
            _log.warning("Failed to get tools from MCP server '%s': %s", server_name, exc)
            continue
        for raw_tool in raw_tools:
            tool_name = str(getattr(raw_tool, "name", "")).strip()
            if not tool_name:
                continue
            tools.append(_make_legacy_tool(server_name, raw_tool))
    return tools


class MCPCommand(FrameworkCommand):
    """Manage MCP server connections and bridge MCP tools/resources into Cerberus AI."""

    name = "/mcp"
    description = "Connect/list/disconnect MCP servers and bridge tools/resources"
    aliases = ["/m"]

    def __init__(self) -> None:
        super().__init__()
        self._subcommands = {
            "connect": "Connect to an MCP server (SSE or stdio endpoint)",
            "list": "List active MCP connections with tools/resources",
            "disconnect": "Disconnect an active MCP alias",
            "context": "Inject MCP resource context into MemoryManager",
            "associations": "Show agent to MCP server associations",
            "help": "Show MCP command usage",
        }

    @property
    def help(self) -> str:
        return (
            "Usage:\n"
            "  /mcp connect <alias> <url_or_path> [--header 'Key: Value']\n"
            "  /mcp list\n"
            "  /mcp disconnect <alias>\n"
            "  /mcp context <alias> <resource_uri> [--topic topic_name] [--agent agent_name]\n"
            "\n"
            "Notes:\n"
            "  - SSE endpoint: https://host/path/sse\n"
            "  - stdio endpoint: stdio:python mcp_server.py\n"
            "  - Every MCP tool call passes through Gatekeeper policy checks"
        )

    async def execute(self, args: List[str]) -> bool:
        if not args:
            console.print(self.help)
            return True

        sub = args[0].lower().strip()
        if sub == "connect":
            return await self._do_connect(args[1:])
        if sub == "list":
            return await self._do_list()
        if sub == "disconnect":
            return await self._do_disconnect(args[1:])
        if sub == "context":
            return await self._do_context(args[1:])
        if sub == "associations":
            return self.handle_associations(args[1:])
        if sub == "help":
            console.print(self.help)
            return True

        console.print(f"[red]Unknown MCP subcommand: {sub}[/red]")
        console.print(self.help)
        return False

    async def _do_connect(self, args: List[str]) -> bool:
        if len(args) < 2:
            console.print("[red]Usage: /mcp connect <alias> <url_or_path> [--header 'Key: Value'][/red]")
            return False

        alias = args[0].strip()
        endpoint = args[1].strip()
        headers, error = self._parse_headers(args[2:])
        if error:
            console.print(f"[red]{error}[/red]")
            return False

        manager = get_mcp_manager(memory=self._resolve_memory_manager())
        try:
            conn = await manager.connect(alias=alias, endpoint=endpoint, headers=headers)
        except Exception as exc:
            console.print(f"[red]MCP connect failed: {exc}[/red]")
            return False

        panel = Panel(
            f"[bold green]Connected[/bold green]\n"
            f"Alias: [cyan]{conn.alias}[/cyan]\n"
            f"Transport: [magenta]{conn.transport}[/magenta]\n"
            f"Tools bridged: [yellow]{len(conn.tools)}[/yellow]\n"
            f"Resources discovered: [yellow]{len(conn.resources)}[/yellow]",
            title="MCP Connection",
            border_style="green",
        )
        console.print(panel)
        return True

    async def _do_list(self) -> bool:
        manager = get_mcp_manager(memory=self._resolve_memory_manager())
        connections = manager.connections

        if not connections:
            console.print("[yellow]No MCP servers connected[/yellow]")
            return True

        table = Table(title="MCP Connections", box=box.ROUNDED)
        table.add_column("Alias", style="cyan")
        table.add_column("Transport", style="magenta")
        table.add_column("Endpoint", style="green")
        table.add_column("Tools", style="yellow")
        table.add_column("Resources", style="yellow")

        for conn in connections.values():
            table.add_row(
                conn.alias,
                conn.transport,
                conn.endpoint,
                str(len(conn.tools)),
                str(len(conn.resources)),
            )

        console.print(table)

        tool_table = Table(title="Bridged MCP Tools", box=box.SIMPLE)
        tool_table.add_column("Registered Name", style="cyan")
        tool_table.add_column("Description", style="white")
        for name, tool in manager.tool_registry.items():
            tool_table.add_row(name, getattr(tool, "description", ""))

        console.print(tool_table)
        return True

    async def _do_disconnect(self, args: List[str]) -> bool:
        if not args:
            console.print("[red]Usage: /mcp disconnect <alias>[/red]")
            return False

        alias = args[0].strip()
        manager = get_mcp_manager(memory=self._resolve_memory_manager())

        ok = await manager.disconnect(alias)
        if ok:
            console.print(f"[green]Disconnected MCP alias '{alias}'[/green]")
            return True

        console.print(f"[yellow]Alias '{alias}' was not connected[/yellow]")
        return False

    async def _do_context(self, args: List[str]) -> bool:
        if len(args) < 2:
            console.print(
                "[red]Usage: /mcp context <alias> <resource_uri> [--topic topic_name] [--agent agent_name][/red]"
            )
            return False

        alias = args[0].strip()
        resource_uri = args[1].strip()

        topic = "mcp.context"
        target_agent: Optional[str] = None

        i = 2
        while i < len(args):
            token = args[i]
            if token == "--topic":
                if i + 1 >= len(args):
                    console.print("[red]--topic requires a value[/red]")
                    return False
                topic = args[i + 1].strip() or topic
                i += 2
                continue
            if token == "--agent":
                if i + 1 >= len(args):
                    console.print("[red]--agent requires a value[/red]")
                    return False
                target_agent = args[i + 1].strip()
                i += 2
                continue
            console.print(f"[red]Unknown argument: {token}[/red]")
            return False

        manager = get_mcp_manager(memory=self._resolve_memory_manager())

        try:
            content = await manager.inject_resource_context(
                alias=alias,
                resource_uri=resource_uri,
                topic=topic,
                target_agent=target_agent,
            )
        except Exception as exc:
            console.print(f"[red]Context injection failed: {exc}[/red]")
            return False

        preview = content if len(content) <= 500 else content[:500] + "..."
        console.print(
            Panel(
                f"[bold green]Context Injected[/bold green]\n"
                f"Alias: [cyan]{alias}[/cyan]\n"
                f"Resource: [magenta]{resource_uri}[/magenta]\n"
                f"Topic: [yellow]{topic}[/yellow]\n\n"
                f"[white]{preview}[/white]",
                title="MCP Resource Injection",
                border_style="green",
            )
        )
        return True

    def _resolve_memory_manager(self) -> MemoryManager:
        candidate = self.memory
        if isinstance(candidate, MemoryManager):
            return candidate
        return MemoryManager()

    def handle_associations(self, args: Optional[List[str]] = None) -> bool:
        _ = args
        if not _AGENT_MCP_ASSOCIATIONS:
            console.print("[yellow]No agent-MCP associations configured[/yellow]")
            return True

        table = Table(title="Agent-MCP Associations", box=box.ROUNDED)
        table.add_column("Agent", style="cyan")
        table.add_column("MCP Servers", style="magenta")
        table.add_column("Total Tools", style="yellow")

        for agent_name, server_names in sorted(_AGENT_MCP_ASSOCIATIONS.items()):
            if not server_names:
                continue
            total_tools = len(get_mcp_tools_for_agent(agent_name))
            table.add_row(agent_name, ", ".join(server_names), str(total_tools))

        console.print(table)
        return True

    @staticmethod
    def _parse_headers(args: Sequence[str]) -> Tuple[Dict[str, str], Optional[str]]:
        headers: Dict[str, str] = {}
        i = 0
        while i < len(args):
            token = args[i]
            if token not in ("--header", "-H"):
                return headers, f"Unknown argument: {token}"
            if i + 1 >= len(args):
                return headers, "--header requires a value"
            raw = args[i + 1]
            if ":" not in raw:
                return headers, f"Invalid header format '{raw}', expected 'Key: Value'"
            key, value = raw.split(":", 1)
            headers[key.strip()] = value.strip()
            i += 2

        return headers, None


MCP_COMMAND_INSTANCE = MCPCommand()
register_command(MCP_COMMAND_INSTANCE)
