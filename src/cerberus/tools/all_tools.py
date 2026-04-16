"""
Dynamic Tool Discovery & Management System for Cerberus AI.

This module provides a professional, modular way to manage and access tools within
the Cerberus AI framework. Instead of eagerly importing all tools at startup, this
registry implements lazy loading, permission scoping, dependency validation, and
forensic telemetry to create a commercial-grade tool orchestrator.

Architecture:
- ToolMetadata: Structured representation of tool with dependencies and phase
- ToolAuthorizationManager: Permission scoping by security phase and agent role
- CerebroToolRegistry: Singleton registry for discovery, loading, permission gating
- Dependency Checking: Validates system dependencies before exposing tools
- Forensic Logging: Audits tool initialization and loading events

Security Phases:
- PHASE_RECON: Reconnaissance and information gathering
- PHASE_EXPLOIT: Exploitation and initial access
- PHASE_SYSTEM: System interaction (file ops, execution)
- PHASE_META: Meta tools (agent_info, list_tools, etc.)
"""

from __future__ import annotations

import importlib
import inspect
import json
import os
import shutil
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from pydantic import BaseModel, Field, ValidationError

# Framework dependencies
try:
    from cerberus.repl.ui.logging import get_cerberus_logger, LOG_AUDIT
except ImportError:
    get_cerberus_logger = None
    LOG_AUDIT = "AUDIT"

try:
    from cerberus.memory.logic import clean
except ImportError:
    clean = lambda x: x


# =============================================================================
# Security Phase Constants
# =============================================================================

PHASE_RECON = "recon"
PHASE_EXPLOIT = "exploit"
PHASE_SYSTEM = "system"
PHASE_META = "meta"

SECURITY_PHASES = {
    PHASE_RECON,
    PHASE_EXPLOIT,
    PHASE_SYSTEM,
    PHASE_META,
}

PHASE_DESCRIPTIONS = {
    PHASE_RECON: "Reconnaissance & information gathering",
    PHASE_EXPLOIT: "Exploitation & initial access",
    PHASE_SYSTEM: "System interaction & execution",
    PHASE_META: "Meta tools & introspection",
}


# =============================================================================
# Tool Discovery Catalog
# =============================================================================

TOOL_CATALOG = {
    # ── PHASE_RECON: Reconnaissance Tools ─────────────────────────────────
    "generic_linux_command": {
        "module": "cerberus.tools.reconnaissance.generic_linux_command",
        "name": "generic_linux_command",
        "phase": PHASE_RECON,
        "dependencies": [],
        "description": "Run generic Linux commands for reconnaissance",
    },
    "execute_code": {
        "module": "cerberus.tools.reconnaissance.exec_code",
        "name": "execute_code",
        "phase": PHASE_RECON,
        "dependencies": [],
        "description": "Execute code for reconnaissance",
    },
    "ldap_search": {
        "module": "cerberus.tools.reconnaissance.ldap_search",
        "name": "ldap_search",
        "phase": PHASE_RECON,
        "dependencies": ["ldapsearch"],
        "description": "Search LDAP directories",
    },
    "nmap": {
        "module": "cerberus.tools.reconnaissance.nmap",
        "name": "nmap",
        "phase": PHASE_RECON,
        "dependencies": ["nmap"],
        "description": "Network scanning and port enumeration with nmap",
    },
    "netcat": {
        "module": "cerberus.tools.reconnaissance.netcat",
        "name": "netcat",
        "phase": PHASE_RECON,
        "dependencies": ["nc"],
        "description": "Network utility for reading/writing network connections",
    },
    "netstat": {
        "module": "cerberus.tools.reconnaissance.netstat",
        "name": "netstat",
        "phase": PHASE_RECON,
        "dependencies": ["netstat"],
        "description": "Display network statistics",
    },
    "curl": {
        "module": "cerberus.tools.reconnaissance.curl",
        "name": "curl",
        "phase": PHASE_RECON,
        "dependencies": ["curl"],
        "description": "Transfer data using URLs",
    },
    "wget": {
        "module": "cerberus.tools.reconnaissance.wget",
        "name": "wget",
        "phase": PHASE_RECON,
        "dependencies": ["wget"],
        "description": "Download files from web servers",
    },
    "smb_list_shares": {
        "module": "cerberus.tools.reconnaissance.smbclient_tool",
        "name": "smb_list_shares",
        "phase": PHASE_RECON,
        "dependencies": ["smbclient"],
        "description": "List SMB shares on a target",
    },
    "smb_run_smbclient": {
        "module": "cerberus.tools.reconnaissance.smbclient_tool",
        "name": "smb_run_smbclient",
        "phase": PHASE_RECON,
        "dependencies": ["smbclient"],
        "description": "Run SMB client commands",
    },
    "smb_download_file": {
        "module": "cerberus.tools.reconnaissance.smbclient_tool",
        "name": "smb_download_file",
        "phase": PHASE_RECON,
        "dependencies": ["smbclient"],
        "description": "Download files via SMB",
    },
    "cat_file": {
        "module": "cerberus.tools.reconnaissance.filesystem",
        "name": "cat_file",
        "phase": PHASE_RECON,
        "dependencies": [],
        "description": "Read file contents",
    },
    "read_file": {
        "module": "cerberus.tools.reconnaissance.filesystem",
        "name": "read_file",
        "phase": PHASE_RECON,
        "dependencies": [],
        "description": "Read file contents with size guardrails and redaction",
    },
    "write_file": {
        "module": "cerberus.tools.reconnaissance.filesystem",
        "name": "write_file",
        "phase": PHASE_RECON,
        "dependencies": [],
        "description": "Write workspace-scoped files and log integrity hashes",
    },
    "find_file": {
        "module": "cerberus.tools.reconnaissance.filesystem",
        "name": "find_file",
        "phase": PHASE_RECON,
        "dependencies": [],
        "description": "Find files on the system",
    },
    "list_dir": {
        "module": "cerberus.tools.reconnaissance.filesystem",
        "name": "list_dir",
        "phase": PHASE_RECON,
        "dependencies": [],
        "description": "List directory contents",
    },
    "pwd_command": {
        "module": "cerberus.tools.reconnaissance.filesystem",
        "name": "pwd_command",
        "phase": PHASE_RECON,
        "dependencies": [],
        "description": "Print working directory",
    },
    "strings_command": {
        "module": "cerberus.tools.reconnaissance.crypto_tools",
        "name": "strings_command",
        "phase": PHASE_RECON,
        "dependencies": ["strings"],
        "description": "Extract strings from binary files",
    },
    "decode64": {
        "module": "cerberus.tools.reconnaissance.crypto_tools",
        "name": "decode64",
        "phase": PHASE_RECON,
        "dependencies": [],
        "description": "Decode base64 encoded data",
    },
    "decode_hex_bytes": {
        "module": "cerberus.tools.reconnaissance.crypto_tools",
        "name": "decode_hex_bytes",
        "phase": PHASE_RECON,
        "dependencies": [],
        "description": "Decode hexadecimal bytes",
    },
    "blue_team_safe_command": {
        "module": "cerberus.tools.reconnaissance.blue_team_safe_command",
        "name": "blue_team_safe_command",
        "phase": PHASE_RECON,
        "dependencies": [],
        "description": "Run blue team safe commands",
    },
    "shodan_search": {
        "module": "cerberus.tools.reconnaissance.shodan",
        "name": "shodan_search",
        "phase": PHASE_RECON,
        "dependencies": [],
        "description": "Search Shodan for devices",
        "requires_env": ["SHODAN_API_KEY"],
    },
    "shodan_host_info": {
        "module": "cerberus.tools.reconnaissance.shodan",
        "name": "shodan_host_info",
        "phase": PHASE_RECON,
        "dependencies": [],
        "description": "Get Shodan host information",
        "requires_env": ["SHODAN_API_KEY"],
    },
    "make_web_search_with_explanation": {
        "module": "cerberus.tools.web.search_web",
        "name": "make_web_search_with_explanation",
        "phase": PHASE_RECON,
        "dependencies": [],
        "description": "Search web with explanations via SearXNG",
    },
    "searxng_web_search": {
        "module": "cerberus.tools.web.search_web",
        "name": "searxng_web_search",
        "phase": PHASE_RECON,
        "dependencies": [],
        "description": "Search web via local SearXNG instance",
    },
    "run_ssh_command_with_credentials": {
        "module": "cerberus.tools.command_and_control.sshpass",
        "name": "run_ssh_command_with_credentials",
        "phase": PHASE_SYSTEM,
        "dependencies": ["sshpass"],
        "description": "Execute SSH commands with password authentication",
    },
    "capture_remote_traffic": {
        "module": "cerberus.tools.network.capture_traffic",
        "name": "capture_remote_traffic",
        "phase": PHASE_SYSTEM,
        "dependencies": ["tcpdump"],
        "description": "Capture network traffic remotely",
    },
    "remote_capture_session": {
        "module": "cerberus.tools.network.capture_traffic",
        "name": "remote_capture_session",
        "phase": PHASE_SYSTEM,
        "dependencies": ["tcpdump"],
        "description": "Start remote packet capture session",
    },
    "web_request_framework": {
        "module": "cerberus.tools.web.headers",
        "name": "web_request_framework",
        "phase": PHASE_SYSTEM,
        "dependencies": [],
        "description": "Make web requests with headers",
    },
    "js_surface_mapper": {
        "module": "cerberus.tools.web.js_surface_mapper",
        "name": "js_surface_mapper",
        "phase": PHASE_SYSTEM,
        "dependencies": [],
        "description": "Map JavaScript attack surface",
    },
    "execute_python_code": {
        "module": "cerberus.tools.misc.code_interpreter",
        "name": "execute_python_code",
        "phase": PHASE_SYSTEM,
        "dependencies": [],
        "description": "Execute Python code",
    },
    "scripting_tool": {
        "module": "cerberus.tools.others.scripting",
        "name": "scripting_tool",
        "phase": PHASE_SYSTEM,
        "dependencies": [],
        "description": "Execute scripts",
    },
    "execute_cli_command": {
        "module": "cerberus.tools.misc.cli_utils",
        "name": "execute_cli_command",
        "phase": PHASE_SYSTEM,
        "dependencies": [],
        "description": "Execute CLI commands",
    },
    "write_key_findings": {
        "module": "cerberus.tools.misc.reasoning",
        "name": "write_key_findings",
        "phase": PHASE_META,
        "dependencies": [],
        "description": "Write key findings to memory",
    },
    "read_key_findings": {
        "module": "cerberus.tools.misc.reasoning",
        "name": "read_key_findings",
        "phase": PHASE_META,
        "dependencies": [],
        "description": "Read key findings from memory",
    },
    "query_memory": {
        "module": "cerberus.tools.misc.rag",
        "name": "query_memory",
        "phase": PHASE_META,
        "dependencies": [],
        "description": "Query episodic and semantic memory",
    },
    "add_to_memory_episodic": {
        "module": "cerberus.tools.misc.rag",
        "name": "add_to_memory_episodic",
        "phase": PHASE_META,
        "dependencies": [],
        "description": "Add to episodic memory",
    },
    "add_to_memory_semantic": {
        "module": "cerberus.tools.misc.rag",
        "name": "add_to_memory_semantic",
        "phase": PHASE_META,
        "dependencies": [],
        "description": "Add to semantic memory",
    },
    "get_rag_status": {
        "module": "cerberus.tools.misc.rag_monitor",
        "name": "get_rag_status",
        "phase": PHASE_META,
        "dependencies": [],
        "description": "Get RAG system status",
    },
    "session_checkpoint": {
        "module": "cerberus.tools.sessions",
        "name": "session_checkpoint",
        "phase": PHASE_META,
        "dependencies": [],
        "description": "Save semantic engagement checkpoint for handoff and recovery",
    },
    "session_resume": {
        "module": "cerberus.tools.sessions",
        "name": "session_resume",
        "phase": PHASE_META,
        "dependencies": [],
        "description": "Resume previously saved engagement checkpoint",
    },
    "session_list": {
        "module": "cerberus.tools.sessions",
        "name": "session_list",
        "phase": PHASE_META,
        "dependencies": [],
        "description": "List available engagement checkpoints in current workspace",
    },
    "session_export": {
        "module": "cerberus.tools.sessions",
        "name": "session_export",
        "phase": PHASE_META,
        "dependencies": [],
        "description": "Export cross-agent handoff memo from a checkpoint",
    },
    "validate_json_schema": {
        "module": "cerberus.tools.validation",
        "name": "validate_json_schema",
        "phase": PHASE_META,
        "dependencies": [],
        "description": "Validate JSON payloads against strict registered schemas",
    },
    "verify_target_availability": {
        "module": "cerberus.tools.validation",
        "name": "verify_target_availability",
        "phase": PHASE_RECON,
        "dependencies": [],
        "description": "Verify target reachability before major scans",
    },
    "validate_semantic_result": {
        "module": "cerberus.tools.validation",
        "name": "validate_semantic_result",
        "phase": PHASE_META,
        "dependencies": [],
        "description": "Deterministically corroborate findings to reduce false positives",
    },
    "validate_resource_health": {
        "module": "cerberus.tools.validation",
        "name": "validate_resource_health",
        "phase": PHASE_SYSTEM,
        "dependencies": [],
        "description": "Check platform and sandbox resource health before heavy tasks",
    },
    "list_assets": {
        "module": "cerberus.tools.workspace",
        "name": "list_assets",
        "phase": PHASE_META,
        "dependencies": [],
        "description": "List structured workspace assets across logs, artifacts, findings, work, and evidence",
    },
    "categorize_artifact": {
        "module": "cerberus.tools.workspace",
        "name": "categorize_artifact",
        "phase": PHASE_SYSTEM,
        "dependencies": [],
        "description": "Move and classify raw artifacts into evidence subfolders with forensic labels",
    },
    "get_summary": {
        "module": "cerberus.tools.workspace",
        "name": "get_summary",
        "phase": PHASE_META,
        "dependencies": [],
        "description": "Get workspace metadata summary including file count and recency",
    },
    "semantic_search": {
        "module": "cerberus.tools.workspace",
        "name": "semantic_search",
        "phase": PHASE_RECON,
        "dependencies": [],
        "description": "Search workspace text artifacts by keyword relevance",
    },
    "stage_for_archive": {
        "module": "cerberus.tools.workspace",
        "name": "stage_for_archive",
        "phase": PHASE_META,
        "dependencies": [],
        "description": "Flag files for retention as trash or critical evidence",
    },
}


# =============================================================================
# Data Models
# =============================================================================

class ToolMetadata(BaseModel):
    """Structured metadata for a tool in the registry."""

    name: str = Field(
        ...,
        description="Unique tool name (matches function name)",
        min_length=1,
        max_length=256,
    )
    module: str = Field(
        ..., description="Module path where tool is defined", min_length=1
    )
    phase: str = Field(
        ...,
        description="Security phase: recon, exploit, system, meta",
    )
    dependencies: List[str] = Field(
        default_factory=list, description="System dependencies (e.g., 'nmap')"
    )
    description: str = Field(default="", description="Tool description for discovery")
    enabled: bool = Field(default=True, description="Whether tool is available")
    disabled_reason: Optional[str] = Field(default=None, description="Why tool is disabled")
    requires_env: List[str] = Field(
        default_factory=list, description="Required environment variables"
    )

    class Config:
        frozen = True


class ToolRegistry(BaseModel):
    """Response model for tool registry queries."""

    total_tools: int = Field(..., description="Total tools in registry")
    available_tools: int = Field(..., description="Available (enabled) tools")
    disabled_tools: int = Field(..., description="Disabled tools")
    phase_breakdown: Dict[str, int] = Field(
        ..., description="Tool count per security phase"
    )
    tools: List[ToolMetadata] = Field(default_factory=list, description="Tool metadata")

    class Config:
        frozen = True


# =============================================================================
# Tool Authorization & Permission Manager
# =============================================================================

class ToolAuthorizationManager:
    """Manages agent authorization for tool access by security phase and role."""

    PHASE_ACCESS_MATRIX = {
        PHASE_RECON: ["red_team", "blue_team", "analyzer", "researcher"],
        PHASE_EXPLOIT: ["red_team", "researcher"],
        PHASE_SYSTEM: ["supervisor", "automation", "executor", "scheduler"],
        PHASE_META: ["red_team", "blue_team", "analyzer", "supervisor", "system"],
    }

    @staticmethod
    def get_accessible_phases(agent_role: str) -> Set[str]:
        """Get the set of security phases accessible to an agent role."""
        accessible = set()
        for phase, roles in ToolAuthorizationManager.PHASE_ACCESS_MATRIX.items():
            if agent_role in roles or agent_role == "supervisor":
                accessible.add(phase)
        return accessible

    @staticmethod
    def is_phase_allowed(agent_role: str, phase: str) -> bool:
        """Check if an agent role can access tools from a given phase."""
        if agent_role == "supervisor":
            return True
        accessible = ToolAuthorizationManager.get_accessible_phases(agent_role)
        return phase in accessible


# =============================================================================
# Dependency Checking
# =============================================================================

def _check_executable_dependency(name: str) -> bool:
    """Check if an executable dependency is available on the system."""
    return shutil.which(name) is not None


def _check_python_dependency(name: str) -> bool:
    """Check if a Python package is available."""
    try:
        importlib.import_module(name)
        return True
    except ImportError:
        return False


def _check_dependency(dep: str) -> bool:
    """Check if a dependency is available (executable or Python package)."""
    return _check_executable_dependency(dep) or _check_python_dependency(dep)


def _check_env_requirements(requires_env: List[str]) -> bool:
    """Check if required environment variables are set."""
    if not requires_env:
        return True
    return all(os.getenv(var) for var in requires_env)


# =============================================================================
# Tool Discovery & Loader Engine
# =============================================================================

class CerberusToolRegistry:
    """Singleton registry for discovering, loading, and managing tools."""

    _instance: Optional[CerberusToolRegistry] = None
    _lock = object()

    def __new__(cls):
        """Ensure singleton pattern."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        """Initialize the registry (only once due to singleton)."""
        if self._initialized:
            return

        self._initialized = True
        self._logger = get_cerberus_logger() if get_cerberus_logger else None
        self._metadata: Dict[str, ToolMetadata] = {}
        self._instances: Dict[str, Any] = {}
        self._discovery_time = datetime.utcnow().isoformat()

        self._discover_tools()
        self._log_initialization()

    def _discover_tools(self) -> None:
        """Scan and validate all tools in the catalog."""
        for tool_key, tool_info in TOOL_CATALOG.items():
            try:
                requires_env = tool_info.get("requires_env", [])
                if not _check_env_requirements(requires_env):
                    disabled_reason = (
                        f"Missing environment variable(s): {', '.join(requires_env)}"
                    )
                    self._metadata[tool_key] = ToolMetadata(
                        name=tool_info["name"],
                        module=tool_info["module"],
                        phase=tool_info["phase"],
                        dependencies=tool_info.get("dependencies", []),
                        description=tool_info.get("description", ""),
                        enabled=False,
                        disabled_reason=disabled_reason,
                        requires_env=requires_env,
                    )
                    continue

                dependencies = tool_info.get("dependencies", [])
                missing_deps = [d for d in dependencies if not _check_dependency(d)]

                if missing_deps:
                    disabled_reason = f"Missing dependencies: {', '.join(missing_deps)}"
                    self._metadata[tool_key] = ToolMetadata(
                        name=tool_info["name"],
                        module=tool_info["module"],
                        phase=tool_info["phase"],
                        dependencies=dependencies,
                        description=tool_info.get("description", ""),
                        enabled=False,
                        disabled_reason=disabled_reason,
                        requires_env=tool_info.get("requires_env", []),
                    )
                else:
                    self._metadata[tool_key] = ToolMetadata(
                        name=tool_info["name"],
                        module=tool_info["module"],
                        phase=tool_info["phase"],
                        dependencies=dependencies,
                        description=tool_info.get("description", ""),
                        enabled=True,
                        disabled_reason=None,
                        requires_env=tool_info.get("requires_env", []),
                    )
            except (ValidationError, KeyError) as e:
                if self._logger:
                    try:
                        self._logger.action(
                            f"Failed to process tool '{tool_key}'",
                            data={"error": str(e)},
                            tags=["error"],
                        )
                    except Exception:
                        pass

    def _log_initialization(self) -> None:
        """Log registry initialization to forensic logger."""
        if not self._logger:
            return

        try:
            enabled_count = sum(1 for t in self._metadata.values() if t.enabled)
            disabled_count = len(self._metadata) - enabled_count
            phase_counts = {}
            for meta in self._metadata.values():
                if meta.enabled:
                    phase_counts[meta.phase] = phase_counts.get(meta.phase, 0) + 1
            phase_summary = ", ".join(
                f"{phase}={count}" for phase, count in sorted(phase_counts.items())
            )

            message = (
                "CerebroToolRegistry initialized: "
                f"{enabled_count}/{len(self._metadata)} tools enabled"
                + (f" ({phase_summary})" if phase_summary else "")
            ).strip()
            self._logger.audit(message, tags=["registry"])
        except Exception:
            pass

    def _load_tool(self, tool_key: str) -> Any:
        """Lazy-load a tool by name and cache it."""
        if tool_key in self._instances:
            return self._instances[tool_key]

        if tool_key not in self._metadata:
            raise ValueError(f"Tool not found: {tool_key}")

        metadata = self._metadata[tool_key]
        if not metadata.enabled:
            raise ValueError(f"Tool is disabled: {tool_key}")

        try:
            module = importlib.import_module(metadata.module)
            tool_func = getattr(module, metadata.name)
            self._instances[tool_key] = tool_func
            if self._logger:
                try:
                    self._logger.action(
                        f"Tool loaded: {metadata.name}",
                        tags=["tool_load"],
                    )
                except Exception:
                    pass
            return tool_func
        except (ImportError, AttributeError, SyntaxError) as e:
            self._metadata[tool_key] = metadata.copy(
                update={"enabled": False, "disabled_reason": f"Load failed: {str(e)}"}
            )
            if self._logger:
                try:
                    self._logger.action(
                        f"Failed to load tool: {tool_key}",
                        data={"error": str(e)},
                        tags=["error"],
                    )
                except Exception:
                    pass
            raise ValueError(f"Failed to load tool '{tool_key}': {str(e)}")

    @property
    def discovery_time(self) -> str:
        """Get discovery timestamp."""
        return self._discovery_time

    def get_tool_by_name(self, tool_name: str) -> Any:
        """Get a tool by name (lazy-loaded)."""
        tool_key = None
        for key, meta in self._metadata.items():
            if meta.name == tool_name:
                tool_key = key
                break

        if tool_key is None:
            raise ValueError(f"Tool not found: {tool_name}")

        return self._load_tool(tool_key)

    def get_tools_for_agent(self, agent_role: str) -> List[ToolMetadata]:
        """Get available tools that an agent can use based on their role."""
        accessible_phases = ToolAuthorizationManager.get_accessible_phases(agent_role)
        tools = [
            meta
            for meta in self._metadata.values()
            if meta.enabled and meta.phase in accessible_phases
        ]
        return sorted(tools, key=lambda t: (t.phase, t.name))

    def get_tools_by_phase(self, phase: str, agent_role: Optional[str] = None) -> List[ToolMetadata]:
        """Get tools filtered by security phase."""
        if phase not in SECURITY_PHASES:
            raise ValueError(f"Unknown phase: {phase}")

        if agent_role and not ToolAuthorizationManager.is_phase_allowed(agent_role, phase):
            return []

        tools = [meta for meta in self._metadata.values() if meta.phase == phase and meta.enabled]
        return sorted(tools, key=lambda t: t.name)

    def get_all_tools(self) -> List[ToolMetadata]:
        """Get all enabled tools in the registry."""
        return sorted(self._metadata.values(), key=lambda t: (t.phase, t.name))

    def get_tool_metadata(self, tool_name: str) -> Optional[ToolMetadata]:
        """Get metadata for a specific tool (without loading it)."""
        for meta in self._metadata.values():
            if meta.name == tool_name:
                return meta
        return None

    def get_registry_status(self) -> ToolRegistry:
        """Get comprehensive registry status and statistics."""
        enabled_tools = [t for t in self._metadata.values() if t.enabled]
        disabled_tools = [t for t in self._metadata.values() if not t.enabled]

        phase_breakdown = {}
        for phase in SECURITY_PHASES:
            count = sum(1 for t in enabled_tools if t.phase == phase)
            if count > 0:
                phase_breakdown[phase] = count

        return ToolRegistry(
            total_tools=len(self._metadata),
            available_tools=len(enabled_tools),
            disabled_tools=len(disabled_tools),
            phase_breakdown=phase_breakdown,
            tools=enabled_tools,
        )

    def disable_tool(self, tool_name: str, reason: str) -> bool:
        """Manually disable a tool."""
        for key, meta in self._metadata.items():
            if meta.name == tool_name:
                self._metadata[key] = meta.copy(
                    update={"enabled": False, "disabled_reason": reason}
                )
                return True
        return False

    def enable_tool(self, tool_name: str) -> bool:
        """Re-enable a disabled tool."""
        for key, meta in self._metadata.items():
            if meta.name == tool_name:
                self._metadata[key] = meta.copy(
                    update={"enabled": True, "disabled_reason": None}
                )
                return True
        return False


# =============================================================================
# Module-level Singleton Access
# =============================================================================

TOOL_REGISTRY = CerberusToolRegistry()


def get_tool_registry() -> CerberusToolRegistry:
    """Get the global tool registry singleton."""
    return TOOL_REGISTRY


def get_all_tools() -> List[ToolMetadata]:
    """Get all available tools (backward compatibility)."""
    return TOOL_REGISTRY.get_all_tools()


def get_tools_for_agent(agent_role: str) -> List[ToolMetadata]:
    """Get tools available to a specific agent role."""
    return TOOL_REGISTRY.get_tools_for_agent(agent_role)


def get_tool(tool_name: str) -> Any:
    """Get a specific tool by name (lazy-loaded)."""
    return TOOL_REGISTRY.get_tool_by_name(tool_name)


def get_registry_status() -> Dict[str, Any]:
    """Get registry status and statistics."""
    status = TOOL_REGISTRY.get_registry_status()
    return {
        "total_tools": status.total_tools,
        "available_tools": status.available_tools,
        "disabled_tools": status.disabled_tools,
        "phase_breakdown": status.phase_breakdown,
        "discovery_time": TOOL_REGISTRY.discovery_time,
    }
