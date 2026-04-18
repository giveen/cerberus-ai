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

from enum import Enum
import importlib
import inspect
import json
import os
import re
import shutil
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from pydantic import BaseModel, Field, ValidationError
from cerberus.planner.models import DependencyKind
from cerberus.planner.validator import (
    UnresolvedDependencyError,
    validate_plan,
)
from cerberus.tools.tool_graph import (
    ToolGraph,
    ToolNode,
    activate_tool_subgraph as graph_activate_tool_subgraph,
    build_tool_graph,
)

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


def _is_truthy_env(value: str) -> bool:
    raw = str(value or "").strip().lower()
    if not raw:
        return False
    if raw.isdigit():
        return int(raw) > 0
    return raw in {"1", "true", "yes", "on", "debug", "verbose"}


def _jit_debug_enabled() -> bool:
    """Return True when JIT trace output is enabled.

    CERBERUS_JIT_DEBUG takes precedence. CERBERUS_DEBUG is used as fallback.
    """
    explicit = os.getenv("CERBERUS_JIT_DEBUG")
    if explicit is not None:
        return _is_truthy_env(explicit)
    return _is_truthy_env(os.getenv("CERBERUS_DEBUG", ""))


def _jit_trace(message: str) -> None:
    if _jit_debug_enabled():
        print(f"[JIT] {message}")


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
    "ping_kali": {
        "module": "cerberus.tools.reconnaissance.ping_kali",
        "name": "ping_kali",
        "phase": PHASE_RECON,
        "dependencies": ["uname"],
        "description": "Run a Kali canary command to attest container execution environment",
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
    "Maps": {
        "module": "cerberus.tools.reconnaissance.browser",
        "name": "Maps",
        "phase": PHASE_RECON,
        "dependencies": [],
        "description": "Navigate to dynamic web targets with optional HTTP Basic Auth",
    },
    "get_page_source": {
        "module": "cerberus.tools.reconnaissance.browser",
        "name": "get_page_source",
        "phase": PHASE_RECON,
        "dependencies": [],
        "description": "Fetch and token-reduce current page source by stripping heavy DOM tags",
    },
    "click_element": {
        "module": "cerberus.tools.reconnaissance.browser",
        "name": "click_element",
        "phase": PHASE_RECON,
        "dependencies": [],
        "description": "Click DOM elements using CSS selectors in the active browser page",
    },
    "fill_form": {
        "module": "cerberus.tools.reconnaissance.browser",
        "name": "fill_form",
        "phase": PHASE_RECON,
        "dependencies": [],
        "description": "Fill form inputs using CSS selectors in the active browser page",
    },
    "browser_screenshot": {
        "module": "cerberus.tools.reconnaissance.browser",
        "name": "browser_screenshot",
        "phase": PHASE_RECON,
        "dependencies": [],
        "description": "Capture a full-page screenshot from the active Playwright browser session",
    },
    "extract_elements": {
        "module": "cerberus.tools.reconnaissance.browser",
        "name": "extract_elements",
        "phase": PHASE_RECON,
        "dependencies": [],
        "description": "Extract visible DOM text and optional attributes from CSS selector matches",
    },
    "describe_page_structure": {
        "module": "cerberus.tools.reconnaissance.browser",
        "name": "describe_page_structure",
        "phase": PHASE_RECON,
        "dependencies": [],
        "description": "Summarize page title, headings, forms, and links from the active browser page",
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
    "request_toolbox": {
        "module": "cerberus.tools.sessions",
        "name": "request_toolbox",
        "phase": PHASE_META,
        "dependencies": [],
        "description": "Persist requested toolbox category for next turn tool routing",
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

TOOL_GRAPH: ToolGraph = build_tool_graph(TOOL_CATALOG)


# Explicit core tools injected into every execution plan.
CORE_TOOL_INJECTION = {
    "reasoning": "read_key_findings",
    "workspace": "list_assets",
    "routing": "request_toolbox",
}
CORE_TOOL_NAMES = list(CORE_TOOL_INJECTION.values())


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
    category: str = Field(
        ..., description="Top-level tool category derived from metadata graph"
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


class ResolutionResult(BaseModel):
    """Deterministic category resolution with explicit scoring output."""

    primary_category: str = Field(..., min_length=1)
    secondary_categories: List[str] = Field(default_factory=list)
    confidence_scores: Dict[str, float] = Field(default_factory=dict)
    fallback_reason: Optional[str] = None

    class Config:
        frozen = True


class ToolResolutionState(str, Enum):
    SUCCESS = "SUCCESS"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"


class DeprecationError(RuntimeError):
    """Raised when deprecated fallback-era APIs are invoked at runtime."""


class ExecutionPlanValidationError(RuntimeError):
    """Raised when deterministic execution-plan validation fails."""


class ToolResolutionResult(BaseModel):
    """Explicit stateful tool activation result for one category request."""

    state: ToolResolutionState
    requested_category: str
    resolved_category: str
    tools: List[Any] = Field(default_factory=list)
    unavailable_tools: List[str] = Field(default_factory=list)
    reason: Optional[str] = None

    class Config:
        arbitrary_types_allowed = True


class ExecutionPlan(BaseModel):
    """Deterministic pre-LLM execution plan for tool selection."""

    resolved_category: str
    tool_nodes: List[ToolNode] = Field(default_factory=list)
    dependencies: List[str] = Field(default_factory=list)
    unresolved_references: List[str] = Field(default_factory=list)
    resolution_state: ToolResolutionState
    reasoning_trace: List[str] = Field(default_factory=list)

    class Config:
        arbitrary_types_allowed = True


class ExecutionPlanValidationResult(BaseModel):
    """Non-mutating validation output for execution plans."""

    is_valid: bool
    errors: List[str] = Field(default_factory=list)
    validated_tool_ids: List[str] = Field(default_factory=list)
    unresolved_references: List[str] = Field(default_factory=list)
    dependency_kinds: Dict[str, str] = Field(default_factory=dict)
    dependency_trace: List[str] = Field(default_factory=list)

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
    category_breakdown: Dict[str, int] = Field(
        default_factory=dict, description="Tool count per graph-derived category"
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


def _existing_tool_categories() -> Set[str]:
    """Return categories from metadata graph (no filesystem scan)."""
    return set(TOOL_GRAPH.categories.keys())


def get_existing_tool_categories() -> List[str]:
    """Return sorted list of top-level tool categories discovered under tools/."""
    return sorted(_existing_tool_categories())


def get_global_tool_names() -> List[str]:
    """Compatibility alias for explicit core tools injected into plans."""
    return list(CORE_TOOL_NAMES)


def _resolve_loaded_tool_name(tool: Any) -> str:
    """Best-effort resolver for loaded tool callable/object names."""
    if hasattr(tool, "name"):
        value = getattr(tool, "name")
        if isinstance(value, str) and value.strip():
            return value.strip()
    if hasattr(tool, "__name__"):
        value = getattr(tool, "__name__")
        if isinstance(value, str) and value.strip():
            return value.strip()
    return type(tool).__name__


def _dedupe_loaded_tools_by_name(tools: List[Any]) -> List[Any]:
    """Deduplicate loaded tools by resolved name while preserving order."""
    seen: Set[str] = set()
    deduped: List[Any] = []
    for tool in tools:
        name = _resolve_loaded_tool_name(tool)
        if name in seen:
            continue
        seen.add(name)
        deduped.append(tool)
    return deduped


def _collect_plan_dependencies(nodes: List[ToolNode]) -> List[str]:
    """Collect deterministic dependency tokens from selected plan nodes."""
    deps: Set[str] = set()
    for node in nodes:
        for dep in node.dependencies:
            token = str(dep or "").strip()
            if token:
                deps.add(token)
    return sorted(deps)


def get_global_tools() -> List[Any]:
    """Deprecated fallback-era API.

    Runtime callers must use execution-plan construction plus
    `inject_core_tools(execution_plan)` and then execute the finalized plan.
    """
    raise DeprecationError(
        "get_global_tools() is deprecated and disabled at runtime. "
        "Core tools must be included only via inject_core_tools(execution_plan)."
    )


def get_global_tools_with_status() -> tuple[List[Any], List[str]]:
    """Deprecated fallback-era API.

    Core tool inclusion must flow through `inject_core_tools(execution_plan)`
    during pure planning, not runtime fallback loaders.
    """
    raise DeprecationError(
        "get_global_tools_with_status() is deprecated and disabled at runtime. "
        "Use inject_core_tools(execution_plan) in planning phase instead."
    )


def merge_with_global_tools(category_tools: List[Any]) -> List[Any]:
    """Deprecated fallback-era API.

    Runtime merging is disabled: all tool inclusion must be expressed in the
    execution plan via graph traversal + inject_core_tools.
    """
    raise DeprecationError(
        "merge_with_global_tools() is deprecated and disabled at runtime. "
        "All tool inclusion must flow through execution-plan construction only."
    )


def can_load_tool(tool_id: str) -> bool:
    """Metadata-only tool availability check used by planning phases.

    This function must remain pure:
    - no module imports
    - no registry mutations
    - no tool instantiation
    """
    normalized_tool_id = str(tool_id or "").strip()
    if not normalized_tool_id:
        return False

    graph_node = TOOL_GRAPH.nodes_by_id.get(normalized_tool_id)
    if graph_node is None:
        return False

    for meta in TOOL_REGISTRY._metadata.values():
        if meta.category == graph_node.category and meta.name == graph_node.name:
            return bool(meta.enabled)
    return False


def inject_core_tools(plan: ExecutionPlan) -> ExecutionPlan:
    """Inject required core tools into the plan with explicit trace output.

    Required injections:
    - reasoning tool
    - workspace tool
    - request_toolbox routing tool
    """
    existing_nodes = list(plan.tool_nodes)
    reasoning_trace = list(plan.reasoning_trace)

    nodes_by_name: Dict[str, ToolNode] = {
        node.name: node for node in TOOL_GRAPH.nodes_by_key.values()
    }
    seen_tool_ids: Set[str] = {f"{node.category}:{node.name}" for node in existing_nodes}
    unavailable_core_tools: List[str] = []
    injected_core_tools: List[str] = []

    for role, tool_name in CORE_TOOL_INJECTION.items():
        node = nodes_by_name.get(tool_name)
        if node is None:
            unavailable_core_tools.append(f"{role}:{tool_name}:missing_graph_node")
            continue

        tool_id = f"{node.category}:{node.name}"
        if tool_id in seen_tool_ids:
            injected_core_tools.append(tool_name)
            continue

        if not can_load_tool(tool_id):
            unavailable_core_tools.append(f"{role}:{tool_name}:not_loadable")
            continue

        existing_nodes.append(node)
        seen_tool_ids.add(tool_id)
        injected_core_tools.append(tool_name)

    state = plan.resolution_state
    if unavailable_core_tools and state == ToolResolutionState.SUCCESS:
        state = ToolResolutionState.DEGRADED

    if existing_nodes and state == ToolResolutionState.FAILED:
        state = ToolResolutionState.DEGRADED

    if not existing_nodes:
        state = ToolResolutionState.FAILED

    reasoning_trace.append(
        "core_injection="
        f"requested:{','.join(CORE_TOOL_NAMES)} "
        f"injected:{','.join(sorted(set(injected_core_tools))) or 'none'} "
        f"unavailable:{','.join(sorted(set(unavailable_core_tools))) or 'none'}"
    )

    return plan.model_copy(
        update={
            "tool_nodes": existing_nodes,
            "dependencies": _collect_plan_dependencies(existing_nodes),
            "resolution_state": state,
            "reasoning_trace": reasoning_trace,
        }
    )


def validate_execution_plan(plan: ExecutionPlan) -> ExecutionPlanValidationResult:
    """Validate plan deterministically without mutating the plan.

    Enforced invariants:
    - No duplicate tool IDs
    - No missing tool references
    - No empty tool list

    Dependency references are classified by kind in planner validator:
    - INTERNAL_TOOL
    - SYSTEM_BINARY
    - EXTERNAL_CAPABILITY
    """
    errors: List[str] = []
    validated_tool_ids: List[str] = []
    dependency_kinds: Dict[str, str] = {}
    unresolved_references: List[str] = []
    dependency_trace: List[str] = []

    if not plan.tool_nodes:
        errors.append("empty_tool_list")

    seen_tool_ids: Set[str] = set()

    for node in plan.tool_nodes:
        tool_id = f"{node.category}:{node.name}"
        if tool_id in seen_tool_ids:
            errors.append(f"duplicate_tool_id:{tool_id}")
            continue
        seen_tool_ids.add(tool_id)

        graph_node = TOOL_GRAPH.nodes_by_id.get(tool_id)
        if graph_node is None:
            errors.append(f"missing_tool_reference:{tool_id}")
            continue

        validated_tool_ids.append(tool_id)

    try:
        dependency_validation = validate_plan(plan, TOOL_GRAPH)
        dependency_trace.extend(dependency_validation.trace_logs)
        dependency_kinds.update(
            {
                dep_name: dep_kind.value
                for dep_name, dep_kind in dependency_validation.dependency_kinds.items()
            }
        )
        unresolved_references = list(dependency_validation.unresolved_references)
    except UnresolvedDependencyError:
        for dependency in plan.dependencies:
            token = str(dependency or "").strip()
            if not token:
                continue
            graph_hit = TOOL_GRAPH.nodes_by_key.get(token) or TOOL_GRAPH.nodes_by_id.get(token)
            if graph_hit is not None:
                dependency_kinds.setdefault(token, DependencyKind.INTERNAL_TOOL.value)
                continue
            if shutil.which(token):
                dependency_kinds[token] = DependencyKind.SYSTEM_BINARY.value
                dependency_trace.append(
                    f"Dependency [{token}] resolved as SYSTEM_BINARY via environment path."
                )
                continue
            if token.endswith("_access"):
                dependency_kinds[token] = DependencyKind.EXTERNAL_CAPABILITY.value
                continue
            unresolved_references.append(token)

    unresolved_references = sorted(set(unresolved_references))

    normalized_errors = sorted(set(errors))
    return ExecutionPlanValidationResult(
        is_valid=not normalized_errors,
        errors=normalized_errors,
        validated_tool_ids=sorted(set(validated_tool_ids)),
        unresolved_references=unresolved_references,
        dependency_kinds=dict(sorted(dependency_kinds.items(), key=lambda item: item[0])),
        dependency_trace=sorted(set(dependency_trace)),
    )


CATEGORY_SCORING_RULES: Dict[str, Dict[str, float]] = {
    "reconnaissance": {
        "scan": 2.0,
        "nmap": 3.0,
        "port": 2.0,
        "enumerate": 1.5,
        "shodan": 2.5,
        "ldap": 1.5,
        "netcat": 1.5,
    },
    "web": {
        "http": 2.0,
        "endpoint": 2.0,
        "headers": 2.0,
        "javascript": 1.5,
        "web": 1.0,
        "url": 1.5,
    },
    "command_and_control": {
        "c2": 3.0,
        "beacon": 2.5,
        "reverse shell": 3.0,
        "ssh": 1.5,
        "command and control": 3.0,
    },
    "exploitation": {
        "exploit": 2.5,
        "vulnerability": 2.0,
        "payload": 2.0,
        "shellcode": 2.5,
    },
    "lateral_movement": {
        "pivot": 2.0,
        "lateral": 2.0,
        "movement": 1.0,
        "remote": 1.0,
    },
    "privilege_scalation": {
        "privesc": 3.0,
        "sudo": 2.0,
        "root": 2.0,
        "escalate": 2.0,
    },
}


def resolve_category(prompt: str) -> ResolutionResult:
    """Resolve prompt -> category with deterministic scoring and explicit rationale."""
    available_categories = sorted(_existing_tool_categories())
    normalized = (prompt or "").strip().lower()
    tokens = set(re.findall(r"[a-z0-9_]+", normalized))

    if not available_categories:
        return ResolutionResult(
            primary_category="misc",
            secondary_categories=[],
            confidence_scores={"misc": 1.0},
            fallback_reason="no_categories",
        )

    raw_scores: Dict[str, float] = {category: 0.0 for category in available_categories}
    for category in available_categories:
        rules = CATEGORY_SCORING_RULES.get(category, {})
        score = 0.0
        for keyword, weight in rules.items():
            keyword_norm = str(keyword).strip().lower()
            if not keyword_norm:
                continue
            if " " in keyword_norm:
                if keyword_norm in normalized:
                    score += float(weight)
            elif keyword_norm in tokens:
                score += float(weight)
        raw_scores[category] = score

    max_raw_score = max(raw_scores.values()) if raw_scores else 0.0
    confidence_scores: Dict[str, float] = {
        category: (raw_scores[category] / max_raw_score if max_raw_score > 0 else 0.0)
        for category in sorted(raw_scores.keys())
    }

    ranked_categories = sorted(
        confidence_scores.items(),
        key=lambda item: (-item[1], item[0]),
    )

    threshold = 0.25
    fallback_reason: Optional[str] = None
    if not ranked_categories:
        primary_category = "misc"
        confidence_scores.setdefault(primary_category, 1.0)
        fallback_reason = "no_scores"
    elif ranked_categories[0][1] < threshold:
        if "misc" in confidence_scores:
            primary_category = "misc"
            fallback_reason = "low_confidence"
        else:
            primary_category = ranked_categories[0][0]
            fallback_reason = "low_confidence_misc_unavailable"
    else:
        primary_category = ranked_categories[0][0]

    confidence_scores.setdefault(primary_category, 0.0)
    secondary_categories = [
        category
        for category, score in ranked_categories
        if category != primary_category and score > 0
    ]

    return ResolutionResult(
        primary_category=primary_category,
        secondary_categories=secondary_categories,
        confidence_scores=confidence_scores,
        fallback_reason=fallback_reason,
    )


def _build_execution_plan_for_category(
    requested_category: str,
    *,
    trace: Optional[List[str]] = None,
) -> ExecutionPlan:
    """Build deterministic execution plan for a requested category token."""
    reasoning_trace = list(trace or [])
    available_categories = set(get_existing_tool_categories())
    resolved_category = str(requested_category or "").strip()
    resolution_state = ToolResolutionState.SUCCESS

    reasoning_trace.append(f"requested_category={resolved_category or '<empty>'}")

    if not resolved_category:
        resolution_state = ToolResolutionState.DEGRADED
        reasoning_trace.append("category_normalized=empty_category")
        resolved_category = "misc" if "misc" in available_categories else ""

    if resolved_category and resolved_category not in available_categories:
        resolution_state = ToolResolutionState.DEGRADED
        reasoning_trace.append(f"category_normalized=invalid_category:{resolved_category}")
        if "misc" in available_categories:
            resolved_category = "misc"
        elif available_categories:
            resolved_category = sorted(available_categories)[0]
        else:
            resolved_category = ""

    if not resolved_category:
        reasoning_trace.append("plan_state=FAILED reason=no_categories_available")
        return ExecutionPlan(
            resolved_category="",
            tool_nodes=[],
            dependencies=[],
            unresolved_references=[],
            resolution_state=ToolResolutionState.FAILED,
            reasoning_trace=reasoning_trace,
        )

    # Step 2: deterministic category subgraph activation from metadata graph.
    subgraph_nodes = list(graph_activate_tool_subgraph(TOOL_GRAPH, resolved_category))
    reasoning_trace.append(
        f"subgraph_activation=category:{resolved_category} node_count:{len(subgraph_nodes)}"
    )

    selected_nodes: List[ToolNode] = []
    unavailable_tools: List[str] = []
    seen_tool_ids: Set[str] = set()

    def _append_if_available(node: ToolNode) -> None:
        tool_id = f"{node.category}:{node.name}"
        if tool_id in seen_tool_ids:
            return

        if not can_load_tool(tool_id):
            unavailable_tools.append(node.name)
            return

        seen_tool_ids.add(tool_id)
        selected_nodes.append(node)

    # Step 3: validate tool availability for category subgraph nodes.
    for node in subgraph_nodes:
        _append_if_available(node)

    unavailable_tools = sorted(set(unavailable_tools))
    if unavailable_tools and resolution_state == ToolResolutionState.SUCCESS:
        resolution_state = ToolResolutionState.DEGRADED

    if not selected_nodes:
        resolution_state = ToolResolutionState.FAILED
        reasoning_trace.append("availability_check=FAILED reason=no_tools_available")
    else:
        reasoning_trace.append(
            f"availability_check=selected:{len(selected_nodes)} unavailable:{len(unavailable_tools)}"
        )

    reasoning_trace.append(f"plan_state={resolution_state.value}")

    # Step 4: emit final deterministic execution plan.
    return ExecutionPlan(
        resolved_category=resolved_category,
        tool_nodes=selected_nodes,
        dependencies=_collect_plan_dependencies(selected_nodes),
        unresolved_references=[],
        resolution_state=resolution_state,
        reasoning_trace=reasoning_trace,
    )


def build_execution_plan(prompt: str) -> ExecutionPlan:
    """Deterministically build pre-LLM execution plan from prompt text.

    Pipeline:
    1) resolve_category(prompt)
    2) activate_tool_subgraph(resolved_category)
    3) validate tool availability
    4) emit ExecutionPlan
    """
    resolution = resolve_category(prompt)
    ranked_scores = sorted(
        resolution.confidence_scores.items(),
        key=lambda item: (-item[1], item[0]),
    )
    score_preview = ",".join(f"{category}={score:.3f}" for category, score in ranked_scores)
    trace = [
        f"resolve_category=primary:{resolution.primary_category}",
        f"resolve_scores={score_preview}",
    ]
    if resolution.fallback_reason:
        trace.append(f"resolve_fallback={resolution.fallback_reason}")

    return _build_execution_plan_for_category(resolution.primary_category, trace=trace)


def build_execution_plan_for_category(category: str) -> ExecutionPlan:
    """Build deterministic pre-LLM execution plan from an explicit category."""
    normalized_category = str(category or "").strip()
    trace = [f"category_override={normalized_category or '<empty>'}"]
    return _build_execution_plan_for_category(normalized_category, trace=trace)


def build_final_execution_plan_for_category(category: str) -> ExecutionPlan:
    """Build a fully normalized execution plan in a pure planning phase.

    Phase A (PURE):
    - category normalization and scoring-derived routing
    - graph validation
    - explicit core tool injection

    This function must not import tool modules or mutate registry state.
    """
    plan = build_execution_plan_for_category(category)
    plan = inject_core_tools(plan)

    validation_result = validate_execution_plan(plan)
    if not validation_result.is_valid:
        raise ExecutionPlanValidationError(
            "Execution plan validation failed: " + ",".join(validation_result.errors)
        )

    normalized_state = plan.resolution_state
    if validation_result.unresolved_references and normalized_state == ToolResolutionState.SUCCESS:
        normalized_state = ToolResolutionState.DEGRADED

    plan = plan.model_copy(
        update={
            "resolution_state": normalized_state,
            "unresolved_references": validation_result.unresolved_references,
            "reasoning_trace": [
                *plan.reasoning_trace,
                "plan_graph_validation="
                f"validated:{len(validation_result.validated_tool_ids)} "
                f"errors:{'|'.join(validation_result.errors) or 'none'}",
                "plan_dependency_resolution="
                f"unresolved:{'|'.join(validation_result.unresolved_references) or 'none'}",
                *validation_result.dependency_trace,
            ]
        }
    )
    return plan


def execute_execution_plan(plan: ExecutionPlan, *, requested_category: str = "") -> ToolResolutionResult:
    """Execute a finalized plan by instantiating tools (impure phase).

    Phase B (IMPURE):
    - tool loading
    - runtime failure handling
    """
    validation_result = validate_execution_plan(plan)
    if not validation_result.is_valid:
        raise ExecutionPlanValidationError(
            "Execution plan validation failed before execution: "
            + ",".join(validation_result.errors)
        )

    loaded_tools: List[Any] = []
    unavailable_tools: List[str] = []
    metadata_key_by_identity: Dict[str, str] = {
        f"{meta.category}:{meta.name}": key
        for key, meta in TOOL_REGISTRY._metadata.items()
    }

    for node in plan.tool_nodes:
        tool_id = f"{node.category}:{node.name}"
        metadata_key = metadata_key_by_identity.get(tool_id)
        if metadata_key is None:
            unavailable_tools.append(node.name)
            continue
        try:
            loaded_tools.append(TOOL_REGISTRY._load_tool(metadata_key))
        except ValueError:
            unavailable_tools.append(node.name)

    state = plan.resolution_state
    if not loaded_tools:
        state = ToolResolutionState.FAILED

    reason: Optional[str] = None
    if state == ToolResolutionState.FAILED:
        reason = "no_tools_available"
    elif state == ToolResolutionState.DEGRADED:
        reason = "tool_unavailable_or_category_normalized"

    return ToolResolutionResult(
        state=state,
        requested_category=str(requested_category or "").strip(),
        resolved_category=plan.resolved_category,
        tools=_dedupe_loaded_tools_by_name(loaded_tools),
        unavailable_tools=sorted(set(unavailable_tools)),
        reason=reason,
    )


def resolve_tools_for_category(category: str) -> ToolResolutionResult:
    """Compatibility wrapper across pure planning + impure execution phases."""
    requested_category = str(category or "").strip()
    plan = build_final_execution_plan_for_category(requested_category)
    return execute_execution_plan(plan, requested_category=requested_category)


def detect_intent(prompt: str) -> str:
    """Compatibility wrapper returning only the primary scored category."""
    return resolve_category(prompt).primary_category


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
        self._tool_graph: ToolGraph = TOOL_GRAPH
        self._metadata: Dict[str, ToolMetadata] = {}
        self._instances: Dict[str, Any] = {}
        self._module_cache: Dict[str, Any] = {}
        self._tools_by_category: Dict[str, List[ToolMetadata]] = {}
        self._category_instances_cache: Dict[str, List[Any]] = {}
        self._category_unavailable_cache: Dict[str, List[str]] = {}
        self._discovery_time = datetime.utcnow().isoformat()

        self._discover_tools()
        self._log_initialization()

    def _discover_tools(self) -> None:
        """Scan and validate all tools in the catalog."""
        self._tools_by_category = {}
        self._category_instances_cache = {}
        self._category_unavailable_cache = {}

        def _record_tool(meta: ToolMetadata) -> None:
            bucket = self._tools_by_category.setdefault(meta.category, [])
            bucket.append(meta)

        for tool_key, node in self._tool_graph.nodes_by_key.items():
            try:
                phase_value = str(node.metadata.get("phase") or "").strip()
                if not phase_value:
                    raise KeyError("phase")

                requires_env_raw = node.metadata.get("requires_env", [])
                requires_env = [
                    str(value)
                    for value in requires_env_raw
                    if isinstance(value, str) and value.strip()
                ] if isinstance(requires_env_raw, list) else []

                if not _check_env_requirements(requires_env):
                    disabled_reason = (
                        f"Missing environment variable(s): {', '.join(requires_env)}"
                    )
                    metadata = ToolMetadata(
                        name=node.name,
                        module=node.module_path,
                        category=node.category,
                        phase=phase_value,
                        dependencies=list(node.dependencies),
                        description=str(node.metadata.get("description", "") or ""),
                        enabled=False,
                        disabled_reason=disabled_reason,
                        requires_env=requires_env,
                    )
                    self._metadata[tool_key] = metadata
                    _record_tool(metadata)
                    continue

                dependencies = list(node.dependencies)
                missing_deps = [d for d in dependencies if not _check_dependency(d)]

                if missing_deps:
                    disabled_reason = f"Missing dependencies: {', '.join(missing_deps)}"
                    metadata = ToolMetadata(
                        name=node.name,
                        module=node.module_path,
                        category=node.category,
                        phase=phase_value,
                        dependencies=dependencies,
                        description=str(node.metadata.get("description", "") or ""),
                        enabled=False,
                        disabled_reason=disabled_reason,
                        requires_env=requires_env,
                    )
                else:
                    metadata = ToolMetadata(
                        name=node.name,
                        module=node.module_path,
                        category=node.category,
                        phase=phase_value,
                        dependencies=dependencies,
                        description=str(node.metadata.get("description", "") or ""),
                        enabled=True,
                        disabled_reason=None,
                        requires_env=requires_env,
                    )

                self._metadata[tool_key] = metadata
                _record_tool(metadata)
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
            module_path = metadata.module
            module = self._module_cache.get(module_path)
            if module is None:
                _jit_trace(f"Importing tool module: {module_path}")
                module = importlib.import_module(module_path)
                self._module_cache[module_path] = module
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
        except Exception as e:
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
        """Get a tool by name via category JIT loading path."""
        target_meta: Optional[ToolMetadata] = None
        for meta in self._metadata.values():
            if meta.name == tool_name:
                target_meta = meta
                break

        if target_meta is None:
            raise ValueError(f"Tool not found: {tool_name}")

        loaded_category_tools = self.get_tools_by_category(target_meta.category)
        for tool in loaded_category_tools:
            resolved_name = getattr(tool, "name", None) or getattr(tool, "__name__", "")
            if str(resolved_name).strip() == tool_name:
                return tool

        raise ValueError(f"Tool '{tool_name}' is unavailable in category '{target_meta.category}'")

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

    def get_tools_by_category(self, category: str) -> List[Any]:
        """Lazily load tools for one category only and cache the result list."""
        loaded_tools, _ = self.get_tools_by_category_with_status(category)
        return loaded_tools

    def get_tools_by_category_with_status(self, category: str) -> tuple[List[Any], List[str]]:
        """Lazily load tools for category and return (loaded, unavailable_tool_names)."""
        if category in self._category_instances_cache:
            _jit_trace(
                f"Category cache hit: {category} ({len(self._category_instances_cache[category])} tools)"
            )
            return (
                self._category_instances_cache[category],
                self._category_unavailable_cache.get(category, []),
            )

        _jit_trace(f"Category cache miss: {category}")

        loaded_tools: List[Any] = []
        unavailable_tools: List[str] = []
        activated_nodes = graph_activate_tool_subgraph(self._tool_graph, category)
        for node in activated_nodes:
            tool_key = next(
                (
                    key
                    for key, item in self._metadata.items()
                    if item.name == node.name and item.module == node.module_path
                ),
                None,
            )
            if tool_key is None:
                unavailable_tools.append(node.name)
                continue
            meta = self._metadata.get(tool_key)
            if meta is None or not meta.enabled:
                unavailable_tools.append(node.name)
                continue
            try:
                loaded_tools.append(self._load_tool(tool_key))
            except ValueError:
                unavailable_tools.append(node.name)
                continue

        self._category_instances_cache[category] = loaded_tools
        self._category_unavailable_cache[category] = sorted(set(unavailable_tools))
        _jit_trace(f"Category cached: {category} ({len(loaded_tools)} tools)")
        return loaded_tools, self._category_unavailable_cache[category]

    def get_tool_metadata_by_category(
        self, category: str, agent_role: Optional[str] = None
    ) -> List[ToolMetadata]:
        """Get tool metadata by derived category without importing tool modules."""
        tools = [
            meta
            for meta in self._tools_by_category.get(category, [])
            if meta.enabled
            and (
                agent_role is None
                or ToolAuthorizationManager.is_phase_allowed(agent_role, meta.phase)
            )
        ]
        return sorted(tools, key=lambda t: (t.phase, t.name))

    def get_tools_grouped_by_category(
        self, agent_role: Optional[str] = None
    ) -> Dict[str, List[ToolMetadata]]:
        """Return enabled tools grouped by derived filesystem category."""
        grouped: Dict[str, List[ToolMetadata]] = {}
        for category, metas in self._tools_by_category.items():
            eligible = [
                meta
                for meta in metas
                if meta.enabled
                and (
                    agent_role is None
                    or ToolAuthorizationManager.is_phase_allowed(agent_role, meta.phase)
                )
            ]
            if eligible:
                grouped[category] = sorted(eligible, key=lambda t: (t.phase, t.name))
        return dict(sorted(grouped.items(), key=lambda item: item[0]))

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

        category_breakdown: Dict[str, int] = {}
        for meta in enabled_tools:
            category_breakdown[meta.category] = category_breakdown.get(meta.category, 0) + 1

        return ToolRegistry(
            total_tools=len(self._metadata),
            available_tools=len(enabled_tools),
            disabled_tools=len(disabled_tools),
            phase_breakdown=phase_breakdown,
            category_breakdown=dict(sorted(category_breakdown.items(), key=lambda item: item[0])),
            tools=enabled_tools,
        )

    def disable_tool(self, tool_name: str, reason: str) -> bool:
        """Manually disable a tool."""
        for key, meta in self._metadata.items():
            if meta.name == tool_name:
                self._metadata[key] = meta.copy(
                    update={"enabled": False, "disabled_reason": reason}
                )
                self._category_instances_cache.pop(meta.category, None)
                self._category_unavailable_cache.pop(meta.category, None)
                return True
        return False

    def enable_tool(self, tool_name: str) -> bool:
        """Re-enable a disabled tool."""
        for key, meta in self._metadata.items():
            if meta.name == tool_name:
                self._metadata[key] = meta.copy(
                    update={"enabled": True, "disabled_reason": None}
                )
                self._category_instances_cache.pop(meta.category, None)
                self._category_unavailable_cache.pop(meta.category, None)
                return True
        return False


# =============================================================================
# Module-level Singleton Access
# =============================================================================

TOOL_REGISTRY = CerberusToolRegistry()


def get_tool_registry() -> CerberusToolRegistry:
    """Get the global tool registry singleton."""
    return TOOL_REGISTRY


def get_tool_graph() -> ToolGraph:
    """Get the deterministic metadata-only tool graph."""
    return TOOL_GRAPH


def activate_tool_subgraph(category: str) -> List[ToolNode]:
    """Activate a deterministic category subgraph from metadata graph."""
    return list(graph_activate_tool_subgraph(TOOL_GRAPH, category))


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
        "category_breakdown": status.category_breakdown,
        "discovery_time": TOOL_REGISTRY.discovery_time,
    }


def get_tools_by_category(category: str) -> List[Any]:
    """Get lazily-loaded tools for one graph-activated category."""
    return TOOL_REGISTRY.get_tools_by_category(category)


def get_tool_metadata_by_category(
    category: str, agent_role: Optional[str] = None
) -> List[ToolMetadata]:
    """Get metadata for tools in a category without importing tool modules."""
    return TOOL_REGISTRY.get_tool_metadata_by_category(category, agent_role=agent_role)


def get_tools_grouped_by_category(
    agent_role: Optional[str] = None,
) -> Dict[str, List[ToolMetadata]]:
    """Get enabled tools grouped by graph-derived categories."""
    return TOOL_REGISTRY.get_tools_grouped_by_category(agent_role=agent_role)
