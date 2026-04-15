"""
Secure Agent Discovery Tool for Cerberus AI.

This module provides a professional, audit-logged way for agents to discover
and understand each other's capabilities within the framework, with permission
scoping to prevent lateral discovery attacks.

Architecture:
- AgentInfoTool: function_tool decorator-based FunctionTool for agent discovery
- AgentInfoRequest: Pydantic validation for agent_name parameter
- AgentInfo: Structured response with identity, capabilities, tools, state
- Permission Scoping: Visibility filter prevents unauthorized discovery
- Forensic Logging: All discovery events logged to workspace audit trail
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from pydantic import BaseModel, Field, ValidationError, field_validator

# Framework dependencies
try:
    from cerberus.memory.logic import clean
except ImportError:
    clean = lambda x: x

try:
    from cerberus.repl.ui.logging import get_cerberus_logger, LOG_AUDIT
except ImportError:
    get_cerberus_logger = None
    LOG_AUDIT = "AUDIT"

try:
    from cerberus.repl.commands.config import CONFIG_STORE
except ImportError:
    CONFIG_STORE = None

try:
    from cerberus.tools.workspace import get_project_space
except ImportError:
    get_project_space = None

try:
    from cerberus.sdk.agents.simple_agent_manager import AGENT_MANAGER
except ImportError:
    AGENT_MANAGER = None

try:
    from cerberus.repl.commands.agent import AgentRegistry, AgentConfig
except ImportError:
    AgentRegistry = None
    AgentConfig = None

try:
    from cerberus.sdk.agents.tool import function_tool
except ImportError:
    function_tool = None


# =============================================================================
# Data Models
# =============================================================================

class AgentInfoRequest(BaseModel):
    """Validated request for agent information discovery."""

    agent_name: str = Field(
        ...,
        description="Name or key of the agent to discover",
        min_length=1,
        max_length=256,
    )
    requester_id: Optional[str] = Field(
        default=None,
        description="ID of agent making the request (for permission scoping)",
    )
    include_internal: bool = Field(
        default=False,
        description="Whether to include internal/system-only agents",
    )

    @field_validator("agent_name")
    @classmethod
    def validate_agent_name(cls, v: str) -> str:
        """Validate agent name format and content."""
        v = v.strip()
        if not v or len(v) == 0:
            raise ValueError("agent_name cannot be empty or whitespace-only")
        if any(c in v for c in ["<", ">", '"', "'"]):
            raise ValueError("agent_name contains invalid characters")
        return v


class ToolAccessInfo(BaseModel):
    """Information about a tool that an agent has access to."""

    name: str
    category: str = "general"  # general, security, admin, restricted
    description: str = ""

    class Config:
        frozen = True


class AgentCapability(BaseModel):
    """Structured representation of an agent's capability."""

    name: str
    domain: str = "general"  # security, analysis, reporting, automation, etc.
    specialization: str = ""
    confidence: float = Field(
        default=1.0, ge=0.0, le=1.0
    )  # Confidence level of capability

    class Config:
        frozen = True


class AgentStatus(BaseModel):
    """Current runtime status of an agent."""

    state: str = "offline"  # offline, idle, active, busy, error
    since: Optional[str] = None  # ISO timestamp
    last_interaction: Optional[str] = None  # ISO timestamp
    message: Optional[str] = None

    class Config:
        frozen = True


class AgentIdentity(BaseModel):
    """Core identity information for an agent."""

    key: str
    name: str
    version: str = "1.0"
    persona: Optional[str] = None
    description: str = ""

    class Config:
        frozen = True


class AgentInfo(BaseModel):
    """Complete structured information about an agent for LLM consumption."""

    identity: AgentIdentity
    capabilities: List[AgentCapability] = Field(default_factory=list)
    tool_access: List[ToolAccessInfo] = Field(default_factory=list)
    status: AgentStatus = Field(default_factory=AgentStatus)
    collaboration_partners: List[str] = Field(
        default_factory=list, description="Agent keys this agent can collaborate with"
    )
    max_parallel: int = Field(default=1, description="Max parallel tasks this agent supports")
    requires_approval: bool = Field(default=False, description="Whether tool use requires approval")
    security_level: str = Field(
        default="standard",
        description="security level: public, standard, restricted, internal",
    )

    def to_llm_text(self) -> str:
        """Format as LLM-readable text for agent comprehension."""
        lines = [
            f"=== Agent Information: {self.identity.name} ===",
            f"Key: {self.identity.key}",
            f"Version: {self.identity.version}",
            f"Status: {self.status.state}",
            "",
        ]

        if self.identity.persona:
            lines.append(f"Persona: {self.identity.persona}")
            lines.append("")

        if self.identity.description:
            lines.append(f"Description: {self.identity.description}")
            lines.append("")

        if self.capabilities:
            lines.append("Capabilities:")
            for cap in self.capabilities:
                domain_label = f"[{cap.domain}]" if cap.domain != "general" else ""
                lines.append(f"  - {cap.name} {domain_label}")
                if cap.specialization:
                    lines.append(f"    Specialization: {cap.specialization}")
            lines.append("")

        if self.tool_access:
            lines.append("Tool Access:")
            by_category: Dict[str, List[ToolAccessInfo]] = {}
            for tool in self.tool_access:
                if tool.category not in by_category:
                    by_category[tool.category] = []
                by_category[tool.category].append(tool)

            for category in sorted(by_category.keys()):
                tools = by_category[category]
                lines.append(f"  [{category.upper()}]")
                for tool in tools:
                    lines.append(f"    - {tool.name}" + (f": {tool.description}" if tool.description else ""))
            lines.append("")

        if self.collaboration_partners:
            lines.append(f"Can Collaborate With: {', '.join(self.collaboration_partners)}")
            lines.append("")

        lines.append(f"Max Parallel Tasks: {self.max_parallel}")
        lines.append(f"Security Level: {self.security_level}")

        if self.requires_approval:
            lines.append("⚠ Tool Use Requires Approval")

        return "\n".join(lines)

    class Config:
        frozen = True


# =============================================================================
# Permission Scoping & Visibility Filter
# =============================================================================

class PermissionManager:
    """Manages agent-to-agent permission scoping for discovery."""

    # Define default collaboration groups
    COLLABORATION_GROUPS = {
        "security": ["red_team", "blue_team", "analyzer"],
        "analysis": ["analyzer", "researcher", "reporter"],
        "automation": ["automation", "executor", "scheduler"],
        "system": ["supervisor", "orchestrator"],
    }

    @staticmethod
    def get_allowed_agents(requester_key: str) -> Set[str]:
        """
        Get set of agent keys that the requester is allowed to discover.

        A requester can discover:
        1. Agents in the same collaboration group
        2. Public system agents
        3. Itself

        Args:
            requester_key: The key of the requesting agent

        Returns:
            Set of agent keys the requester is allowed to see
        """
        allowed = {requester_key}  # Always allowed to query self

        # Find which groups this agent belongs to
        for group, members in PermissionManager.COLLABORATION_GROUPS.items():
            if requester_key in members:
                # Agent belongs to this group, can see all group members
                allowed.update(members)

        # Add public system agents
        allowed.update(["system", "supervisor", "help"])

        return allowed

    @staticmethod
    def is_discovery_permitted(requester_key: Optional[str], target_key: str) -> bool:
        """
        Check if requester is allowed to discover information about target.

        Args:
            requester_key: The key of the requesting agent (None = no restrictions)
            target_key: The key of the target agent to discover

        Returns:
            True if discovery is permitted, False otherwise
        """
        if requester_key is None:
            return True  # No requester restriction means full access

        allowed = PermissionManager.get_allowed_agents(requester_key)
        return target_key in allowed


# =============================================================================
# Agent Discovery Engine
# =============================================================================

class AgentDiscoveryEngine:
    """Core engine for discovering agent information with auditing."""

    def __init__(self):
        self._registry: Optional[Any] = None
        self._logger = None
        self._current_agent_key: Optional[str] = None

    def set_registry(self, registry: Any) -> None:
        """Set the agent registry for lookups."""
        self._registry = registry

    def set_logger(self, logger: Any) -> None:
        """Set the forensic logger for audit events."""
        self._logger = logger

    def set_current_agent(self, agent_key: str) -> None:
        """Set current executing agent for logging context."""
        self._current_agent_key = agent_key

    async def discover(self, request: AgentInfoRequest) -> AgentInfo:
        """
        Discover information about an agent with permission scoping.

        Args:
            request: Validated discovery request

        Returns:
            AgentInfo with visible information

        Raises:
            ValueError: If agent not found or access denied
        """
        target_key = request.agent_name

        # Permission check
        if not PermissionManager.is_discovery_permitted(request.requester_id, target_key):
            await self._log_discovery_event(
                requester=request.requester_id or "unknown",
                target=target_key,
                status="denied",
                reason="permission_scope_violation",
            )
            raise ValueError(
                f"Agent '{request.requester_id}' is not permitted to discover '{target_key}'"
            )

        # Lookup agent config
        if not self._registry:
            await self._log_discovery_event(
                requester=request.requester_id or "unknown",
                target=target_key,
                status="error",
                reason="no_registry",
            )
            raise ValueError("Agent registry not available")

        config = self._registry.get(target_key)
        if not config:
            await self._log_discovery_event(
                requester=request.requester_id or "unknown",
                target=target_key,
                status="not_found",
            )
            raise ValueError(f"Agent '{target_key}' not found in registry")

        # Build agent info
        agent_info = self._build_agent_info(config, request)

        # Log successful discovery
        await self._log_discovery_event(
            requester=request.requester_id or "unknown",
            target=target_key,
            status="success",
        )

        return agent_info

    def _build_agent_info(self, config: Any, request: AgentInfoRequest) -> AgentInfo:
        """Build structured agent info from config."""
        # Identity
        identity = AgentIdentity(
            key=config.key,
            name=config.name or config.key,
            version="1.0",
            persona=config.persona,
            description=f"An agent with capabilities: {', '.join(config.capabilities) if config.capabilities else 'general'}",
        )

        # Capabilities
        capabilities = [
            AgentCapability(
                name=cap,
                domain="security" if "security" in cap.lower() or "attack" in cap.lower() else "general",
                confidence=0.9,
            )
            for cap in config.capabilities
        ]

        # Tool access (from required_tools)
        tool_access = [
            ToolAccessInfo(
                name=tool,
                category="restricted" if tool.startswith("admin_") else "general",
                description=f"Access to {tool} tool",
            )
            for tool in config.required_tools
        ]

        # Status (get from AGENT_MANAGER if available)
        status = self._get_agent_status(config.key)

        # Collaboration partners (from permission groups)
        collaboration_partners = list(
            PermissionManager.get_allowed_agents(config.key) - {config.key}
        )

        return AgentInfo(
            identity=identity,
            capabilities=capabilities,
            tool_access=tool_access,
            status=status,
            collaboration_partners=collaboration_partners,
            max_parallel=1,
            requires_approval=any("admin" in t for t in config.required_tools),
            security_level="standard" if "security" in config.key.lower() else "public",
        )

    def _get_agent_status(self, agent_key: str) -> AgentStatus:
        """Get current runtime status of agent."""
        try:
            if AGENT_MANAGER:
                agent = AGENT_MANAGER.get_active_agent()
                if agent and hasattr(agent, "key") and agent.key == agent_key:
                    return AgentStatus(
                        state="active",
                        since=datetime.now().isoformat(),
                    )
        except Exception:
            pass

        return AgentStatus(state="offline")

    async def _log_discovery_event(
        self,
        requester: str,
        target: str,
        status: str,
        reason: Optional[str] = None,
    ) -> None:
        """Log discovery event to forensic audit trail."""
        if not self._logger and get_cerberus_logger:
            self._logger = get_cerberus_logger()

        if self._logger:
            message = f"Agent discovery: {requester} -> {target} [{status}]"
            if reason:
                message += f" ({reason})"

            try:
                self._logger.audit(
                    message,
                    discovery_event=True,
                    requester=requester,
                    target=target,
                    status=status,
                    reason=reason or "",
                    timestamp=datetime.now().isoformat(),
                )
            except Exception:
                pass  # Non-blocking logging


# =============================================================================
# Global Discovery Engine & Tool Function
# =============================================================================

_DISCOVERY_ENGINE = AgentDiscoveryEngine()


async def agent_info_handler(agent_name: str, requester_id: Optional[str] = None) -> str:
    """
    Discover and return information about an agent.

    This tool allows agents to safely discover each other's capabilities
    with permission scoping to prevent lateral attacks.

    Args:
        agent_name: Name or key of the agent to discover
        requester_id: ID of agent making request (for permission scoping)

    Returns:
        LLM-readable formatted agent information
    """
    try:
        # Validate input
        request = AgentInfoRequest(
            agent_name=agent_name,
            requester_id=requester_id,
            include_internal=False,
        )
    except ValidationError as e:
        error_msg = f"Invalid agent discovery request: {e.errors()[0]['msg']}"
        return json.dumps({"error": error_msg, "valid": False})

    try:
        # Initialize registry if needed
        if not _DISCOVERY_ENGINE._registry and AgentRegistry:
            registry = AgentRegistry()
            registry.load()  # Load from default path
            _DISCOVERY_ENGINE.set_registry(registry)

        # Discover agent info
        agent_info = await _DISCOVERY_ENGINE.discover(request)

        # Return LLM-readable format
        return agent_info.to_llm_text()

    except ValueError as e:
        return json.dumps({"error": str(e), "valid": False})
    except Exception as e:
        error_msg = f"Agent discovery error: {str(e)}"
        return json.dumps({"error": error_msg, "valid": False})


# =============================================================================
# FunctionTool Registration
# =============================================================================

if function_tool:
    @function_tool
    async def agent_info(agent_name: str, requester_id: Optional[str] = None) -> str:
        """
        Discover another agent's capabilities, tools, and current status.

        Use this tool to learn about other agents you can collaborate with.
        Returns detailed information including capabilities, tool access,
        current status, and collaboration partners.

        Permission Scoping:
        - Agents can only discover info about agents in their collaboration group
        - Attempts to discover unauthorized agents are logged and denied
        - All discovery events are audited for security

        Args:
            agent_name: The name or key of the agent to discover (e.g., "red_team", "analyzer")
            requester_id: Your agent ID (used for permission scoping; usually auto-filled)

        Returns:
            Formatted agent information with identity, capabilities, tools, and status.
            If discovery is denied, returns an error message.

        Examples:
            - agent_info(agent_name="analyzer")
            - agent_info(agent_name="researcher", requester_id="security_agent")
        """
        return await agent_info_handler(agent_name, requester_id)


# =============================================================================
# Public API
# =============================================================================

def get_discovery_engine() -> AgentDiscoveryEngine:
    """Get the global agent discovery engine."""
    return _DISCOVERY_ENGINE


def initialize_discovery(registry: Optional[Any] = None) -> None:
    """
    Initialize the agent discovery engine with a registry.

    Args:
        registry: AgentRegistry instance (optional, will load default if not provided)
    """
    if registry:
        _DISCOVERY_ENGINE.set_registry(registry)
    elif AgentRegistry:
        try:
            reg = AgentRegistry()
            reg.load()
            _DISCOVERY_ENGINE.set_registry(reg)
        except Exception:
            pass

    if get_cerberus_logger:
        try:
            _DISCOVERY_ENGINE.set_logger(get_cerberus_logger())
        except Exception:
            pass


# Backward compatibility: keep the original _get_agent_token_info function
def _get_agent_token_info() -> Dict:
    """Get current agent's token information from the active model instance.

    Returns a dict with keys matching the previous implementation so
    existing call sites need no changes.
    """
    try:
        from cerberus.sdk.agents.models.openai_chatcompletions import get_current_active_model

        model = get_current_active_model()

        if model:
            if hasattr(model, "get_full_display_name"):
                display_name = model.get_full_display_name()
            elif hasattr(model, "agent_name"):
                if hasattr(model, "agent_id") and model.agent_id:
                    display_name = f"{model.agent_name} [{model.agent_id}]"
                else:
                    display_name = model.agent_name
            else:
                display_name = "Agent"

            return {
                "agent_name": display_name,
                "agent_id": getattr(model, "agent_id", None),
                "interaction_counter": getattr(model, "interaction_counter", 0),
                "total_input_tokens": getattr(model, "total_input_tokens", 0),
                "total_output_tokens": getattr(model, "total_output_tokens", 0),
                "total_reasoning_tokens": getattr(model, "total_reasoning_tokens", 0),
                "total_cost": getattr(model, "total_cost", 0.0),
            }

        from cerberus.sdk.agents.models.openai_chatcompletions import ACTIVE_MODEL_INSTANCES

        if ACTIVE_MODEL_INSTANCES:
            latest_key = max(ACTIVE_MODEL_INSTANCES.keys(), key=lambda x: x[1])
            model_ref = ACTIVE_MODEL_INSTANCES[latest_key]

            if model_ref:
                return {
                    "agent_name": getattr(model_ref, "agent_name", "Unknown"),
                    "agent_id": getattr(model_ref, "agent_id", None),
                    "interaction_counter": getattr(model_ref, "interaction_counter", 0),
                    "total_input_tokens": getattr(model_ref, "total_input_tokens", 0),
                    "total_output_tokens": getattr(model_ref, "total_output_tokens", 0),
                    "total_reasoning_tokens": getattr(model_ref, "total_reasoning_tokens", 0),
                    "total_cost": getattr(model_ref, "total_cost", 0.0),
                }
    except Exception:
        pass

    return {
        "agent_name": "Unknown",
        "agent_id": None,
        "interaction_counter": 0,
        "total_input_tokens": 0,
        "total_output_tokens": 0,
        "total_reasoning_tokens": 0,
        "total_cost": 0.0,
    }

