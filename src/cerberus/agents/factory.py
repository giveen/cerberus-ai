"""Cerberus agent factory.

This module provides a commercial-grade factory for dynamic, lazy, and
safety-aware agent instantiation.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
import importlib
import logging
import os
from pathlib import Path
import pkgutil
import re
import threading
from typing import Any, Dict, Iterable, Mapping, MutableMapping, Optional, Sequence, Type
from uuid import uuid4

from openai import AsyncOpenAI

from cerberus.agents.registry import AgentRegistry as PersonaAgentRegistry
from cerberus.sdk.agents import Agent, FunctionTool, OpenAIChatCompletionsModel, function_tool
from cerberus.tools.all_tools import get_tool, get_tools_for_agent
from cerberus.tools.reconnaissance.filesystem import PathGuard
from cerberus.tools.workspace import get_project_space
from cerberus.util.config import get_effective_api_base, get_effective_api_key, get_effective_model
from cerberus.util import create_system_prompt_renderer, load_prompt_template

try:
    from cerberus.repl.ui.logging import get_cerberus_logger
except Exception:  # pragma: no cover - optional logger
    get_cerberus_logger = None


def _resolve_factory_api_key() -> str:
    """Resolve runtime API key without shipping hardcoded placeholders."""
    local_key = os.getenv("CERBERUS_LOCAL_KEY", "").strip()
    api_key = get_effective_api_key(default=local_key)
    if api_key:
        return api_key
    raise RuntimeError(
        "No API key configured. Set CERBERUS_API_KEY (or CERBERUS_LOCAL_KEY for local-only runtime)."
    )


@dataclass(frozen=True)
class WorkspacePaths:
    """Workspace paths injected into every agent context."""

    repo_root: Path
    active_workspace: Path
    prompts_root: Path
    evidence_root: Path
    reports_root: Path


@dataclass
class CerebroRedaction:
    """System-wide redaction engine used for context-safe rendering."""

    replacements: Mapping[re.Pattern[str], str] = field(
        default_factory=lambda: {
            re.compile(r"(?i)\\b(api[_-]?key|token|password|secret)\\s*[:=]\\s*[^\\s]+"):
                r"\\1=[REDACTED_SECRET]",
            re.compile(r"(?i)\\b[a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{2,}\\b"):
                "[REDACTED_EMAIL]",
        }
    )

    def scrub(self, value: str) -> str:
        text = value
        for pattern, replacement in self.replacements.items():
            text = pattern.sub(replacement, text)
        return text


@dataclass(frozen=True)
class CerebroToolbox:
    """Role-filtered toolbox containing callable tool handles."""

    role: str
    tool_functions: Mapping[str, Any]

    def as_list(self) -> list[Any]:
        return list(self.tool_functions.values())


@dataclass(frozen=True)
class CerebroContext:
    """Injected context with workspace, security, and runtime metadata."""

    agent_uuid: str
    role: str
    workspace: WorkspacePaths
    toolbox: CerebroToolbox
    redaction: CerebroRedaction
    path_guard: PathGuard
    metadata: Mapping[str, Any]


@dataclass(frozen=True)
class AgentDiscoveryRecord:
    """Static discovery output created without importing agent modules."""

    role: str
    module_path: str
    preferred_export: str
    prompt_candidates: tuple[str, ...]


class CerebroBaseAgentProvider(ABC):
    """Type-safe provider contract for lazy agent materialization."""

    role: str
    module_path: str
    preferred_export: str

    @abstractmethod
    def load_base_agent(self) -> Agent:
        """Load and return the base agent template."""


class LazyModuleAgentProvider(CerebroBaseAgentProvider):
    """Provider that imports module only at spawn time."""

    role = "generic"
    module_path = ""
    preferred_export = ""

    def load_base_agent(self) -> Agent:
        module = importlib.import_module(self.module_path)

        if self.preferred_export:
            candidate = getattr(module, self.preferred_export, None)
            if isinstance(candidate, Agent):
                return candidate

        agent_candidates: list[tuple[str, Agent]] = []
        for attr_name in dir(module):
            if attr_name.startswith("_"):
                continue
            attr = getattr(module, attr_name)
            if isinstance(attr, Agent):
                agent_candidates.append((attr_name, attr))

        if not agent_candidates:
            raise RuntimeError(f"No Agent instance found in module '{self.module_path}'")

        agent_candidates.sort(key=lambda item: (0 if item[0].endswith("_agent") else 1, item[0]))
        return agent_candidates[0][1]


class CerebroAgentFactory:
    """CALM factory for secure lifecycle management of specialized agents."""

    _MODULE_ROLE_ALIASES: Mapping[str, str] = {
        "web_pentester": "web_pentester",
        "dfir": "forensic_analyst",
        "blue_teamer": "blue_teamer",
        "red_teamer": "red_teamer",
        "codeagent": "code_synthesis_engine",
        "bug_bounter": "vulnerability_researcher",
        "network_traffic_analyzer": "network_traffic_analyzer",
        "memory_analysis_agent": "memory_analyst",
        "android_sast_agent": "android_sast_auditor",
        "wifi_security_tester": "wifi_security_tester",
        "subghz_sdr_agent": "subghz_specialist",
    }

    _SINGLETON_DEFAULTS = {
        "code_synthesis_engine",
        "codeagent",
    }

    _SYSTEM_TOOL_ROLE_MAP: Mapping[str, str] = {
        "web_pentester": "researcher",
        "forensic_analyst": "analyzer",
        "blue_teamer": "blue_team",
        "red_teamer": "red_team",
        "code_synthesis_engine": "executor",
        "vulnerability_researcher": "researcher",
        "network_traffic_analyzer": "analyzer",
        "memory_analyst": "analyzer",
        "android_sast_auditor": "analyzer",
        "wifi_security_tester": "researcher",
        "subghz_specialist": "researcher",
        "generic_intelligence": "supervisor",
    }

    _ROLE_ALIASES: Mapping[str, str] = {
        "redteam_agent": "red_teamer",
        "red_team_agent": "red_teamer",
        "redteam": "red_teamer",
        "blue_team_agent": "blue_teamer",
        "generic": "generic_intelligence",
    }

    def __init__(
        self,
        *,
        workspace_root: str | Path | None = None,
        singleton_roles: Optional[Iterable[str]] = None,
    ) -> None:
        self._lock = threading.RLock()
        self._logger = get_cerberus_logger() if get_cerberus_logger else logging.getLogger(__name__)

        self._workspace_paths = self._build_workspace_paths(workspace_root)
        self._redaction = CerebroRedaction()
        self._path_guard = PathGuard(self._workspace_paths.repo_root, self._pathguard_audit)
        self._persona_registry = PersonaAgentRegistry(
            prompts_root=self._workspace_paths.prompts_root,
            logger=self._logger,
        )

        self._records: Dict[str, AgentDiscoveryRecord] = {}
        self._providers: Dict[str, Type[CerebroBaseAgentProvider]] = {}
        self._singletons: Dict[str, Agent] = {}
        self._live_agents: Dict[str, Agent] = {}
        self._agent_roles_by_uuid: Dict[str, str] = {}
        self._last_missing_persona_paths: Dict[str, tuple[str, ...]] = {}

        self._singleton_roles = set(self._SINGLETON_DEFAULTS)
        if singleton_roles:
            self._singleton_roles.update(self._normalize_role(role) for role in singleton_roles)

        self._discover_agents()

    @property
    def roles(self) -> list[str]:
        return sorted(self._providers.keys())

    @property
    def workspace_paths(self) -> WorkspacePaths:
        return self._workspace_paths

    def register_provider(self, role: str, provider_cls: Type[CerebroBaseAgentProvider]) -> None:
        """Register a provider class for a role with ABC type-safety checks."""
        if not isinstance(provider_cls, type) or not issubclass(provider_cls, CerebroBaseAgentProvider):
            raise TypeError("provider_cls must be a subclass of CerebroBaseAgentProvider")
        normalized = self._normalize_role(role)
        self._providers[normalized] = provider_cls

    def create_agent(
        self,
        role: str,
        *,
        user_name: Optional[str] = None,
        target_ip: Optional[str] = None,
        project_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        model_override: Optional[str] = None,
        custom_name: Optional[str] = None,
        allow_subghz: bool = False,
        extra_tools: Optional[Sequence[str]] = None,
        singleton: Optional[bool] = None,
    ) -> Agent:
        """Spawn a role agent with hydrated prompt and injected runtime context."""
        normalized_role = self._normalize_role(role)
        use_singleton = normalized_role in self._singleton_roles if singleton is None else singleton

        with self._lock:
            if use_singleton and normalized_role in self._singletons:
                existing = self._singletons[normalized_role]
                existing_uuid = getattr(existing, "cerebro_agent_uuid", "unknown")
                self._log_lifecycle_event("spawn_reuse", normalized_role, existing_uuid, {"singleton": True})
                return existing

        provider_cls = self._providers.get(normalized_role)
        if provider_cls is None:
            missing_paths = self._collect_missing_persona_paths(normalized_role)
            return self._fallback_generic(
                role=normalized_role,
                reason="role_not_discovered",
                user_name=user_name,
                target_ip=target_ip,
                project_id=project_id,
                metadata=metadata,
                model_override=model_override,
                custom_name=custom_name,
                missing_persona_paths=missing_paths,
            )

        agent_uuid = str(uuid4())
        runtime_metadata = self._compose_metadata(
            agent_uuid=agent_uuid,
            role=normalized_role,
            user_name=user_name,
            target_ip=target_ip,
            project_id=project_id,
            metadata=metadata,
        )

        try:
            provider = provider_cls()
            base_agent = provider.load_base_agent()
            hydrated_instructions = self._hydrate_prompt(normalized_role, runtime_metadata, base_agent)
            toolbox = self._build_toolbox(
                normalized_role,
                allow_subghz=allow_subghz,
                extra_tools=extra_tools,
            )
            runtime_agent = self._clone_runtime_agent(
                base_agent=base_agent,
                role=normalized_role,
                agent_uuid=agent_uuid,
                hydrated_instructions=hydrated_instructions,
                toolbox=toolbox,
                model_override=model_override,
                custom_name=custom_name,
            )
        except Exception as exc:  # pragma: no cover - failover path
            return self._fallback_generic(
                role=normalized_role,
                reason=f"init_failure:{type(exc).__name__}",
                user_name=user_name,
                target_ip=target_ip,
                project_id=project_id,
                metadata={**(metadata or {}), "init_error": str(exc)},
                model_override=model_override,
                custom_name=custom_name,
                missing_persona_paths=self._last_missing_persona_paths.get(normalized_role, ()),
            )

        context = CerebroContext(
            agent_uuid=agent_uuid,
            role=normalized_role,
            workspace=self._workspace_paths,
            toolbox=toolbox,
            redaction=self._redaction,
            path_guard=self._path_guard,
            metadata=runtime_metadata,
        )

        setattr(runtime_agent, "cerebro_context", context)
        setattr(runtime_agent, "cerebro_agent_uuid", agent_uuid)
        setattr(runtime_agent, "cerebro_role", normalized_role)

        with self._lock:
            self._live_agents[agent_uuid] = runtime_agent
            self._agent_roles_by_uuid[agent_uuid] = normalized_role
            if use_singleton:
                self._singletons[normalized_role] = runtime_agent

        self._log_lifecycle_event("spawn", normalized_role, agent_uuid, {"singleton": use_singleton})
        return runtime_agent

    def destroy_agent(self, agent_uuid: str) -> bool:
        """Destroy a previously spawned agent and emit lifecycle event."""
        with self._lock:
            agent = self._live_agents.pop(agent_uuid, None)
            role = self._agent_roles_by_uuid.pop(agent_uuid, "unknown")
            if agent is None:
                return False

            for key, singleton_agent in list(self._singletons.items()):
                if getattr(singleton_agent, "cerebro_agent_uuid", None) == agent_uuid:
                    del self._singletons[key]

        self._log_lifecycle_event("destroy", role, agent_uuid, {})
        return True

    def get_registered_roles(self) -> list[str]:
        return self.roles

    def _discover_agents(self) -> None:
        import cerberus.agents as agents_pkg

        for _, module_name, is_pkg in pkgutil.iter_modules(agents_pkg.__path__, agents_pkg.__name__ + "."):
            if is_pkg:
                continue
            stem = module_name.rsplit(".", 1)[-1]
            if stem in {"factory", "__init__"}:
                continue

            role = self._normalize_role(self._MODULE_ROLE_ALIASES.get(stem, stem))
            preferred_export = f"{stem}_agent"
            record = AgentDiscoveryRecord(
                role=role,
                module_path=module_name,
                preferred_export=preferred_export,
                prompt_candidates=self._prompt_candidates(role=role, stem=stem),
            )
            self._records[role] = record
            provider_cls = self._build_provider_class(record)
            self.register_provider(role, provider_cls)

        # Ensure failover role always exists in registry surface.
        if "generic_intelligence" not in self._providers:
            generic_record = AgentDiscoveryRecord(
                role="generic_intelligence",
                module_path="",
                preferred_export="",
                prompt_candidates=self._prompt_candidates(role="generic_intelligence", stem="generic"),
            )
            self._records[generic_record.role] = generic_record

    def _build_provider_class(self, record: AgentDiscoveryRecord) -> Type[CerebroBaseAgentProvider]:
        attrs: Dict[str, Any] = {
            "role": record.role,
            "module_path": record.module_path,
            "preferred_export": record.preferred_export,
            "__doc__": f"Lazy provider for role '{record.role}'",
        }
        class_name = "AgentFactory" + "".join(part.capitalize() for part in record.role.split("_")) + "Provider"
        return type(class_name, (LazyModuleAgentProvider,), attrs)

    def _clone_runtime_agent(
        self,
        *,
        base_agent: Agent,
        role: str,
        agent_uuid: str,
        hydrated_instructions: str,
        toolbox: CerebroToolbox,
        model_override: Optional[str],
        custom_name: Optional[str],
    ) -> Agent:
        model_name = (
            model_override
            or os.getenv(f"CERBERUS_{role.upper()}_MODEL")
            or os.getenv(f"CERBERUS_{role.upper()}_MODEL")
            or get_effective_model()
        )
        api_key = _resolve_factory_api_key()

        runtime_model = OpenAIChatCompletionsModel(
            model=model_name,
            openai_client=AsyncOpenAI(api_key=api_key),
            agent_name=base_agent.name,
            agent_id=agent_uuid,
            agent_type=role,
        )

        runtime_agent = base_agent.clone(
            model=runtime_model,
            instructions=hydrated_instructions,
            tools=toolbox.as_list(),
        )

        if custom_name:
            runtime_agent.name = custom_name

        self._inject_mcp_tools(runtime_agent, role)
        return runtime_agent

    def _build_toolbox(
        self,
        role: str,
        *,
        allow_subghz: bool,
        extra_tools: Optional[Sequence[str]],
    ) -> CerebroToolbox:
        system_role = self._SYSTEM_TOOL_ROLE_MAP.get(role, "analyzer")
        tool_meta = get_tools_for_agent(system_role)
        loaded: Dict[str, Any] = {}

        for meta in tool_meta:
            if role == "blue_teamer" and ("subghz" in meta.name.lower()) and not allow_subghz:
                continue
            try:
                loaded[meta.name] = self._normalize_agent_tool(
                    meta.name,
                    get_tool(meta.name),
                    meta.description,
                )
            except Exception:
                continue

        for explicit_name in extra_tools or ():
            try:
                loaded[explicit_name] = self._normalize_agent_tool(
                    explicit_name,
                    get_tool(explicit_name),
                    "",
                )
            except Exception:
                continue

        return CerebroToolbox(role=role, tool_functions=loaded)

    @staticmethod
    def _normalize_agent_tool(tool_name: str, tool_obj: Any, description: str) -> Any:
        """Ensure tools exposed through runtime Agent.tools are SDK FunctionTool objects."""
        if isinstance(tool_obj, FunctionTool):
            return tool_obj
        if callable(tool_obj):
            wrapped = function_tool(
                name_override=tool_name,
                description_override=description or str(getattr(tool_obj, "__doc__", "") or ""),
            )(tool_obj)
            return wrapped
        return tool_obj

    def _hydrate_prompt(self, role: str, metadata: Mapping[str, Any], base_agent: Agent) -> str:
        template_text: Optional[str] = None
        record = self._records.get(role)
        stem = role
        if record and record.module_path:
            stem = record.module_path.rsplit(".", 1)[-1]
        candidates = record.prompt_candidates if record else self._prompt_candidates(role=role, stem=stem)

        resolution = self._persona_registry.resolve_prompt_paths(
            role=role,
            stem=stem,
            candidates=candidates,
        )
        if resolution.missing:
            self._last_missing_persona_paths[role] = tuple(str(path) for path in resolution.searched_paths)
        else:
            self._last_missing_persona_paths.pop(role, None)

        if resolution.selected_path is not None:
            try:
                template_text = load_prompt_template(str(resolution.selected_path))
            except FileNotFoundError:
                template_text = None

        if template_text is None:
            for relative_path in candidates:
                try:
                    template_text = load_prompt_template(relative_path)
                    break
                except FileNotFoundError:
                    continue

        if template_text is None:
            if isinstance(base_agent.instructions, str):
                template_text = base_agent.instructions
            else:
                template_text = "You are the Cerberus Generic Intelligence Agent. Operate safely and explain rationale."

        renderer = create_system_prompt_renderer(template_text)
        hydrated = renderer(**metadata)

        header_lines = [
            "# Session Metadata",
            f"- user_name: {metadata.get('user_name', 'unknown')}",
            f"- target_ip: {metadata.get('target_ip', 'unknown')}",
            f"- project_id: {metadata.get('project_id', 'unknown')}",
            f"- session_uuid: {metadata.get('session_uuid', 'unknown')}",
            "",
        ]
        return "\n".join(header_lines) + hydrated

    def _compose_metadata(
        self,
        *,
        agent_uuid: str,
        role: str,
        user_name: Optional[str],
        target_ip: Optional[str],
        project_id: Optional[str],
        metadata: Optional[Mapping[str, Any]],
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "user_name": user_name or os.getenv("USER") or os.getenv("USERNAME") or "unknown",
            "target_ip": target_ip or os.getenv("CERBERUS_TARGET_IP") or "unknown",
            "project_id": project_id or os.getenv("CERBERUS_PROJECT_ID") or "unknown",
            "session_uuid": agent_uuid,
            "role": role,
            "workspace_root": str(self._workspace_paths.repo_root),
            "active_workspace": str(self._workspace_paths.active_workspace),
            "timestamp_utc": datetime.now(tz=UTC).isoformat(),
        }
        if metadata:
            payload.update(dict(metadata))
        return payload

    def _fallback_generic(
        self,
        *,
        role: str,
        reason: str,
        user_name: Optional[str],
        target_ip: Optional[str],
        project_id: Optional[str],
        metadata: Optional[Mapping[str, Any]],
        model_override: Optional[str],
        custom_name: Optional[str],
        missing_persona_paths: Sequence[str] = (),
    ) -> Agent:
        fallback_uuid = str(uuid4())
        fallback_role = "generic_intelligence"
        runtime_metadata = self._compose_metadata(
            agent_uuid=fallback_uuid,
            role=fallback_role,
            user_name=user_name,
            target_ip=target_ip,
            project_id=project_id,
            metadata=metadata,
        )
        runtime_metadata = dict(runtime_metadata)
        runtime_metadata["failover_reason"] = reason
        runtime_metadata["requested_role"] = role
        runtime_metadata["missing_persona_paths"] = list(missing_persona_paths)
        runtime_metadata["missing_persona_file"] = missing_persona_paths[0] if missing_persona_paths else ""

        base_prompt = self._hydrate_prompt(fallback_role, runtime_metadata, _generic_template_agent())
        toolbox = self._build_toolbox(fallback_role, allow_subghz=False, extra_tools=None)
        model_name = model_override or get_effective_model()
        api_key = _resolve_factory_api_key()

        generic_agent = Agent(
            name=custom_name or "Generic Intelligence Agent",
            instructions=base_prompt,
            description="Fallback continuity agent used when specialized initialization fails.",
            model=OpenAIChatCompletionsModel(
                model=model_name,
                openai_client=AsyncOpenAI(api_key=api_key),
                agent_name="Generic Intelligence Agent",
                agent_id=fallback_uuid,
                agent_type=fallback_role,
            ),
            tools=toolbox.as_list(),
        )
        self._inject_mcp_tools(generic_agent, fallback_role)

        context = CerebroContext(
            agent_uuid=fallback_uuid,
            role=fallback_role,
            workspace=self._workspace_paths,
            toolbox=toolbox,
            redaction=self._redaction,
            path_guard=self._path_guard,
            metadata=runtime_metadata,
        )
        setattr(generic_agent, "cerebro_context", context)
        setattr(generic_agent, "cerebro_agent_uuid", fallback_uuid)
        setattr(generic_agent, "cerebro_role", fallback_role)

        with self._lock:
            self._live_agents[fallback_uuid] = generic_agent
            self._agent_roles_by_uuid[fallback_uuid] = fallback_role

        self._log_lifecycle_event(
            "spawn_failover",
            fallback_role,
            fallback_uuid,
            {
                "requested_role": role,
                "reason": reason,
                "missing_persona_file": runtime_metadata["missing_persona_file"],
                "missing_persona_paths": runtime_metadata["missing_persona_paths"],
            },
        )
        if missing_persona_paths:
            audit = getattr(self._logger, "audit", None)
            if callable(audit):
                audit(
                    "generic_intelligence failover due to missing persona file",
                    actor="agent_factory",
                    data={
                        "requested_role": role,
                        "missing_persona_file": missing_persona_paths[0],
                        "searched_persona_paths": list(missing_persona_paths),
                    },
                    tags=["agent_factory", "spawn_failover", "persona_missing"],
                )
        return generic_agent

    def _inject_mcp_tools(self, runtime_agent: Agent, role: str) -> None:
        try:
            mcp_module = importlib.import_module("cerberus.repl.commands.mcp")
            get_mcp_tools_for_agent = getattr(mcp_module, "get_mcp_tools_for_agent", None)
            if not callable(get_mcp_tools_for_agent):
                return
            mcp_tools = get_mcp_tools_for_agent(role)
            if not isinstance(mcp_tools, (list, tuple)):
                return
            if not mcp_tools:
                return

            existing = list(getattr(runtime_agent, "tools", []) or [])
            existing_by_name = {
                self._tool_name(tool): tool
                for tool in existing
                if self._tool_name(tool)
            }
            for mcp_tool in mcp_tools:
                tool_name = self._tool_name(mcp_tool)
                if tool_name:
                    existing_by_name[tool_name] = mcp_tool
            runtime_agent.tools = list(existing_by_name.values())
        except Exception:
            return

    @staticmethod
    def _tool_name(tool: Any) -> str:
        value = getattr(tool, "name", None)
        if isinstance(value, str) and value.strip():
            return value.strip()
        value = getattr(tool, "__name__", None)
        if isinstance(value, str) and value.strip():
            return value.strip()
        return ""

    def _pathguard_audit(self, event: str, payload: Mapping[str, Any]) -> None:
        data = {"event": event, **dict(payload)}
        audit = getattr(self._logger, "audit", None)
        if callable(audit):
            audit(
                "PathGuard event",
                actor="agent_factory",
                data=data,
                tags=["pathguard", event],
            )

    def _build_workspace_paths(self, workspace_root: str | Path | None) -> WorkspacePaths:
        repo_root = Path(workspace_root).expanduser().resolve() if workspace_root else Path.cwd().resolve()
        active_workspace = get_project_space().ensure_initialized().resolve()
        src_root = Path(__file__).resolve().parents[1]
        prompts_root = src_root / "prompts"

        return WorkspacePaths(
            repo_root=repo_root,
            active_workspace=active_workspace,
            prompts_root=prompts_root,
            evidence_root=active_workspace / "evidence",
            reports_root=active_workspace / "reports",
        )

    def _prompt_candidates(self, *, role: str, stem: str) -> tuple[str, ...]:
        return self._persona_registry.prompt_candidates(role=role, stem=stem)

    def _normalize_role(self, value: str) -> str:
        normalized = self._persona_registry.normalize_role(value)
        return self._ROLE_ALIASES.get(normalized, normalized)

    def _collect_missing_persona_paths(self, role: str) -> tuple[str, ...]:
        normalized_role = self._normalize_role(role)
        resolution = self._persona_registry.resolve_prompt_paths(
            role=normalized_role,
            stem=normalized_role,
        )
        missing = tuple(str(path) for path in resolution.searched_paths)
        self._last_missing_persona_paths[normalized_role] = missing
        return missing

    def _log_lifecycle_event(self, event: str, role: str, agent_uuid: str, data: Mapping[str, Any]) -> None:
        payload = {
            "event": event,
            "role": role,
            "agent_uuid": agent_uuid,
            "workspace": str(self._workspace_paths.active_workspace),
            **dict(data),
        }

        audit = getattr(self._logger, "audit", None)
        if callable(audit):
            audit(
                f"Lifecycle Event: {event}",
                actor="agent_factory",
                data=payload,
                tags=["lifecycle", "agent_factory", event],
            )
            return

        logging.getLogger(__name__).info("Lifecycle Event %s", payload)


def _generic_template_agent() -> Agent:
    """Internal helper used exclusively for prompt hydration fallback path."""
    model_name = get_effective_model()
    api_key = _resolve_factory_api_key()
    api_base = get_effective_api_base()
    return Agent(
        name="Generic Intelligence Agent Template",
        instructions="You are a safe and capable cybersecurity assistant.",
        description="Template holder for failover hydration.",
        model=OpenAIChatCompletionsModel(
            model=model_name,
            openai_client=AsyncOpenAI(api_key=api_key, base_url=api_base),
            agent_name="Generic Intelligence Agent Template",
            agent_id="template",
            agent_type="generic_intelligence",
        ),
        tools=[],
    )


_GLOBAL_FACTORY: Optional[CerebroAgentFactory] = None


def get_cerebro_agent_factory() -> CerebroAgentFactory:
    """Compatibility accessor for a process-wide agent factory instance."""
    global _GLOBAL_FACTORY
    if _GLOBAL_FACTORY is None:
        _GLOBAL_FACTORY = CerebroAgentFactory()
    return _GLOBAL_FACTORY


def get_agent_factory(agent_role: str):
    """Compatibility shim exposing callable factories per role."""
    factory = get_cerebro_agent_factory()

    def _spawn(
        model_override: str | None = None,
        custom_name: str | None = None,
        agent_id: str | None = None,
    ) -> Agent:
        metadata: Dict[str, Any] = {}
        if agent_id:
            metadata["requested_agent_id"] = agent_id
        return factory.create_agent(
            agent_role,
            model_override=model_override,
            custom_name=custom_name,
            metadata=metadata,
        )

    return _spawn


__all__ = [
    "WorkspacePaths",
    "CerebroRedaction",
    "CerebroToolbox",
    "CerebroContext",
    "CerebroBaseAgentProvider",
    "LazyModuleAgentProvider",
    "CerebroAgentFactory",
    "get_cerebro_agent_factory",
    "get_agent_factory",
]
