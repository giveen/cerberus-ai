"""Model governance command for Cerebro REPL.

Provides a provider-agnostic model orchestrator with:
- pluggable provider adapters (OpenAI, Anthropic, Google, Local, MCP)
- capability audit against active agent requirements
- dynamic model parameter overrides
- cost-aware routing suggestions
- workspace persistence + audit trail for model selections
"""

from __future__ import annotations

from abc import ABC, abstractmethod
import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
import json
import os
from pathlib import Path
import tempfile
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from pydantic import BaseModel, Field, ValidationError
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from cerberus.memory import MemoryManager
from cerberus.repl.commands.base import Command, CommandError, register_command
from cerberus.repl.commands.cost import USAGE_TRACKER
from cerberus.sdk.agents.simple_agent_manager import AGENT_MANAGER
from cerberus.tools.workspace import get_project_space


console = Console()

LITELLM_MODEL_CATALOG_URL = os.getenv("CERBERUS_LITELLM_MODEL_CATALOG_URL", "").strip()
LEGACY_LITELLM_CATALOG_URL = "https://raw.githubusercontent.com/BerriAI/litellm/main/model_prices_and_context_window.json"
LEGACY_OLLAMA_CATALOG_URL = os.getenv("OLLAMA_API_BASE", "http://ollama").rstrip("/") + "/api/tags"


@dataclass(frozen=True)
class ModelCapabilities:
    """Capability profile for a model candidate."""

    tool_calling: bool
    json_mode: bool
    max_context_window: int


@dataclass(frozen=True)
class ModelDescriptor:
    """Provider-agnostic model metadata."""

    id: str
    provider: str
    category: str
    description: str
    capabilities: ModelCapabilities
    input_cost_per_token: Decimal
    output_cost_per_token: Decimal


class ModelSelectionState(BaseModel):
    """Persisted model selection for current workspace."""

    schema_version: str = "1.0"
    selected_model: str = "cerebro1"
    provider: str = "openai"
    parameters: Dict[str, Any] = Field(default_factory=dict)
    updated_at: str = Field(default_factory=lambda: datetime.now(tz=UTC).isoformat())


class ModelAuditEvent(BaseModel):
    """Audit row for model changes."""

    timestamp: str = Field(default_factory=lambda: datetime.now(tz=UTC).isoformat())
    user: str
    action: str
    model: str
    provider: str
    details: Dict[str, Any] = Field(default_factory=dict)


class ModelProviderInterface(ABC):
    """Provider adapter contract for model discovery and validation."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Stable provider name."""

    @abstractmethod
    async def list_models(self) -> List[ModelDescriptor]:
        """List models available from this provider."""

    @abstractmethod
    async def supports_model(self, model_id: str) -> bool:
        """Return whether model_id belongs to this provider."""


class CatalogProvider(ModelProviderInterface):
    """HTTP-catalog backed provider using LiteLLM model metadata."""

    def __init__(
        self,
        *,
        name: str,
        category: str,
        required_env_keys: Sequence[str],
        prefixes: Sequence[str],
        description_hint: str,
    ) -> None:
        self._name = name
        self._category = category
        self._required_env_keys = list(required_env_keys)
        self._prefixes = list(prefixes)
        self._description_hint = description_hint

    @property
    def name(self) -> str:
        return self._name

    async def list_models(self) -> List[ModelDescriptor]:
        if self._required_env_keys and not any(os.getenv(k) for k in self._required_env_keys):
            return []

        catalog = await _load_litellm_catalog()
        results: List[ModelDescriptor] = []

        for model_id, payload in catalog.items():
            if not self._matches_prefix(model_id):
                continue

            input_cost = Decimal(str(payload.get("input_cost_per_token", 0) or 0))
            output_cost = Decimal(str(payload.get("output_cost_per_token", 0) or 0))
            context_window = int(payload.get("max_input_tokens", 0) or 0)
            supports_fc = bool(payload.get("supports_function_calling", False))
            supports_json = bool(payload.get("supports_response_schema", False) or payload.get("supports_json_mode", False))

            desc = str(payload.get("description") or self._description_hint)
            results.append(
                ModelDescriptor(
                    id=model_id,
                    provider=self._name,
                    category=self._category,
                    description=desc,
                    capabilities=ModelCapabilities(
                        tool_calling=supports_fc,
                        json_mode=supports_json,
                        max_context_window=context_window,
                    ),
                    input_cost_per_token=input_cost,
                    output_cost_per_token=output_cost,
                )
            )

        return sorted(results, key=lambda item: item.id)

    async def supports_model(self, model_id: str) -> bool:
        return self._matches_prefix(model_id)

    def _matches_prefix(self, model_id: str) -> bool:
        lowered = model_id.lower().strip()
        if not self._prefixes:
            return True
        return any(lowered.startswith(prefix) for prefix in self._prefixes)


class LocalModelProvider(ModelProviderInterface):
    """Discover local model endpoints from Ollama/vLLM runtime hints."""

    @property
    def name(self) -> str:
        return "local"

    async def list_models(self) -> List[ModelDescriptor]:
        models: List[ModelDescriptor] = []

        ollama_models = await self._discover_ollama_models()
        for model in ollama_models:
            models.append(
                ModelDescriptor(
                    id=model,
                    provider="local",
                    category="Local (Ollama)",
                    description="Local model served by Ollama",
                    capabilities=ModelCapabilities(
                        tool_calling=False,
                        json_mode=False,
                        max_context_window=32768,
                    ),
                    input_cost_per_token=Decimal("0"),
                    output_cost_per_token=Decimal("0"),
                )
            )

        vllm_models = self._discover_vllm_models()
        for model in vllm_models:
            models.append(
                ModelDescriptor(
                    id=model,
                    provider="local",
                    category="Local (vLLM)",
                    description="Model registered through vLLM endpoint",
                    capabilities=ModelCapabilities(
                        tool_calling=True,
                        json_mode=True,
                        max_context_window=65536,
                    ),
                    input_cost_per_token=Decimal("0"),
                    output_cost_per_token=Decimal("0"),
                )
            )

        dedup: Dict[str, ModelDescriptor] = {item.id: item for item in models}
        return sorted(dedup.values(), key=lambda item: item.id)

    async def supports_model(self, model_id: str) -> bool:
        available = await self.list_models()
        return any(item.id == model_id for item in available)

    async def _discover_ollama_models(self) -> List[str]:
        try:
            import requests  # type: ignore

            base = os.getenv("OLLAMA_API_BASE", "http://127.0.0.1:11434")
            url = f"{base.rstrip('/')}/api/tags"
            response = await asyncio.to_thread(requests.get, url, timeout=2)
            if response.status_code != 200:
                return []
            payload = response.json()
            data = payload.get("models", payload.get("items", []))
            results = [str(entry.get("name", "")).strip() for entry in data if str(entry.get("name", "")).strip()]
            return results
        except Exception:
            return []

    @staticmethod
    def _discover_vllm_models() -> List[str]:
        explicit = os.getenv("CERBERUS_VLLM_MODELS", "")
        models = [token.strip() for token in explicit.split(",") if token.strip()]
        return models


class MCPModelProvider(ModelProviderInterface):
    """Expose MCP-backed model identifiers discovered from active MCP connections."""

    @property
    def name(self) -> str:
        return "mcp"

    async def list_models(self) -> List[ModelDescriptor]:
        try:
            from cerberus.repl.commands.mcp import get_mcp_manager

            manager = get_mcp_manager()
            aliases = sorted(manager.connections.keys())
        except Exception:
            aliases = []

        models: List[ModelDescriptor] = []
        for alias in aliases:
            model_id = f"mcp/{alias}"
            models.append(
                ModelDescriptor(
                    id=model_id,
                    provider="mcp",
                    category="MCP",
                    description=f"Model endpoint exposed by MCP connection '{alias}'",
                    capabilities=ModelCapabilities(
                        tool_calling=True,
                        json_mode=True,
                        max_context_window=32768,
                    ),
                    input_cost_per_token=Decimal("0"),
                    output_cost_per_token=Decimal("0"),
                )
            )
        return models

    async def supports_model(self, model_id: str) -> bool:
        return model_id.startswith("mcp/")


class ModelOrchestrator:
    """Provider-agnostic model governance utility."""

    def __init__(self, *, memory: MemoryManager, workspace_root: Path) -> None:
        self._memory = memory
        self._workspace_root = workspace_root.resolve()
        self._selection_path = self._workspace_root / ".cerberus" / "session" / "model_selection.json"
        self._audit_path = self._workspace_root / ".cerberus" / "audit" / "model_actions.jsonl"
        self._providers: List[ModelProviderInterface] = [
            CatalogProvider(
                name="openai",
                category="OpenAI",
                required_env_keys=["OPENAI_API_KEY"],
                prefixes=["gpt", "o1", "o3", "o4", "openai/"],
                description_hint="OpenAI frontier/general-purpose model",
            ),
            CatalogProvider(
                name="anthropic",
                category="Anthropic",
                required_env_keys=["ANTHROPIC_API_KEY"],
                prefixes=["claude", "anthropic/"],
                description_hint="Anthropic Claude model",
            ),
            CatalogProvider(
                name="google",
                category="Google",
                required_env_keys=["GOOGLE_API_KEY", "GEMINI_API_KEY"],
                prefixes=["gemini", "google/"],
                description_hint="Google Gemini model",
            ),
            LocalModelProvider(),
            MCPModelProvider(),
        ]
        self._model_cache: Dict[str, ModelDescriptor] = {}

    async def refresh_catalog(self) -> Dict[str, ModelDescriptor]:
        entries: Dict[str, ModelDescriptor] = {}
        for provider in self._providers:
            for descriptor in await provider.list_models():
                entries[descriptor.id] = descriptor

        # Alias models are first-class to preserve backward compatibility.
        entries.setdefault(
            "cerebro1",
            ModelDescriptor(
                id="cerebro1",
                provider="openai",
                category="Alias",
                description="Commercial cybersecurity default",
                capabilities=ModelCapabilities(tool_calling=True, json_mode=True, max_context_window=128000),
                input_cost_per_token=Decimal("0.0000025"),
                output_cost_per_token=Decimal("0.00001"),
            ),
        )
        entries.setdefault(
            "cerebro1-fast",
            ModelDescriptor(
                id="cerebro1-fast",
                provider="openai",
                category="Alias",
                description="Faster low-latency alias profile",
                capabilities=ModelCapabilities(tool_calling=True, json_mode=True, max_context_window=64000),
                input_cost_per_token=Decimal("0.00000015"),
                output_cost_per_token=Decimal("0.0000006"),
            ),
        )

        self._model_cache = entries
        return entries

    async def resolve_model(self, model_id: str) -> Optional[ModelDescriptor]:
        if model_id in self._model_cache:
            return self._model_cache[model_id]
        await self.refresh_catalog()
        return self._model_cache.get(model_id)

    def current_selection(self) -> ModelSelectionState:
        env_model = os.getenv("CERBERUS_MODEL", "cerebro1")
        if self._selection_path.exists():
            try:
                obj = json.loads(self._selection_path.read_text(encoding="utf-8"))
                state = ModelSelectionState.model_validate(obj)
                if env_model:
                    state = state.model_copy(update={"selected_model": env_model})
                return state
            except Exception:
                pass
        return ModelSelectionState(selected_model=env_model, provider=self._guess_provider(env_model))

    async def select_model(self, *, model_id: str, user: str) -> Tuple[ModelSelectionState, List[str], Optional[str]]:
        descriptor = await self.resolve_model(model_id)
        provider_name = descriptor.provider if descriptor else self._guess_provider(model_id)

        state = self.current_selection().model_copy(
            update={
                "selected_model": model_id,
                "provider": provider_name,
                "updated_at": datetime.now(tz=UTC).isoformat(),
            }
        )
        self._apply_runtime_selection(state)
        self._persist_selection(state)

        warnings = await self.capability_audit(model_id)
        routing_hint = self.routing_suggestion(model_id)

        self._append_audit(
            ModelAuditEvent(
                user=user,
                action="select",
                model=model_id,
                provider=provider_name,
                details={"warnings": warnings, "routing_suggestion": routing_hint},
            )
        )
        return state, warnings, routing_hint

    def set_parameters(self, *, updates: Mapping[str, Any], user: str) -> ModelSelectionState:
        state = self.current_selection()
        params = dict(state.parameters)
        params.update(updates)

        normalized = self._normalize_parameters(params)
        new_state = state.model_copy(
            update={
                "parameters": normalized,
                "updated_at": datetime.now(tz=UTC).isoformat(),
            }
        )

        self._apply_runtime_parameters(normalized)
        self._persist_selection(new_state)

        self._append_audit(
            ModelAuditEvent(
                user=user,
                action="set-parameters",
                model=new_state.selected_model,
                provider=new_state.provider,
                details={"updates": normalized},
            )
        )
        return new_state

    async def capability_audit(self, model_id: str) -> List[str]:
        descriptor = await self.resolve_model(model_id)
        caps = descriptor.capabilities if descriptor else self._heuristic_capabilities(model_id)
        litellm_caps = self._litellm_capabilities(model_id)
        if litellm_caps is not None:
            caps = litellm_caps

        requires_tools = False
        requires_json = False
        minimum_context = 0

        active_agent = AGENT_MANAGER.get_active_agent()
        if active_agent is not None:
            agent_tools = getattr(active_agent, "tools", [])
            requires_tools = isinstance(agent_tools, list) and len(agent_tools) > 0
            requires_json = bool(getattr(active_agent, "output_type", None))

            try:
                instr = getattr(active_agent, "instructions", "")
                if isinstance(instr, str) and "json" in instr.lower():
                    requires_json = True
            except Exception:
                pass

        ctx_env = os.getenv("CERBERUS_CONTEXT_WINDOW") or os.getenv("CERBERUS_MAX_CONTEXT")
        if ctx_env and str(ctx_env).isdigit():
            minimum_context = int(str(ctx_env))

        warnings: List[str] = []
        if requires_tools and not caps.tool_calling:
            warnings.append("Active agent has tools but selected model may not support tool-calling")
        if requires_json and not caps.json_mode:
            warnings.append("Active agent appears to require structured output, but model JSON mode is uncertain")
        if minimum_context > 0 and caps.max_context_window > 0 and caps.max_context_window < minimum_context:
            warnings.append(
                f"Selected model context window ({caps.max_context_window}) is below requested minimum ({minimum_context})"
            )

        return warnings

    @staticmethod
    def _litellm_capabilities(model_id: str) -> Optional[ModelCapabilities]:
        """Best-effort capability probe via LiteLLM standardized metadata."""
        try:
            import litellm  # type: ignore

            getter = getattr(litellm, "get_supported_openai_params", None)
            if getter is None:
                return None
            supported_params = getter(model=model_id) or []
            supports_tools = "tools" in supported_params or "tool_choice" in supported_params
            supports_json = "response_format" in supported_params
            # LiteLLM does not always expose context size here; keep heuristic default.
            return ModelCapabilities(
                tool_calling=supports_tools,
                json_mode=supports_json,
                max_context_window=128000,
            )
        except Exception:
            return None

    def routing_suggestion(self, model_id: str) -> Optional[str]:
        selected_rate = self._combined_rate(model_id)
        if selected_rate <= Decimal("0"):
            return None

        provider = self._guess_provider(model_id)
        candidates = [mid for mid in self._model_cache.keys() if self._guess_provider(mid) == provider and mid != model_id]
        if not candidates:
            return None

        cheaper = sorted(
            ((mid, self._combined_rate(mid)) for mid in candidates),
            key=lambda item: item[1],
        )
        for candidate, rate in cheaper:
            if rate > 0 and rate * Decimal("2") < selected_rate:
                return (
                    f"Cost-aware routing: '{model_id}' is relatively expensive for routine tasks. "
                    f"Consider '{candidate}' (approx. {(rate * Decimal('1000000')):.2f} $/M tokens)."
                )
        return None

    def available_models_snapshot(self) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        for item in sorted(self._model_cache.values(), key=lambda x: x.id):
            rows.append(
                {
                    "name": item.id,
                    "provider": item.provider,
                    "category": item.category,
                    "description": item.description,
                    "input_cost": float(item.input_cost_per_token * Decimal("1000000")),
                    "output_cost": float(item.output_cost_per_token * Decimal("1000000")),
                }
            )
        return rows

    def _apply_runtime_selection(self, state: ModelSelectionState) -> None:
        os.environ["CERBERUS_MODEL"] = state.selected_model
        os.environ["CERBERUS_MODEL_PROVIDER"] = state.provider

    @staticmethod
    def _normalize_parameters(params: Mapping[str, Any]) -> Dict[str, Any]:
        normalized: Dict[str, Any] = {}
        for key, value in params.items():
            k = str(key).strip().lower()
            if not k:
                continue
            if k in {"temperature", "top_p"}:
                try:
                    normalized[k] = float(value)
                except Exception:
                    continue
                continue
            if k in {"context_window", "max_tokens"}:
                try:
                    normalized[k] = int(value)
                except Exception:
                    continue
                continue
            normalized[k] = value
        return normalized

    @staticmethod
    def _apply_runtime_parameters(params: Mapping[str, Any]) -> None:
        if "temperature" in params:
            os.environ["CERBERUS_TEMP"] = str(params["temperature"])
        if "context_window" in params:
            os.environ["CERBERUS_CONTEXT_WINDOW"] = str(params["context_window"])
        if "max_tokens" in params:
            os.environ["CERBERUS_MAX_TOKENS"] = str(params["max_tokens"])

    def _persist_selection(self, state: ModelSelectionState) -> None:
        self._selection_path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(state.model_dump(mode="json"), ensure_ascii=True, indent=2)
        self._atomic_write_text(self._selection_path, payload)

    def _append_audit(self, event: ModelAuditEvent) -> None:
        self._audit_path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(event.model_dump(mode="json"), ensure_ascii=True) + "\n"

        existing = ""
        if self._audit_path.exists():
            existing = self._audit_path.read_text(encoding="utf-8")
        self._atomic_write_text(self._audit_path, existing + line)

        self._memory.record(
            {
                "topic": "model.audit",
                "finding": f"Model action '{event.action}' on {event.model}",
                "source": "model_command",
                "tags": ["model", "audit", "governance"],
                "artifacts": event.model_dump(mode="python"),
            }
        )

    @staticmethod
    def _atomic_write_text(target: Path, text: str) -> None:
        fd, tmp_name = tempfile.mkstemp(prefix=".model_tmp_", dir=str(target.parent))
        tmp_path = Path(tmp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(text)
                handle.flush()
            tmp_path.replace(target)
        finally:
            if tmp_path.exists():
                tmp_path.unlink(missing_ok=True)

    def _combined_rate(self, model_id: str) -> Decimal:
        descriptor = self._model_cache.get(model_id)
        if descriptor is not None:
            return descriptor.input_cost_per_token + descriptor.output_cost_per_token

        in_rate, out_rate = USAGE_TRACKER.price_table.rate_for(model_id)
        return in_rate + out_rate

    def _guess_provider(self, model_id: str) -> str:
        lowered = model_id.lower().strip()
        if lowered.startswith("mcp/"):
            return "mcp"
        if lowered.startswith(("claude", "anthropic/")):
            return "anthropic"
        if lowered.startswith(("gemini", "google/")):
            return "google"
        if lowered.startswith(("ollama", "llama", "qwen", "mistral", "deepseek", "vllm")):
            return "local"
        return "openai"

    def _heuristic_capabilities(self, model_id: str) -> ModelCapabilities:
        lowered = model_id.lower().strip()
        local = any(lowered.startswith(prefix) for prefix in ("ollama", "llama", "qwen", "mistral", "deepseek", "vllm"))
        return ModelCapabilities(
            tool_calling=not local,
            json_mode=not local,
            max_context_window=32768 if local else 128000,
        )


async def _load_litellm_catalog() -> Dict[str, Dict[str, Any]]:
    if os.getenv("CERBERUS_ENABLE_REMOTE_MODEL_CATALOG", "").strip().lower() not in {"1", "true", "yes", "on"}:
        return {}
    if not LITELLM_MODEL_CATALOG_URL:
        return {}

    try:
        import requests  # type: ignore

        response = await asyncio.to_thread(requests.get, LITELLM_MODEL_CATALOG_URL, timeout=4)
        if response.status_code != 200:
            return {}
        obj = response.json()
        if isinstance(obj, dict):
            return {str(k): v for k, v in obj.items() if isinstance(v, dict)}
        return {}
    except Exception:
        return {}


_GLOBAL_ORCHESTRATOR: Optional[ModelOrchestrator] = None


def get_model_orchestrator(memory: Optional[MemoryManager] = None) -> ModelOrchestrator:
    global _GLOBAL_ORCHESTRATOR
    if _GLOBAL_ORCHESTRATOR is None:
        mem = memory or MemoryManager()
        workspace_root = get_project_space().ensure_initialized().resolve()
        _GLOBAL_ORCHESTRATOR = ModelOrchestrator(memory=mem, workspace_root=workspace_root)
    return _GLOBAL_ORCHESTRATOR


def get_all_predefined_models() -> List[Dict[str, Any]]:
    """Compatibility helper used by completer/compact modules."""
    orchestrator = get_model_orchestrator()

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        # Best-effort snapshot in async contexts.
        return orchestrator.available_models_snapshot()

    asyncio.run(orchestrator.refresh_catalog())
    return orchestrator.available_models_snapshot()


def get_predefined_model_names() -> List[str]:
    """Compatibility helper used by completer module."""
    return [item["name"] for item in get_all_predefined_models()]


class ModelCommand(Command):
    """Model governance command with a legacy selection wrapper."""

    name = "/model"
    description = "View or change the current LLM model"
    aliases = ["/mod"]

    def __init__(self) -> None:
        super().__init__(name=self.name, description=self.description, aliases=self.aliases)
        self._memory = self._resolve_memory_manager()
        self._orchestrator = get_model_orchestrator(self._memory)
        self.cached_models: List[Dict[str, Any]] = []
        self.cached_model_numbers: Dict[str, str] = {}
        self.last_model_fetch: Optional[str] = None

    @property
    def help(self) -> str:
        return (
            "Usage:\n"
            "  /model                             # show current selection + catalog\n"
            "  /model <model_id>                  # select model\n"
            "  /model <number>                    # select cached numbered model\n"
            "  /model list                        # list catalog\n"
            "  /model --set key=value             # set runtime parameter\n"
            "  /model --set temperature=0.2 --set context_window=128000\n"
            "\n"
            "Model changes are persisted in workspace .cerberus/session/model_selection.json"
        )

    def handle(self, args: Optional[List[str]] = None) -> bool:  # type: ignore[override]
        try:
            clean = self.sanitize_args(args)
        except Exception as exc:
            console.print(f"[red]Input validation failed: {exc}[/red]")
            return False

        record = self._audit_before(clean)
        try:
            if self._should_use_governance_path(clean):
                result = self._run_execute(clean)
            elif not clean:
                result = self.handle_no_args()
            else:
                result = self._handle_legacy_selection(clean)
        except CommandError as exc:
            self._audit_after(record, success=False, error=str(exc))
            console.print(f"[red]{self.name}: {exc}[/red]")
            return False
        except Exception as exc:  # pylint: disable=broad-except
            self._audit_after(record, success=False, error=repr(exc))
            raise

        self._audit_after(record, success=bool(result))
        return bool(result)

    def handle_no_args(self) -> bool:  # type: ignore[override]
        self._refresh_legacy_model_cache()
        self._render_legacy_status_table()
        return True

    async def execute(self, args: List[str]) -> bool:
        await self._orchestrator.refresh_catalog()

        if not args:
            self._render_status_table()
            return True

        if args[0] in {"help", "--help", "-h"}:
            console.print(self.help)
            return True

        if args[0] == "list":
            self._render_catalog_table()
            return True

        if "--set" in args:
            updates, err = self._parse_set_args(args)
            if err:
                console.print(f"[red]{err}[/red]")
                return False

            state = self._orchestrator.set_parameters(updates=updates, user=self.session.user)
            console.print(
                Panel(
                    f"Updated parameters for [cyan]{state.selected_model}[/cyan]:\n"
                    f"{json.dumps(state.parameters, ensure_ascii=True)}",
                    title="Model Parameters",
                    border_style="green",
                )
            )
            return True

        model_id = args[0].strip()
        state, warnings, suggestion = await self._orchestrator.select_model(model_id=model_id, user=self.session.user)

        lines = [
            f"Selected model: [cyan]{state.selected_model}[/cyan]",
            f"Provider: [magenta]{state.provider}[/magenta]",
            f"Persisted at: [white]{self._orchestrator._selection_path}[/white]",  # pylint: disable=protected-access
        ]
        if warnings:
            lines.append("\n[bold yellow]Capability Audit Warnings:[/bold yellow]")
            for item in warnings:
                lines.append(f"- {item}")
        if suggestion:
            lines.append("\n[bold blue]Routing Suggestion:[/bold blue]")
            lines.append(suggestion)

        console.print(Panel("\n".join(lines), title="Model Governance", border_style="green"))
        return True

    @staticmethod
    def _should_use_governance_path(args: List[str]) -> bool:
        return any(token.startswith("--") for token in args) or (bool(args) and args[0] in {"list", "help", "--help", "-h"})

    def _handle_legacy_selection(self, args: List[str]) -> bool:
        token = args[0] if args else ""
        if token.isdigit() and token in self.cached_model_numbers:
            selected_model = self.cached_model_numbers[token]
        else:
            selected_model = token

        os.environ["CERBERUS_MODEL"] = selected_model
        os.environ["CERBERUS_MODEL_PROVIDER"] = self._orchestrator._guess_provider(selected_model)  # pylint: disable=protected-access
        console.print(
            Panel(
                f"Model changed to: [cyan]{selected_model}[/cyan]\n"
                "Note: This will take effect on the next agent interaction",
                title="Model Changed",
                border_style="green",
            )
        )
        return True

    def _refresh_legacy_model_cache(self) -> None:
        models = self._fetch_legacy_models()
        if not models:
            models = [
                {
                    "name": row.get("name", ""),
                    "provider": row.get("provider", "openai"),
                    "supports_function_calling": True,
                    "input_cost_per_token": row.get("input_cost", 0),
                    "output_cost_per_token": row.get("output_cost", 0),
                }
                for row in get_all_predefined_models()
            ]

        deduped: Dict[str, Dict[str, Any]] = {}
        for model in models:
            name = str(model.get("name", "")).strip()
            if not name:
                continue
            deduped[name] = model

        self.cached_models = sorted(deduped.values(), key=lambda item: str(item.get("name", "")).lower())
        self.cached_model_numbers = {
            str(index): str(model.get("name", ""))
            for index, model in enumerate(self.cached_models, start=1)
            if str(model.get("name", "")).strip()
        }
        self.last_model_fetch = datetime.now(tz=UTC).isoformat()

    def _fetch_legacy_models(self) -> List[Dict[str, Any]]:
        try:
            import requests  # type: ignore
        except Exception:
            return []

        models: List[Dict[str, Any]] = []

        try:
            response = requests.get(LEGACY_LITELLM_CATALOG_URL, timeout=4)
            if response.status_code == 200:
                payload = response.json()
                if isinstance(payload, dict):
                    for model_name, meta in payload.items():
                        if not isinstance(meta, dict):
                            continue
                        models.append(
                            {
                                "name": str(model_name),
                                "provider": str(meta.get("litellm_provider") or meta.get("provider") or "openai"),
                                "supports_function_calling": bool(meta.get("supports_function_calling", False)),
                                "input_cost_per_token": meta.get("input_cost_per_token", 0),
                                "output_cost_per_token": meta.get("output_cost_per_token", 0),
                                "max_tokens": meta.get("max_tokens", meta.get("max_input_tokens", 0)),
                            }
                        )
        except Exception:
            pass

        try:
            response = requests.get(LEGACY_OLLAMA_CATALOG_URL, timeout=2)
            if response.status_code == 200:
                payload = response.json()
                data = payload.get("models", payload.get("items", [])) if isinstance(payload, dict) else []
                for entry in data:
                    if not isinstance(entry, dict):
                        continue
                    name = str(entry.get("name", "")).strip()
                    if not name:
                        continue
                    models.append(
                        {
                            "name": name,
                            "provider": "ollama",
                            "supports_function_calling": False,
                            "input_cost_per_token": 0,
                            "output_cost_per_token": 0,
                            "max_tokens": 32768,
                        }
                    )
        except Exception:
            pass

        return models

    def _render_legacy_status_table(self) -> None:
        current_model = os.getenv("CERBERUS_MODEL", "")
        table = Table(title="Current Model", box=box.ROUNDED)
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="white")
        table.add_row("Model", current_model or "[default]")
        table.add_row("Cached Models", str(len(self.cached_models)))
        table.add_row("Last Refresh", self.last_model_fetch or "never")
        console.print(table)

        if not self.cached_models:
            return

        catalog = Table(title="Available Models", box=box.SIMPLE_HEAVY)
        catalog.add_column("#", style="bold white", justify="right")
        catalog.add_column("Model", style="cyan")
        catalog.add_column("Provider", style="magenta")
        for index, model in enumerate(self.cached_models, start=1):
            catalog.add_row(str(index), str(model.get("name", "")), str(model.get("provider", "")))
        console.print(catalog)

    def _render_status_table(self) -> None:
        state = self._orchestrator.current_selection()

        table = Table(title="Model Selection", box=box.ROUNDED)
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="white")
        table.add_row("Model", state.selected_model)
        table.add_row("Provider", state.provider)
        table.add_row("Updated", state.updated_at)
        table.add_row("Parameters", json.dumps(state.parameters, ensure_ascii=True) if state.parameters else "{}")

        console.print(table)
        self._render_catalog_table(limit=25)

    def _render_catalog_table(self, *, limit: Optional[int] = None) -> None:
        rows = get_all_predefined_models()

        table = Table(title="Available Models", box=box.SIMPLE_HEAVY)
        table.add_column("#", style="bold white", justify="right")
        table.add_column("Model", style="cyan")
        table.add_column("Provider", style="magenta")
        table.add_column("Category", style="blue")
        table.add_column("Input $/M", style="green", justify="right")
        table.add_column("Output $/M", style="red", justify="right")

        subset = rows if limit is None else rows[:limit]
        for idx, row in enumerate(subset, start=1):
            in_cost = row.get("input_cost")
            out_cost = row.get("output_cost")
            in_text = f"${in_cost:.2f}" if isinstance(in_cost, (int, float)) else "Unknown"
            out_text = f"${out_cost:.2f}" if isinstance(out_cost, (int, float)) else "Unknown"
            table.add_row(str(idx), str(row.get("name", "")), str(row.get("provider", "")), str(row.get("category", "")), in_text, out_text)

        if limit is not None and len(rows) > limit:
            table.caption = f"Showing {limit}/{len(rows)} models. Use '/model list' for full catalog."

        console.print(table)

    @staticmethod
    def _parse_set_args(args: Sequence[str]) -> Tuple[Dict[str, Any], Optional[str]]:
        updates: Dict[str, Any] = {}
        i = 0
        while i < len(args):
            token = args[i]
            if token != "--set":
                i += 1
                continue
            if i + 1 >= len(args):
                return {}, "--set requires key=value"
            pair = args[i + 1]
            if "=" not in pair:
                return {}, f"Invalid --set value '{pair}', expected key=value"
            key, value = pair.split("=", 1)
            key = key.strip()
            value = value.strip()
            if not key:
                return {}, "Parameter key cannot be empty"
            updates[key] = value
            i += 2
        if not updates:
            return {}, "No parameter updates supplied"
        return updates, None

    def _resolve_memory_manager(self) -> MemoryManager:
        if isinstance(self.memory, MemoryManager):
            return self.memory
        return MemoryManager()


class ModelShowCommand(Command):
    """Compatibility command that exposes the legacy model-show surface."""

    name = "/model-show"
    description = "Show all available models from LiteLLM repository"
    aliases = ["/mod-show"]

    def __init__(self) -> None:
        super().__init__(name=self.name, description=self.description, aliases=self.aliases)

    @property
    def help(self) -> str:
        return "Usage: /model-show [supported] [search-term]"

    def handle(self, args: Optional[List[str]] = None) -> bool:  # type: ignore[override]
        try:
            clean = self.sanitize_args(args)
        except Exception as exc:
            console.print(f"[red]Input validation failed: {exc}[/red]")
            return False

        record = self._audit_before(clean)
        try:
            result = self._render_filtered_catalog(clean)
        except CommandError as exc:
            self._audit_after(record, success=False, error=str(exc))
            console.print(f"[red]{self.name}: {exc}[/red]")
            return False
        except Exception as exc:  # pylint: disable=broad-except
            self._audit_after(record, success=False, error=repr(exc))
            raise

        self._audit_after(record, success=bool(result))
        return bool(result)

    async def execute(self, args: List[str]) -> bool:
        _ = args
        cmd = ModelCommand()
        await cmd._orchestrator.refresh_catalog()  # pylint: disable=protected-access
        cmd._render_catalog_table(limit=None)  # pylint: disable=protected-access
        return True

    def _render_filtered_catalog(self, args: List[str]) -> bool:
        command = ModelCommand()
        command._refresh_legacy_model_cache()

        supported_only = any(token.lower() == "supported" for token in args)
        search_terms = [token.lower() for token in args if token.lower() != "supported"]

        models = list(command.cached_models)
        if supported_only:
            models = [model for model in models if bool(model.get("supports_function_calling", False))]
        if search_terms:
            models = [
                model
                for model in models
                if all(term in str(model.get("name", "")).lower() for term in search_terms)
            ]

        table = Table(title="Available Models", box=box.SIMPLE_HEAVY)
        table.add_column("Model", style="cyan")
        table.add_column("Provider", style="magenta")
        table.add_column("Functions", style="green")

        for model in models:
            table.add_row(
                str(model.get("name", "")),
                str(model.get("provider", "")),
                "yes" if bool(model.get("supports_function_calling", False)) else "no",
            )

        console.print(table)
        return True


MODEL_COMMAND_INSTANCE = ModelCommand()
MODEL_SHOW_COMMAND_INSTANCE = ModelShowCommand()
register_command(MODEL_COMMAND_INSTANCE)
register_command(MODEL_SHOW_COMMAND_INSTANCE)
