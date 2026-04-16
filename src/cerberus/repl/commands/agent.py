"""Agent command and lightweight registry helpers.

This module now serves two compatibility roles:

1. The legacy REPL `/agent` command surface expected by tests and other
   command modules.
2. The lightweight registry/manager objects used by `config` and
   `agent_info` helpers.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    yaml = None

from pydantic import BaseModel, Field, ValidationError as PydanticValidationError, field_validator

from cerberus.agents import get_agent_module, get_available_agents
from cerberus.repl.commands.base import Command, register_command

try:
    from cerberus.agents import Agent
except Exception:  # pragma: no cover - optional runtime dependency
    Agent = Any  # type: ignore[assignment]

try:
    from cerberus.util import visualize_agent_graph  # type: ignore[attr-defined]
except Exception:  # pragma: no cover - function removed in current tree
    def visualize_agent_graph(_agent: Any) -> None:
        return


console = Console()

__all__ = [
    "AgentConfig",
    "RuntimeContext",
    "SecurityAgent",
    "AgentRegistry",
    "AgentManager",
    "AgentCommand",
    "main",
]


def _clean_agent_key(agent_name: str) -> str:
    key = agent_name.strip()
    if key.endswith("_agent"):
        key = key[: -len("_agent")]
    key = re.sub(r"[^A-Za-z0-9]+", "_", key)
    return key.upper()


def _safe_len(value: Any) -> int:
    try:
        return len(value)
    except Exception:
        return 0


def _resolve_instructions(agent: Any) -> str:
    instructions = getattr(agent, "instructions", "")
    if callable(instructions):
        try:
            resolved = instructions(context_variables={})
        except TypeError:
            resolved = instructions()
        except Exception:
            resolved = ""
        return str(resolved)
    return str(instructions or "")


def _resolve_agent_key(agent_id: str, agents_to_display: Dict[str, Any]) -> Optional[str]:
    if agent_id.isdigit():
        index = int(agent_id)
        if 1 <= index <= len(agents_to_display):
            return list(agents_to_display.keys())[index - 1]
        return None

    lowered = agent_id.lower()
    for key, agent in agents_to_display.items():
        if key == agent_id:
            return key
        name = str(getattr(agent, "name", "")).lower()
        if name == lowered:
            return key
    return None


class AgentConfig(BaseModel):
    key: str
    name: Optional[str] = None
    persona: Optional[str] = None
    system_prompt: Optional[str] = None
    model: Optional[str] = None
    capabilities: List[str] = Field(default_factory=list)
    required_tools: List[str] = Field(default_factory=list)

    @field_validator("key")
    @classmethod
    def key_must_be_nonempty(cls, value: str) -> str:
        if not value or not isinstance(value, str):
            raise ValueError("agent key must be a non-empty string")
        return value


@dataclass
class RuntimeContext:
    workspace: Dict[str, Any] = field(default_factory=dict)
    memory: Dict[str, Any] = field(default_factory=dict)


class SecurityAgent:
    """A lightweight agent instance with explicit state and async lifecycle."""

    def __init__(self, config: AgentConfig, context: Optional[RuntimeContext] = None):
        self.config = config
        self.context = context or RuntimeContext()
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self.state: Dict[str, Any] = {}

    @property
    def key(self) -> str:
        return self.config.key

    async def initialize(self) -> None:
        missing = [tool for tool in self.config.required_tools if not os.getenv(tool)]
        if missing:
            raise RuntimeError(f"Missing required tool(s) or env keys: {', '.join(missing)}")
        self.state["persona"] = self.config.persona or ""
        self.state["model"] = self.config.model or os.getenv("DEFAULT_MODEL", "<unset>")

    async def run(self) -> None:
        self._running = True
        try:
            while self._running:
                await asyncio.sleep(0.05)
        finally:
            self._running = False

    async def stop(self) -> None:
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    def spawn(self) -> None:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop and loop.is_running():
            if not self._task or self._task.done():
                self._task = loop.create_task(self.run())
        else:
            asyncio.run(self.run())

    def handoff_state(self) -> Dict[str, Any]:
        return dict(self.state)

    def accept_handoff(self, state: Dict[str, Any]) -> None:
        self.state.update(state)


class AgentRegistry:
    def __init__(self, path: Optional[Path] = None):
        self.path = Path(path) if path else None
        self._configs: Dict[str, AgentConfig] = {}

    def load(self, path: Optional[Path] = None) -> None:
        config_path = Path(path or self.path or "agents.json")
        if not config_path.exists():
            return

        text = config_path.read_text(encoding="utf8")
        if config_path.suffix in (".yml", ".yaml") and yaml:
            data = yaml.safe_load(text)
        else:
            data = json.loads(text)

        if not isinstance(data, list):
            raise RuntimeError("agent registry file must be a list of agent configs")

        for item in data:
            try:
                cfg = AgentConfig(**item)
            except PydanticValidationError as exc:
                raise RuntimeError(f"Invalid agent config: {exc}") from exc
            self._configs[cfg.key] = cfg

    def list(self) -> List[AgentConfig]:
        return list(self._configs.values())

    def get(self, key: str) -> Optional[AgentConfig]:
        return self._configs.get(key)

    @staticmethod
    def on_config_changed(_name: str, _value: Any) -> None:
        """Best-effort compatibility hook for config command notifications."""
        return


class AgentManager:
    def __init__(self, registry: AgentRegistry):
        self.registry = registry
        self.active: Optional[SecurityAgent] = None
        self.instances: Dict[str, SecurityAgent] = {}

    def list_available(self) -> List[str]:
        return [config.key for config in self.registry.list()]

    async def load(
        self,
        key: str,
        inject_capabilities: Optional[List[str]] = None,
        context: Optional[RuntimeContext] = None,
    ) -> SecurityAgent:
        cfg = self.registry.get(key)
        if not cfg:
            raise KeyError(f"Unknown agent: {key}")

        injected = cfg.model_copy()
        if inject_capabilities:
            injected.capabilities = list({*injected.capabilities, *inject_capabilities})

        agent = SecurityAgent(injected, context=context)
        await agent.initialize()
        self.instances[agent.key] = agent

        if self.active:
            handoff = self.active.handoff_state()
            agent.accept_handoff(handoff)
            await self.active.stop()

        self.active = agent
        return agent

    def status(self) -> Dict[str, Any]:
        return {
            "active": self.active.key if self.active else None,
            "instances": list(self.instances.keys()),
        }

    async def spawn_subagent(
        self,
        parent_key: str,
        child_key: str,
        capabilities: Optional[List[str]] = None,
    ) -> SecurityAgent:
        parent = self.instances.get(parent_key)
        if not parent:
            raise KeyError(f"Parent agent not found: {parent_key}")

        ctx = RuntimeContext(
            workspace=dict(parent.context.workspace),
            memory=dict(parent.context.memory),
        )
        child = await self.load(child_key, inject_capabilities=capabilities, context=ctx)
        child.spawn()
        return child


class AgentCommand(Command):
    """Legacy `/agent` command surface kept for CLI/test compatibility."""

    def __init__(self) -> None:
        super().__init__(
            name="/agent",
            description="Manage and switch between agents",
            aliases=["/a"],
        )
        self._subcommands = {
            "list": "List available agents",
            "select": "Select an agent by name or number",
            "info": "Show information about an agent",
            "multi": "Enable multi-agent mode",
            "current": "Show current agent configuration",
        }

    def _get_model_display(self, agent_name: str, agent: Any) -> str:
        ctf_model = os.getenv("CTF_MODEL")
        model = str(getattr(agent, "model", ""))
        if ctf_model and model == ctf_model:
            return ""

        env_var_name = f"CERBERUS_{_clean_agent_key(agent_name)}_MODEL"
        return os.getenv(env_var_name) or model

    def _get_model_display_for_info(self, agent_name: str, agent: Any) -> str:
        ctf_model = os.getenv("CTF_MODEL")
        model = str(getattr(agent, "model", ""))
        if ctf_model and model == ctf_model:
            return "Default CTF Model"

        env_var_name = f"CERBERUS_{_clean_agent_key(agent_name)}_MODEL"
        return os.getenv(env_var_name) or model

    def get_subcommands(self) -> List[str]:
        return list(self._subcommands.keys())

    def get_subcommand_description(self, subcommand: str) -> str:
        return self._subcommands.get(subcommand, "")

    def handle(self, args: Optional[List[str]] = None) -> bool:
        if not args:
            return self.handle_current([])

        subcommand = args[0]
        if subcommand in self._subcommands:
            handler = getattr(self, f"handle_{subcommand}", None)
            if handler:
                return bool(handler(args[1:] if len(args) > 1 else []))

        return self.handle_select(args)

    def handle_list(self, args: Optional[List[str]] = None) -> bool:  # pylint: disable=unused-argument
        agents_to_display = get_available_agents()

        agents_table = Table(title="Available Agents")
        agents_table.add_column("#", style="dim")
        agents_table.add_column("Name", style="cyan")
        agents_table.add_column("Key", style="magenta")
        agents_table.add_column("Module", style="green")
        agents_table.add_column("Description", style="white")

        for index, (agent_key, agent) in enumerate(agents_to_display.items(), 1):
            description = getattr(agent, "description", "") or _resolve_instructions(agent)
            description = " ".join(str(description).split())
            agents_table.add_row(
                str(index),
                str(getattr(agent, "name", agent_key)),
                agent_key,
                get_agent_module(agent_key),
                description[:200] + ("..." if len(description) > 200 else ""),
            )

        console.print(agents_table)
        return True

    def handle_select(self, args: Optional[List[str]] = None) -> bool:
        if not args:
            console.print("[red]Error: No agent specified[/red]")
            console.print("Usage: /agent select <agent_key|number>")
            return False

        agents_to_display = get_available_agents()
        agent_key = _resolve_agent_key(args[0], agents_to_display)
        if not agent_key:
            console.print(f"[red]Error: Unknown agent key: {args[0]}[/red]")
            return False

        agent = agents_to_display[agent_key]
        os.environ["CERBERUS_AGENT_TYPE"] = agent_key
        os.environ["CERBERUS_PARALLEL"] = "1"

        console.print(f"[green]Switched to agent: {getattr(agent, 'name', agent_key)}[/green]")
        try:
            visualize_agent_graph(agent)
        except Exception:
            pass
        return True

    def handle_info(self, args: Optional[List[str]] = None) -> bool:
        if not args:
            console.print("[red]Error: No agent specified[/red]")
            console.print("Usage: /agent info <agent_key|number>")
            return False

        agents_to_display = get_available_agents()
        agent_key = _resolve_agent_key(args[0], agents_to_display)
        if not agent_key:
            console.print(f"[red]Error: Unknown agent key: {args[0]}[/red]")
            return False

        agent = agents_to_display[agent_key]
        name = str(getattr(agent, "name", agent_key))
        description = " ".join(str(getattr(agent, "description", "N/A") or "N/A").split())
        instructions = _resolve_instructions(agent)
        output_type = getattr(agent, "output_type", None) or "N/A"

        markdown_content = f"""
# Agent Info: {name}

| Property               | Value                         |
|------------------------|-------------------------------|
| Key                    | {agent_key}                   |
| Name                   | {name}                        |
| Description            | {description}                 |
| Functions              | {_safe_len(getattr(agent, 'functions', []))}              |
| Parallel Tool Calls    | {"Yes" if getattr(agent, 'parallel_tool_calls', False) else "No"} |
| Handoff Description    | {getattr(agent, 'handoff_description', None) or 'N/A'}                |
| Handoffs               | {_safe_len(getattr(agent, 'handoffs', []))}               |
| Tools                  | {_safe_len(getattr(agent, 'tools', []))}                  |
| Input Guardrails       | {_safe_len(getattr(agent, 'input_guardrails', []))}          |
| Output Guardrails      | {_safe_len(getattr(agent, 'output_guardrails', []))}         |
| Output Type            | {output_type}                 |
| Hooks                  | {_safe_len(getattr(agent, 'hooks', []))}                  |

## Instructions
{instructions}
"""
        console.print(Markdown(markdown_content))
        return True

    def handle_current(self, args: Optional[List[str]] = None) -> bool:  # pylint: disable=unused-argument
        parallel_count = int(os.getenv("CERBERUS_PARALLEL", os.getenv("CERBERUS_PARALLEL", "1")))
        try:
            from cerberus.repl.commands.parallel import PARALLEL_CONFIGS
        except Exception:
            PARALLEL_CONFIGS = []

        agents_to_display = get_available_agents()
        if parallel_count >= 2 and PARALLEL_CONFIGS:
            lines = [
                "[bold cyan]Active Pattern:[/bold cyan] Parallel Configuration",
                "[bold]Mode:[/bold] Parallel Execution",
                f"[bold]Agent Count:[/bold] {len(PARALLEL_CONFIGS)}",
                "",
                "[bold]Configured Agents:[/bold]",
            ]
            for index, config in enumerate(PARALLEL_CONFIGS, 1):
                agent = agents_to_display.get(config.agent_name)
                display_name = getattr(agent, "name", config.agent_name) if agent else config.agent_name
                model_info = f" [{config.model}]" if getattr(config, "model", None) else ""
                agent_id = getattr(config, "id", None) or f"P{index}"
                lines.append(f"  {index}. {display_name} ({config.agent_name}) [{agent_id}]{model_info}")

            console.print(
                Panel(
                    "\n".join(lines),
                    title="Current Configuration",
                    border_style="yellow",
                    expand=False,
                )
            )
            return True

        current_agent_key = os.getenv("CERBERUS_AGENT_TYPE", next(iter(agents_to_display), ""))
        if current_agent_key not in agents_to_display:
            console.print(f"[red]Error: Current agent '{current_agent_key}' not found[/red]")
            return False

        current_agent = agents_to_display[current_agent_key]
        content = [
            f"[bold cyan]Active Agent:[/bold cyan] {getattr(current_agent, 'name', current_agent_key)}",
            f"[bold]Agent Key:[/bold] {current_agent_key}",
            f"[bold]Model:[/bold] {self._get_model_display_for_info(current_agent_key, current_agent)}",
            f"[bold]Tools:[/bold] {_safe_len(getattr(current_agent, 'tools', []))}",
            f"[bold]Handoffs:[/bold] {_safe_len(getattr(current_agent, 'handoffs', []))}",
        ]
        console.print(
            Panel(
                "\n".join(content),
                title="Current Configuration",
                border_style="green",
                expand=False,
            )
        )
        return True

    def handle_multi(self, args: Optional[List[str]] = None) -> bool:  # pylint: disable=unused-argument
        console.print("[yellow]Use /parallel for multi-agent configuration[/yellow]")
        return True


def _print_json(obj: Any) -> None:
    try:
        print(json.dumps(obj, indent=2))
    except Exception:
        print(obj)


async def main(argv: Optional[List[str]] = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="agent-manager")
    parser.add_argument("cmd", choices=["list_available", "load", "status", "spawn_subagent"])
    parser.add_argument("keys", nargs="*", help="Keys for load/spawn operations")
    parser.add_argument("--caps", help="Comma separated capabilities to inject", default="")
    parser.add_argument("--registry", help="Path to agent registry (json|yaml)", default="agents.json")
    args = parser.parse_args(argv)

    registry = AgentRegistry(Path(args.registry))
    try:
        registry.load()
    except Exception as exc:
        print(f"Failed to load registry: {exc}")

    manager = AgentManager(registry)
    caps = [cap.strip() for cap in args.caps.split(",") if cap.strip()]

    if args.cmd == "list_available":
        _print_json(manager.list_available())
        return 0

    if args.cmd == "status":
        _print_json(manager.status())
        return 0

    if args.cmd == "load":
        if not args.keys:
            print("load requires an agent key")
            return 2
        key = args.keys[0]
        try:
            agent = await manager.load(key, inject_capabilities=caps)
        except Exception as exc:
            print(f"Failed to load agent: {exc}")
            return 3
        _print_json({"loaded": agent.key, "capabilities": agent.config.capabilities})
        return 0

    if args.cmd == "spawn_subagent":
        if not args.keys or len(args.keys) < 2:
            print("spawn_subagent requires parent_key and child_key")
            return 2
        parent_key, child_key = args.keys[0], args.keys[1]
        try:
            child = await manager.spawn_subagent(parent_key, child_key, capabilities=caps)
        except Exception as exc:
            print(f"Failed to spawn subagent: {exc}")
            return 4
        _print_json({"spawned": child.key, "capabilities": child.config.capabilities})
        return 0

    return 0


AGENT_COMMAND_INSTANCE = AgentCommand()
register_command(AGENT_COMMAND_INSTANCE)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
