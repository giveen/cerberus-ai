"""Interactive onboarding bootstrapper for Cerebro REPL."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Literal, Mapping, Optional, Sequence

from pydantic import BaseModel, Field
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskID, TextColumn, TimeElapsedColumn
from rich.prompt import Confirm, Prompt
from rich.table import Table

from cai.memory import MemoryManager
from cai.repl.commands.base import FrameworkCommand, get_command, register_command
from cai.tools.workspace import ProjectSpace

console = Console()

_PROJECT_NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")


class EngagementTemplate(BaseModel):
    key: str
    title: str
    summary: str
    primary_agent: str
    supporting_agents: List[str] = Field(default_factory=list)
    required_tools: List[str] = Field(default_factory=list)
    starter_prompt: str


class AuditSnapshot(BaseModel):
    runtime_env_ok: bool = False
    platform_mode: str = "unknown"
    nmap_available: bool = False
    missing_tools: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)


class OnboardingState(BaseModel):
    project_name: str
    workspace_dir: str
    workspace_root: str
    provider: Literal["openai", "anthropic", "local"]
    model: str
    local_endpoint: Optional[str] = None
    api_key_configured: bool = False
    rules_acknowledged: bool = False
    template: EngagementTemplate
    audit: AuditSnapshot
    completed_at: str


class QuickstartOptions(BaseModel):
    project_name: Optional[str] = None
    workspace_dir: Optional[str] = None
    provider: Optional[Literal["openai", "anthropic", "local"]] = None
    template: Optional[str] = None
    model: Optional[str] = None
    api_key: Optional[str] = None
    local_endpoint: Optional[str] = None
    acknowledge_roe: bool = False
    json_output: bool = False
    status: bool = False
    reset: bool = False
    non_interactive: bool = False


class OnboardingManager:
    """Drive a commercial onboarding flow across config, workspace, and audit layers."""

    _DEFAULT_MODELS: Mapping[str, str] = {
        "openai": "gpt-4o",
        "anthropic": "claude-sonnet-4-20250514",
        "local": "llama3.1",
    }

    _TEMPLATES: Dict[str, EngagementTemplate] = {
        "external-web-audit": EngagementTemplate(
            key="external-web-audit",
            title="External Web Audit",
            summary="Bootstrap a customer-facing web assessment with recon, exploitation, and reporting coverage.",
            primary_agent="web_pentester_agent",
            supporting_agents=["bug_bounter_agent", "reporting_agent"],
            required_tools=["curl", "wget", "nmap"],
            starter_prompt="Assess the authorized external web surface, prioritize exploitable findings, and prepare evidence for customer reporting.",
        ),
        "internal-network-discovery": EngagementTemplate(
            key="internal-network-discovery",
            title="Internal Network Discovery",
            summary="Prepare a lateral-movement and service-enumeration engagement inside an authorized network.",
            primary_agent="redteam_agent",
            supporting_agents=["network_security_analyzer_agent", "reporting_agent"],
            required_tools=["nmap", "ssh", "tcpdump"],
            starter_prompt="Enumerate the authorized internal address space, map exposed services, and identify pivot opportunities without exceeding scope.",
        ),
        "compliance-policy-review": EngagementTemplate(
            key="compliance-policy-review",
            title="Compliance/Policy Review",
            summary="Stage a governance-oriented review with defensive analysis and reporting deliverables.",
            primary_agent="blueteam_agent",
            supporting_agents=["reporting_agent"],
            required_tools=["curl", "ssh"],
            starter_prompt="Review the authorized control set, identify policy gaps, and produce remediation-oriented findings suitable for compliance stakeholders.",
        ),
    }

    def __init__(self, *, memory: MemoryManager, session_user: str) -> None:
        self._memory = memory
        self._session_user = session_user

    async def run(self, options: QuickstartOptions) -> OnboardingState:
        self._render_banner()

        progress = Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=28),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        )

        with progress:
            stage_ids = {
                "safety": progress.add_task("Safety briefing", total=1),
                "workspace": progress.add_task("Workspace bootstrap", total=1),
                "provider": progress.add_task("Provider configuration", total=1),
                "audit": progress.add_task("Environment audit", total=1),
                "template": progress.add_task("Template injection", total=1),
                "persist": progress.add_task("Persistence", total=1),
            }

            rules_acknowledged = await self._rules_of_engagement(options, stage_ids["safety"], progress)
            project_name, workspace_dir, workspace_root = await self._configure_workspace(options, stage_ids["workspace"], progress)
            provider, model, local_endpoint, api_key_configured = await self._configure_provider(options, stage_ids["provider"], progress)
            audit = await self._run_environment_audit(stage_ids["audit"], progress)
            template = await self._select_template(options, stage_ids["template"], progress)

            state = OnboardingState(
                project_name=project_name,
                workspace_dir=str(workspace_dir),
                workspace_root=str(workspace_root),
                provider=provider,
                model=model,
                local_endpoint=local_endpoint,
                api_key_configured=api_key_configured,
                rules_acknowledged=rules_acknowledged,
                template=template,
                audit=audit,
                completed_at=datetime.now(tz=UTC).isoformat(),
            )
            await self._persist_state(state, stage_ids["persist"], progress)

        self._render_completion(state)
        return state

    def load_state(self) -> Optional[OnboardingState]:
        path = self._state_path()
        if not path.exists():
            return None
        try:
            return OnboardingState.model_validate(json.loads(path.read_text(encoding="utf-8")))
        except Exception:
            return None

    def reset_state(self) -> bool:
        removed = False
        for path in (self._state_path(), self._brief_path()):
            if path.exists():
                path.unlink()
                removed = True
        return removed

    async def _rules_of_engagement(self, options: QuickstartOptions, task_id: TaskID, progress: Progress) -> bool:
        self._render_rules_panel()
        acknowledged = options.acknowledge_roe
        if not acknowledged:
            token = await self._ask(
                "Type AUTHORIZED to confirm you will only assess systems with written authorization",
                default="",
            )
            acknowledged = token.strip().upper() == "AUTHORIZED"

        if not acknowledged:
            raise RuntimeError("Rules of engagement acknowledgement is mandatory")

        progress.update(task_id, advance=1, description="Safety briefing acknowledged")
        return True

    async def _configure_workspace(
        self,
        options: QuickstartOptions,
        task_id: TaskID,
        progress: Progress,
    ) -> tuple[str, Path, Path]:
        project_name = options.project_name or await self._ask(
            "Project name",
            default=f"engagement-{datetime.now(tz=UTC).strftime('%Y%m%d')}",
        )
        project_name = project_name.strip()
        if not _PROJECT_NAME_RE.match(project_name):
            raise RuntimeError("Project name must use letters, numbers, hyphens, or underscores")

        default_workspace_dir = options.workspace_dir or str((Path.cwd() / "workspaces").resolve())
        workspace_dir = Path(
            options.workspace_dir
            or default_workspace_dir
            if options.non_interactive
            else await self._ask("Workspace directory", default=default_workspace_dir)
        ).expanduser().resolve()

        await self._invoke_command("config", ["set", "CEREBRO_WORKSPACE_DIR", str(workspace_dir)])
        await self._invoke_command("/workspace", ["set", project_name])
        await self._invoke_command("config", ["set", "CEREBRO_WORKSPACE", project_name, "--persist"])
        await self._invoke_command("config", ["set", "CEREBRO_WORKSPACE_DIR", str(workspace_dir), "--persist"])
        self._reset_workspace_scoped_caches()

        project_space = ProjectSpace.from_environment()
        workspace_root = project_space.initialize()
        os.environ["WORKSPACE_ROOT"] = str(workspace_root)
        await self._invoke_command("env", ["set", "WORKSPACE_ROOT", str(workspace_root)])

        progress.update(task_id, advance=1, description=f"Workspace ready: {project_name}")
        return project_name, workspace_dir, workspace_root

    async def _configure_provider(
        self,
        options: QuickstartOptions,
        task_id: TaskID,
        progress: Progress,
    ) -> tuple[Literal["openai", "anthropic", "local"], str, Optional[str], bool]:
        provider = options.provider or await self._choose_provider()
        model = options.model or self._DEFAULT_MODELS[provider]
        local_endpoint: Optional[str] = None
        api_key_configured = False

        if provider == "openai":
            api_key_configured = await self._persist_secret_if_needed("OPENAI_API_KEY", options.api_key, "OpenAI API key")
        elif provider == "anthropic":
            api_key_configured = await self._persist_secret_if_needed("ANTHROPIC_API_KEY", options.api_key, "Anthropic API key")
        else:
            local_endpoint = options.local_endpoint or (
                "http://127.0.0.1:11434/v1"
                if options.non_interactive
                else await self._ask(
                    "Local provider endpoint",
                    default="http://127.0.0.1:11434/v1",
                )
            )
            api_key_configured = await self._check_local_endpoint(local_endpoint)

        if options.model:
            model = options.model.strip() or model
        elif not options.non_interactive:
            chosen_model = await self._ask(
                "Default model",
                default=model,
            )
            model = chosen_model.strip() or model

        await self._invoke_command("/model", [model])
        await self._invoke_command("config", ["set", "CEREBRO_MODEL", model, "--persist"])

        progress.update(task_id, advance=1, description=f"Provider configured: {provider}")
        return provider, model, local_endpoint, api_key_configured

    async def _run_environment_audit(self, task_id: TaskID, progress: Progress) -> AuditSnapshot:
        env_ok = await self._invoke_command("env", ["audit"])

        from cai.repl.commands.platform import get_system_auditor

        platform_specs = await get_system_auditor(self._memory).audit(refresh=True)
        tool_map = {tool.name: tool.available for tool in platform_specs.tools}
        required = ["nmap", "curl", "ssh"]
        missing = [name for name in required if not tool_map.get(name, False)]
        warnings: List[str] = []
        if missing:
            warnings.append("Missing recommended tooling: " + ", ".join(missing))

        self._render_audit_summary(platform_specs.virtualization.summary, tool_map, missing, env_ok)

        progress.update(task_id, advance=1, description="Environment audit complete")
        return AuditSnapshot(
            runtime_env_ok=env_ok,
            platform_mode=platform_specs.virtualization.summary,
            nmap_available=tool_map.get("nmap", False),
            missing_tools=missing,
            warnings=warnings,
        )

    async def _select_template(
        self,
        options: QuickstartOptions,
        task_id: TaskID,
        progress: Progress,
    ) -> EngagementTemplate:
        template_key = options.template or await self._choose_template()
        template = self._TEMPLATES.get(template_key)
        if template is None:
            raise RuntimeError(f"Unknown template '{template_key}'")

        await self._invoke_command("config", ["set", "CEREBRO_AGENT_TYPE", template.primary_agent, "--persist"])
        self._render_template_summary(template)

        progress.update(task_id, advance=1, description=f"Template loaded: {template.title}")
        return template

    async def _persist_state(self, state: OnboardingState, task_id: TaskID, progress: Progress) -> None:
        state_path = self._state_path()
        brief_path = self._brief_path()
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state_path.write_text(json.dumps(state.model_dump(mode="json"), indent=2, ensure_ascii=True), encoding="utf-8")
        brief_path.write_text(self._build_bootstrap_brief(state), encoding="utf-8")

        self._memory.record(
            {
                "topic": "quickstart.onboarding",
                "finding": f"Onboarding completed for workspace {state.project_name}",
                "source": "quickstart_command",
                "tags": ["quickstart", "onboarding", state.provider, state.template.key],
                "artifacts": {
                    "workspace_root": state.workspace_root,
                    "model": state.model,
                    "primary_agent": state.template.primary_agent,
                },
            }
        )

        progress.update(task_id, advance=1, description="Selections persisted")

    async def _persist_secret_if_needed(self, env_name: str, supplied_value: Optional[str], label: str) -> bool:
        existing = os.getenv(env_name, "").strip()
        if existing and not supplied_value:
            keep_existing = await self._confirm(f"Use existing {label}?", default=True)
            if keep_existing:
                return True

        secret = supplied_value
        if secret is None:
            secret = await self._ask(label, default="", password=True)

        if not secret:
            return bool(existing)

        ok = await self._invoke_command("config", ["set", env_name, secret, "--persist"])
        return ok

    async def _check_local_endpoint(self, endpoint: str) -> bool:
        try:
            import httpx

            async with httpx.AsyncClient(timeout=2.0) as client:
                response = await client.get(endpoint)
                return response.status_code < 500
        except Exception:
            return False

    async def _invoke_command(self, command_name: str, args: List[str]) -> bool:
        command = self._new_command(command_name)
        if command is None:
            raise RuntimeError(f"Required command '{command_name}' is not registered")
        return await command.execute(args)

    def _new_command(self, command_name: str) -> Optional[FrameworkCommand]:
        if command_name == "config":
            from cai.repl.commands.config import ConfigCommand

            return ConfigCommand()
        if command_name == "/workspace":
            from cai.repl.commands.workspace import WorkspaceCommand

            return WorkspaceCommand()
        if command_name == "env":
            from cai.repl.commands import env as env_module

            env_module.ENV_AUDITOR = env_module.EnvironmentAuditor()
            return env_module.EnvCommand()
        if command_name == "/model":
            from cai.repl.commands import model as model_module

            model_module._GLOBAL_ORCHESTRATOR = None
            return model_module.ModelCommand()
        if command_name == "/platform":
            from cai.repl.commands import platform as platform_module

            platform_module._GLOBAL_AUDITOR = None
            return platform_module.PlatformCommand()
        return get_command(command_name)

    def _reset_workspace_scoped_caches(self) -> None:
        from cai.tools import workspace as workspace_module

        workspace_module._ACTIVE_SPACE = None

        try:
            from cai.repl.commands import model as model_module

            model_module._GLOBAL_ORCHESTRATOR = None
        except Exception:
            pass

        try:
            from cai.repl.commands import platform as platform_module

            platform_module._GLOBAL_AUDITOR = None
        except Exception:
            pass

    async def _ask(
        self,
        prompt: str,
        *,
        default: Optional[str] = None,
        password: bool = False,
    ) -> str:
        response = await asyncio.to_thread(Prompt.ask, prompt, default=default, password=password)
        return response or ""

    async def _confirm(self, prompt: str, *, default: bool = False) -> bool:
        return await asyncio.to_thread(Confirm.ask, prompt, default=default)

    async def _choose_provider(self) -> Literal["openai", "anthropic", "local"]:
        choice = await self._ask(
            "Provider [openai/anthropic/local]",
            default="openai",
        )
        normalized = choice.strip().lower()
        if normalized not in {"openai", "anthropic", "local"}:
            raise RuntimeError("Provider must be one of: openai, anthropic, local")
        return normalized  # type: ignore[return-value]

    async def _choose_template(self) -> str:
        table = Table(title="Engagement Templates", box=box.SIMPLE_HEAVY)
        table.add_column("Key", style="cyan")
        table.add_column("Template", style="white")
        table.add_column("Primary Agent", style="magenta")
        for template in self._TEMPLATES.values():
            table.add_row(template.key, template.title, template.primary_agent)
        console.print(table)
        choice = await self._ask(
            "Template key",
            default="external-web-audit",
        )
        return choice.strip().lower()

    def _state_path(self) -> Path:
        project_space = ProjectSpace.from_environment()
        project_space.initialize()
        return project_space.get_path(".cai", "session", "quickstart_state.json", create_parent=True)

    def _brief_path(self) -> Path:
        project_space = ProjectSpace.from_environment()
        project_space.initialize()
        return project_space.get_path(".cai", "session", "engagement_bootstrap.md", create_parent=True)

    def _build_bootstrap_brief(self, state: OnboardingState) -> str:
        lines = [
            "# Engagement Bootstrap",
            "",
            f"Project: {state.project_name}",
            f"Workspace: {state.workspace_root}",
            f"Provider: {state.provider}",
            f"Model: {state.model}",
            f"Primary agent: {state.template.primary_agent}",
            f"Supporting agents: {', '.join(state.template.supporting_agents) if state.template.supporting_agents else 'none'}",
            f"Required tools: {', '.join(state.template.required_tools) if state.template.required_tools else 'none'}",
            "",
            "## Starter Objective",
            state.template.starter_prompt,
        ]
        if state.local_endpoint:
            lines.extend(["", f"Local endpoint: {state.local_endpoint}"])
        return "\n".join(lines) + "\n"

    def _render_banner(self) -> None:
        console.print(
            Panel(
                "Commercial onboarding bootstrapper for the first 60 seconds of a new engagement.\n"
                "This wizard will initialize a workspace, configure the preferred model provider, audit the runtime, and stage a ready-to-use engagement template.",
                title="Cerebro Quickstart",
                border_style="cyan",
                box=box.DOUBLE,
            )
        )

    def _render_rules_panel(self) -> None:
        table = Table(box=box.SIMPLE_HEAVY, title="Rules of Engagement")
        table.add_column("Control", style="cyan")
        table.add_column("Requirement", style="white")
        table.add_row("Authorization", "Operate only on targets covered by written authorization")
        table.add_row("Scope", "Do not exceed the approved IP ranges, domains, or accounts")
        table.add_row("Safety", "Avoid destructive actions and preserve evidence for reporting")
        table.add_row("Compliance", "Treat collected data as confidential customer material")
        console.print(table)

    def _render_audit_summary(
        self,
        platform_mode: str,
        tool_map: Mapping[str, bool],
        missing_tools: Sequence[str],
        env_ok: bool,
    ) -> None:
        table = Table(title="Bootstrap Audit Summary", box=box.SIMPLE)
        table.add_column("Check", style="cyan")
        table.add_column("Status", style="white")
        table.add_row("Environment integrity", "pass" if env_ok else "attention")
        table.add_row("Execution mode", platform_mode)
        table.add_row("Nmap", "present" if tool_map.get("nmap", False) else "missing")
        table.add_row("Curl", "present" if tool_map.get("curl", False) else "missing")
        table.add_row("SSH", "present" if tool_map.get("ssh", False) else "missing")
        table.add_row("Missing tools", ", ".join(missing_tools) if missing_tools else "none")
        console.print(table)

    def _render_template_summary(self, template: EngagementTemplate) -> None:
        table = Table(title="Template Loaded", box=box.ROUNDED)
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="white")
        table.add_row("Template", template.title)
        table.add_row("Primary agent", template.primary_agent)
        table.add_row("Supporting agents", ", ".join(template.supporting_agents) if template.supporting_agents else "none")
        table.add_row("Required tools", ", ".join(template.required_tools) if template.required_tools else "none")
        console.print(table)

    def _render_completion(self, state: OnboardingState) -> None:
        summary = Table(title="Onboarding Complete", box=box.SIMPLE_HEAVY)
        summary.add_column("Field", style="cyan")
        summary.add_column("Value", style="white")
        summary.add_row("Workspace", state.workspace_root)
        summary.add_row("Provider", state.provider)
        summary.add_row("Model", state.model)
        summary.add_row("Primary agent", state.template.primary_agent)
        summary.add_row("Template", state.template.title)
        summary.add_row("Bootstrap brief", str(self._brief_path()))
        console.print(summary)
        console.print(
            Panel(
                "Next commands:\n"
                "1. /config show\n"
                "2. /platform --table\n"
                f"3. Start the engagement with: {state.template.starter_prompt}",
                title="Ready",
                border_style="green",
            )
        )


class QuickstartCommand(FrameworkCommand):
    """Interactive environment bootstrapper for new Cerebro engagements."""

    name = "/quickstart"
    description = "Run the onboarding wizard for workspace, provider, audit, and template setup"
    aliases = ["/qs", "/quick"]

    def __init__(self) -> None:
        super().__init__()
        self._memory = self._resolve_memory_manager()
        self._manager = OnboardingManager(memory=self._memory, session_user=self.session.user)

    @property
    def help(self) -> str:
        return (
            "Usage: /quickstart [options]\n\n"
            "Interactive mode:\n"
            "  /quickstart\n\n"
            "Status and maintenance:\n"
            "  /quickstart status\n"
            "  /quickstart reset\n\n"
            "Non-interactive bootstrap:\n"
            "  /quickstart --non-interactive --project <name> --provider <openai|anthropic|local> --template <key> --acknowledge-roe\n"
            "              [--workspace-dir <dir>] [--api-key <key>] [--local-endpoint <url>] [--model <id>] [--json]\n"
        )

    async def execute(self, args: List[str]) -> bool:
        if args and args[0] in {"help", "--help", "-h"}:
            console.print(self.help)
            return True

        options = self._parse_args(args)

        if options.status:
            return self._show_status(json_output=options.json_output)

        if options.reset:
            removed = self._manager.reset_state()
            console.print("[green]Quickstart state cleared.[/green]" if removed else "[yellow]No quickstart state found.[/yellow]")
            return True

        if options.non_interactive and not options.acknowledge_roe:
            console.print("[red]Non-interactive mode requires --acknowledge-roe[/red]")
            return False

        if options.non_interactive and (not options.project_name or not options.provider or not options.template):
            console.print("[red]Non-interactive mode requires --project, --provider, and --template[/red]")
            return False

        try:
            state = await self._manager.run(options)
        except RuntimeError as exc:
            console.print(f"[red]quickstart: {exc}[/red]")
            return False

        if options.json_output:
            console.print(json.dumps(state.model_dump(mode="json"), indent=2, ensure_ascii=True))
        return True

    def _show_status(self, *, json_output: bool) -> bool:
        state = self._manager.load_state()
        if state is None:
            console.print("[yellow]No persisted quickstart state found for the current workspace.[/yellow]")
            return True

        if json_output:
            console.print(json.dumps(state.model_dump(mode="json"), indent=2, ensure_ascii=True))
            return True

        self._manager._render_completion(state)  # pylint: disable=protected-access
        return True

    def _parse_args(self, args: Sequence[str]) -> QuickstartOptions:
        options = QuickstartOptions()
        i = 0
        while i < len(args):
            token = args[i]
            if token == "status":
                options.status = True
                i += 1
                continue
            if token == "reset":
                options.reset = True
                i += 1
                continue
            if token == "--json":
                options.json_output = True
                i += 1
                continue
            if token == "--acknowledge-roe":
                options.acknowledge_roe = True
                i += 1
                continue
            if token == "--non-interactive":
                options.non_interactive = True
                i += 1
                continue
            if token in {"--project", "--workspace-dir", "--provider", "--template", "--model", "--api-key", "--local-endpoint"}:
                if i + 1 >= len(args):
                    raise RuntimeError(f"Missing value for {token}")
                value = args[i + 1]
                if token == "--project":
                    options.project_name = value
                elif token == "--workspace-dir":
                    options.workspace_dir = value
                elif token == "--provider":
                    options.provider = value.lower()  # type: ignore[assignment]
                elif token == "--template":
                    options.template = value.lower()
                elif token == "--model":
                    options.model = value
                elif token == "--api-key":
                    options.api_key = value
                elif token == "--local-endpoint":
                    options.local_endpoint = value
                i += 2
                continue
            raise RuntimeError(f"Unknown option: {token}")

        return options

    def _resolve_memory_manager(self) -> MemoryManager:
        if isinstance(self.memory, MemoryManager):
            return self.memory
        return MemoryManager()


QUICKSTART_COMMAND_INSTANCE = QuickstartCommand()
register_command(QUICKSTART_COMMAND_INSTANCE)