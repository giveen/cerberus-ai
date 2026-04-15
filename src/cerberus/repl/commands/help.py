"""Dynamic help command for the Cerberus AI REPL.

This module implements a registry-driven documentation engine so help output is
always synchronized with active command objects.
"""

from __future__ import annotations

from dataclasses import dataclass
import sys
from typing import Dict, List, Optional, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from cerberus.repl.commands.base import COMMAND_ALIASES, COMMANDS, Command, FrameworkCommand, register_command

try:
    from caiextensions.platform.base.platform_manager import PlatformManager  # type: ignore

    HAS_PLATFORM_EXTENSIONS = True
except ImportError:
    PlatformManager = None  # type: ignore[assignment]
    HAS_PLATFORM_EXTENSIONS = False

from cerberus import is_caiextensions_platform_available

console = Console()


def create_styled_table(title: str, headers: List[Tuple[str, str]], header_style: str = "bold white") -> Table:
    """Create a consistently styled rich table."""
    table = Table(title=title, show_header=True, header_style=header_style, box=box.ROUNDED)
    for header, style in headers:
        table.add_column(header, style=style)
    return table


def create_notes_panel(notes: List[str], title: str = "Notes", border_style: str = "yellow") -> Panel:
    """Create a notes panel for contextual guidance."""
    notes_text = Text.from_markup("\n".join(f"• {note}" for note in notes))
    return Panel(notes_text, title=title, border_style=border_style, box=box.ROUNDED)


@dataclass
class CommandDoc:
    """Reflective documentation snapshot for one command."""

    name: str
    aliases: List[str]
    description: str
    help_text: str
    category: str
    risk_level: str
    impact: str
    subcommands: List[Tuple[str, str]]


class DocGenerator:
    """Build dynamic command documentation from the live registry."""

    _CATEGORY_MAP: Dict[str, str] = {
        # Core Operations
        "agent": "Core Operations",
        "memory": "Core Operations",
        "workspace": "Core Operations",
        # Financials & Config
        "cost": "Financials & Config",
        "config": "Financials & Config",
        "env": "Financials & Config",
        # Lifecycle & Utilities
        "exit": "Lifecycle & Utilities",
        "flush": "Lifecycle & Utilities",
        "compact": "Lifecycle & Utilities",
    }

    _RISK_MAP: Dict[str, Tuple[str, str]] = {
        "agent": ("Medium", "Agent switches can alter execution behavior"),
        "memory": ("Low", "Memory actions affect retained context"),
        "workspace": ("Medium", "Workspace operations can move/archive artifacts"),
        "cost": ("Low", "Cost tracking is read-mostly; budget changes affect policy"),
        "config": ("Medium", "Config changes can alter runtime security posture"),
        "env": ("High", "Environment access may expose sensitive host context"),
        "exit": ("Medium", "Shutdown can terminate active sessions"),
        "flush": ("High", "Purge actions can permanently clear volatile state"),
        "compact": ("Medium", "Compaction rewrites active context window"),
        "graph": ("Medium", "Visualization exports may include sensitive findings"),
        "shell": ("High", "Shell execution performs live system commands"),
        "virtualization": ("High", "Container actions can start/stop infrastructure"),
        "mcp": ("Medium", "External integrations extend trust boundaries"),
        "parallel": ("Medium", "Parallel actions increase concurrent side effects"),
        "run": ("Medium", "Queued execution can trigger deferred operations"),
        "kill": ("High", "Process termination can disrupt active engagements"),
    }

    @staticmethod
    def _normalize(name: str) -> str:
        return str(name or "").lstrip("/").strip().lower()

    def _category_for(self, normalized_name: str) -> str:
        return self._CATEGORY_MAP.get(normalized_name, "Extended Operations")

    def _risk_for(self, normalized_name: str) -> Tuple[str, str]:
        return self._RISK_MAP.get(normalized_name, ("Low", "Read-only or low-impact operation"))

    @staticmethod
    def _extract_help(cmd: FrameworkCommand) -> str:
        execute_doc = (getattr(cmd.execute, "__doc__", "") or "").strip()
        if execute_doc:
            return execute_doc

        class_doc = (getattr(cmd.__class__, "__doc__", "") or "").strip()
        if class_doc:
            return class_doc

        try:
            return str(cmd.help)
        except Exception:
            return f"{cmd.name} — {cmd.description}"

    @staticmethod
    def _extract_subcommands(cmd: FrameworkCommand) -> List[Tuple[str, str]]:
        rows: List[Tuple[str, str]] = []
        try:
            for sub in cmd.get_subcommands():
                rows.append((sub, cmd.get_subcommand_description(sub)))
        except Exception:
            pass
        return rows

    def snapshot(self) -> List[CommandDoc]:
        docs: List[CommandDoc] = []
        for _, cmd in sorted(COMMANDS.items(), key=lambda item: self._normalize(item[0])):
            name_norm = self._normalize(cmd.name)
            risk, impact = self._risk_for(name_norm)
            docs.append(
                CommandDoc(
                    name=cmd.name,
                    aliases=list(cmd.aliases),
                    description=str(getattr(cmd, "description", "")),
                    help_text=self._extract_help(cmd),
                    category=self._category_for(name_norm),
                    risk_level=risk,
                    impact=impact,
                    subcommands=self._extract_subcommands(cmd),
                )
            )
        return docs

    def resolve_command_doc(self, token: str) -> Optional[CommandDoc]:
        normalized = self._normalize(token)

        # Resolve from aliases and canonical registry names.
        alias_key = f"/{normalized}"
        resolved_name = COMMAND_ALIASES.get(alias_key) or COMMAND_ALIASES.get(normalized) or token
        cmd = COMMANDS.get(resolved_name)

        if cmd is None:
            # Fallback lookup by normalized key.
            for name, cand in COMMANDS.items():
                if self._normalize(name) == normalized or self._normalize(getattr(cand, "name", "")) == normalized:
                    cmd = cand
                    break

        if cmd is None:
            return None

        name_norm = self._normalize(cmd.name)
        risk, impact = self._risk_for(name_norm)
        return CommandDoc(
            name=cmd.name,
            aliases=list(cmd.aliases),
            description=str(getattr(cmd, "description", "")),
            help_text=self._extract_help(cmd),
            category=self._category_for(name_norm),
            risk_level=risk,
            impact=impact,
            subcommands=self._extract_subcommands(cmd),
        )

    @staticmethod
    def build_examples(name: str) -> List[str]:
        n = name.lstrip("/").lower()
        specific = {
            "help": ["/help", "/help cost", "/help commands"],
            "agent": ["/agent list", "/agent select red_teamer"],
            "memory": ["/memory search credential", "/memory clear red_teamer"],
            "workspace": ["/workspace info", "/workspace archive"],
            "cost": ["/cost show", "/cost budget 25 --currency USD"],
            "config": ["/config list", "/config set CERBERUS_MODEL o4-mini"],
            "env": ["/env show", "/env audit"],
            "flush": ["/flush --memory", "/flush --all --retain-kb"],
            "graph": ["/graph network --format mermaid", "/graph export --layer knowledge --format svg"],
            "exit": ["/exit", "/exit --force"],
            "compact": ["/compact summary", "/compact"],
        }
        return specific.get(n, [f"/{n}", f"/{n} --help"])


class HelpCommand(Command):
    """Registry-driven REPL documentation command."""

    name = "/help"
    description = "Display help information about commands and features with dynamic, risk-aware guidance"
    aliases = ["/h", "/?"]

    def __init__(self) -> None:
        super().__init__(name=self.name, description=self.description, aliases=self.aliases)
        self._docs = DocGenerator()

        # Keep explicit subcommands for backward compatibility and discoverability.
        self.add_subcommand("commands", "List all available commands", self.handle_commands)
        self.add_subcommand("aliases", "Show command alias registry", self.handle_aliases)
        self.add_subcommand("quick", "Show quick command reference", self.handle_quick)
        self.add_subcommand("platform", "Show platform extension help", self.handle_platform)

        # Compatibility entry points expected by older integrations/tests.
        self.add_subcommand("memory", "Show memory command help", self.handle_memory)
        self.add_subcommand("agent", "Show agent command help", self.handle_agent)
        self.add_subcommand("graph", "Show graph command help", self.handle_graph)
        self.add_subcommand("shell", "Show shell command help", self.handle_shell)
        self.add_subcommand("env", "Show env command help", self.handle_env)
        self.add_subcommand("model", "Show model command help", self.handle_model)
        self.add_subcommand("turns", "Show turns control help", self.handle_turns)
        self.add_subcommand("config", "Show config command help", self.handle_config)

    def handle(self, args: Optional[List[str]] = None) -> bool:  # type: ignore[override]
        clean = self.sanitize_args(args)
        if not clean:
            return self.handle_no_args()

        sub = clean[0]
        registered = self.subcommands.get(sub)
        if registered:
            handler = registered.get("handler")
            if callable(handler):
                return bool(handler(clean[1:]))

        handler = getattr(self, f"handle_{sub}", None)
        if callable(handler):
            return bool(handler(clean[1:]))

        return self._render_command_detail(sub)

    @property
    def help(self) -> str:
        return (
            "help [command|subcommand]\n\n"
            "Dynamic documentation features:\n"
            "  - registry-reflective command docs\n"
            "  - professional category grouping\n"
            "  - risk/impact metadata per command\n"
            "  - interactive per-command detail with examples and error codes\n"
        )

    async def execute(self, args: List[str]) -> bool:
        if not args:
            return self.handle_help()

        topic = args[0].lower()

        # Registered help subcommands first.
        handler = getattr(self, f"_sub_{topic}", None)
        if handler:
            return await handler(args[1:])

        # Otherwise interpret as interactive help <command_name>.
        return self._render_command_detail(topic)

    # ------------------------------------------------------------------
    # Core rendering
    # ------------------------------------------------------------------

    def _commands_by_category(self) -> Dict[str, List[CommandDoc]]:
        docs = self._docs.snapshot()
        grouped: Dict[str, List[CommandDoc]] = {
            "Core Operations": [],
            "Financials & Config": [],
            "Lifecycle & Utilities": [],
            "Extended Operations": [],
        }
        for doc in docs:
            grouped.setdefault(doc.category, []).append(doc)
        for key in grouped:
            grouped[key] = sorted(grouped[key], key=lambda d: d.name.lower())
        return grouped

    def _render_overview_dashboard(self) -> bool:
        grouped = self._commands_by_category()

        console.print(
            Panel(
                "Dynamic Command Documentation\n"
                "Source of truth: live command registry (no static command list)",
                title="Cerberus AI Help",
                border_style="blue",
                box=box.ROUNDED,
            )
        )

        for category in ("Core Operations", "Financials & Config", "Lifecycle & Utilities", "Extended Operations"):
            rows = grouped.get(category, [])
            if not rows:
                continue

            table = create_styled_table(
                category,
                [
                    ("Command", "cyan"),
                    ("Description", "white"),
                    ("Risk", "yellow"),
                    ("Impact", "magenta"),
                ],
            )

            for doc in rows:
                primary_alias = doc.aliases[0] if doc.aliases else f"/{doc.name.lstrip('/')}"
                table.add_row(primary_alias, doc.description or "—", doc.risk_level, doc.impact)

            console.print(table)

        console.print(
            create_notes_panel(
                [
                    "Use /help <command> for detailed examples, flags, and error codes.",
                    "Risk metadata indicates potential operational impact before execution.",
                    "Command list is generated at runtime from active registry objects.",
                ],
                title="Usage",
                border_style="green",
            )
        )
        return True

    def _render_command_detail(self, token: str) -> bool:
        doc = self._docs.resolve_command_doc(token)
        if doc is None:
            console.print(f"[red]No help topic found for '{token}'.[/red]")
            return False

        details = Table(title=f"Command Detail: /{doc.name.lstrip('/')}", box=box.ROUNDED)
        details.add_column("Field", style="cyan")
        details.add_column("Value", style="white")

        details.add_row("Description", doc.description or "—")
        details.add_row("Category", doc.category)
        details.add_row("Risk Level", doc.risk_level)
        details.add_row("Impact", doc.impact)
        details.add_row("Aliases", ", ".join(doc.aliases) if doc.aliases else "—")
        console.print(details)

        help_text = doc.help_text.strip() if doc.help_text else "No command-specific usage text is available."
        console.print(Panel(help_text, title="Usage & Behavior", border_style="blue", box=box.ROUNDED))

        if doc.subcommands:
            sub_table = create_styled_table(
                "Subcommands",
                [("Subcommand", "yellow"), ("Description", "white")],
            )
            for sub, desc in doc.subcommands:
                sub_table.add_row(sub, desc or "—")
            console.print(sub_table)

        examples = self._docs.build_examples(doc.name)
        error_codes = [
            "0: Success",
            "1: Command execution failure",
            "2: Input validation / policy violation",
        ]

        console.print(
            create_notes_panel(
                [
                    "Examples:",
                    *examples,
                    "",
                    "Common Error Codes:",
                    *error_codes,
                ],
                title="Examples & Errors",
                border_style="yellow",
            )
        )
        return True

    # ------------------------------------------------------------------
    # Explicit subcommand handlers
    # ------------------------------------------------------------------

    async def _sub_commands(self, _: List[str]) -> bool:
        return self._render_overview_dashboard()

    async def _sub_aliases(self, _: List[str]) -> bool:
        return self.handle_help_aliases()

    async def _sub_quick(self, _: List[str]) -> bool:
        return self.handle_quick()

    async def _sub_platform(self, _: List[str]) -> bool:
        return self.handle_help_platform_manager()

    async def _sub_memory(self, _: List[str]) -> bool:
        return self._render_command_detail("memory")

    async def _sub_agent(self, _: List[str]) -> bool:
        return self._render_command_detail("agent")

    async def _sub_graph(self, _: List[str]) -> bool:
        return self._render_command_detail("graph")

    async def _sub_shell(self, _: List[str]) -> bool:
        return self._render_command_detail("shell")

    async def _sub_env(self, _: List[str]) -> bool:
        return self._render_command_detail("env")

    async def _sub_model(self, _: List[str]) -> bool:
        return self._render_command_detail("model")

    async def _sub_turns(self, _: List[str]) -> bool:
        return self._render_command_detail("turns")

    async def _sub_config(self, _: List[str]) -> bool:
        return self._render_command_detail("config")

    # ------------------------------------------------------------------
    # Backward-compatible public methods (sync)
    # ------------------------------------------------------------------

    def handle_help(self) -> bool:
        return self._render_overview_dashboard()

    def handle_no_args(self) -> bool:
        return self.handle_help()

    def handle_commands(self, _: Optional[List[str]] = None) -> bool:
        return self._render_overview_dashboard()

    def handle_quick(self, _: Optional[List[str]] = None) -> bool:
        quick = create_styled_table(
            "Quick Reference",
            [("Pattern", "cyan"), ("Purpose", "white")],
        )
        quick.add_row("/help", "Show dynamic documentation dashboard")
        quick.add_row("/help <command>", "Show command-specific usage and risk profile")
        quick.add_row("/help aliases", "Show alias map from live registry")
        quick.add_row("/help commands", "List categorized commands")
        console.print(quick)
        return True

    def handle_aliases(self, _: Optional[List[str]] = None) -> bool:
        return self.handle_help_aliases()

    def handle_help_aliases(self) -> bool:
        console.print(
            Panel(
                "Alias shortcuts for active commands in the current runtime.",
                title="Command Aliases",
                border_style="blue",
                box=box.ROUNDED,
            )
        )
        table = create_styled_table(
            "Command Aliases",
            [("Alias", "yellow"), ("Resolves To", "cyan")],
        )

        for alias, resolved in sorted(COMMAND_ALIASES.items(), key=lambda kv: kv[0].lower()):
            table.add_row(alias, resolved)

        console.print(table)
        console.print(
            create_notes_panel(
                [
                    "Aliases are generated from active command objects at registration time.",
                    "If a command is disabled/unloaded, its aliases disappear automatically.",
                ],
                title="Alias Notes",
                border_style="blue",
            )
        )
        return True

    def handle_help_memory(self) -> bool:
        console.print(
            Panel(
                "Memory Commands\n"
                "/memory search <query>\n"
                "/memory add <note>\n"
                "/memory clear <scope>",
                title="Memory Help",
                border_style="cyan",
                box=box.ROUNDED,
            )
        )
        self._print_command_table(
            "Memory Commands",
            [
                ("/memory search", "", "Search stored context and recall relevant notes"),
                ("/memory add", "", "Store a new memory entry for later retrieval"),
                ("/memory clear", "", "Clear memory by scope or topic"),
            ],
        )
        console.print(
            create_notes_panel(
                [
                    "Use memory search before re-asking the same question.",
                    "Clear only the minimum scope necessary when removing stored context.",
                ],
                title="Memory Notes",
                border_style="yellow",
            )
        )
        console.print(
            Panel(
                "Examples\n/memory search credential\n/memory clear session",
                title="Memory Examples",
                border_style="green",
                box=box.ROUNDED,
            )
        )
        return True

    def handle_help_model(self) -> bool:
        console.print(
            Panel(
                "Model Commands\n/model list\n/model set <name>\n/model current",
                title="Model Help",
                border_style="cyan",
                box=box.ROUNDED,
            )
        )
        self._print_command_table(
            "Model Commands",
            [
                ("/model list", "", "List available models and providers"),
                ("/model set", "", "Select the active model for the session"),
                ("/model current", "", "Show the active model and pricing context"),
            ],
        )
        console.print(
            create_notes_panel(
                [
                    "Model changes affect subsequent agent runs only.",
                    "Prefer lower-cost models for broad reconnaissance and higher-tier models for deep analysis.",
                ],
                title="Model Notes",
                border_style="yellow",
            )
        )
        console.print(
            Panel(
                "Examples\n/model list\n/model set o4-mini",
                title="Model Examples",
                border_style="green",
                box=box.ROUNDED,
            )
        )
        return True

    def handle_help_turns(self) -> bool:
        console.print(
            Panel(
                "Turn Controls\n/turns show\n/turns set <count>",
                title="Turns Help",
                border_style="cyan",
                box=box.ROUNDED,
            )
        )
        self._print_command_table(
            "Turn Controls",
            [
                ("/turns show", "", "Show the current maximum turn budget"),
                ("/turns set", "", "Set a new max-turn value for the session"),
            ],
        )
        console.print(
            create_notes_panel(
                [
                    "Lower turn budgets are useful for quick experiments.",
                    "Increase the limit for longer multi-step agent workflows.",
                ],
                title="Turns Notes",
                border_style="yellow",
            )
        )
        return True

    def handle_help_config(self) -> bool:
        return self._render_command_detail("config")

    def handle_help_platform_manager(self) -> bool:
        if not HAS_PLATFORM_EXTENSIONS or not is_caiextensions_platform_available():
            console.print(
                Panel(
                    "No platform extensions available in this runtime.",
                    title="Platform Extensions",
                    border_style="yellow",
                    box=box.ROUNDED,
                )
            )
            return True

        try:
            manager = None
            module = sys.modules.get("caiextensions.platform.base")
            if module is not None:
                manager = getattr(module, "platform_manager", None)
            if manager is None:
                if PlatformManager is None:
                    raise RuntimeError("Platform manager extension is not available")
                manager = PlatformManager()
            names = manager.list_platforms() or []

            if not names:
                console.print(
                    Panel(
                        "No platforms registered in the current runtime.",
                        title="Platform Extensions",
                        border_style="yellow",
                        box=box.ROUNDED,
                    )
                )
                return True

            table = create_styled_table(
                "Platform Extensions",
                [("Platform", "cyan"), ("Description", "white"), ("Commands", "yellow")],
            )

            for name in names:
                platform = manager.get_platform(name)
                desc = getattr(platform, "description", "—") if platform else "—"
                cmds = ", ".join(platform.get_commands()) if platform and hasattr(platform, "get_commands") else "—"
                table.add_row(name, str(desc), cmds)

            console.print(table)
            return True
        except Exception as exc:
            console.print(f"[red]Failed to load platform extension metadata: {exc}[/red]")
            return False

    def handle_memory(self, _: Optional[List[str]] = None) -> bool:
        memory_cmd = COMMANDS.get("/memory") or COMMANDS.get("memory")
        if memory_cmd is not None:
            show_help = getattr(memory_cmd, "show_help", None)
            if callable(show_help):
                show_help()
                return True
        return self.handle_help_memory()

    def handle_agent(self, _: Optional[List[str]] = None) -> bool:
        console.print(
            Panel(
                "Agent Commands\n/agent list\n/agent select <agent>\n/agent info <agent>",
                title="Agent Commands",
                border_style="cyan",
                box=box.ROUNDED,
            )
        )
        return True

    def handle_graph(self, _: Optional[List[str]] = None) -> bool:
        console.print(
            Panel(
                "Graph Commands\n/graph show\n/graph export --format mermaid",
                title="Graph Help",
                border_style="cyan",
                box=box.ROUNDED,
            )
        )
        return True

    def handle_platform(self, _: Optional[List[str]] = None) -> bool:
        platform_cmd = COMMANDS.get("/platform") or COMMANDS.get("platform")
        if platform_cmd is not None:
            show_help = getattr(platform_cmd, "show_help", None)
            if callable(show_help):
                show_help()
                return True
        return self.handle_help_platform_manager()

    def handle_shell(self, _: Optional[List[str]] = None) -> bool:
        console.print(
            Panel(
                "Shell Commands\n/shell <command>\nUse shell access carefully for live system operations.",
                title="Shell Help",
                border_style="cyan",
                box=box.ROUNDED,
            )
        )
        return True

    def handle_env(self, _: Optional[List[str]] = None) -> bool:
        console.print(
            Panel(
                "Environment Help\nCERBERUS_MODEL\nCERBERUS_MAX_USD\nCERBERUS_DISABLE_USAGE_TRACKING",
                title="Environment Variables",
                border_style="cyan",
                box=box.ROUNDED,
            )
        )
        return True

    def handle_model(self, _: Optional[List[str]] = None) -> bool:
        return self.handle_help_model()

    def handle_turns(self, _: Optional[List[str]] = None) -> bool:
        return self.handle_help_turns()

    def handle_config(self, _: Optional[List[str]] = None) -> bool:
        return self._render_command_detail("config")

    def _print_command_table(self, title: str, commands: List[Tuple[str, str, str]]) -> None:
        table = create_styled_table(title, [("Command", "cyan"), ("Aliases", "yellow"), ("Description", "white")])
        for cmd, alias, desc in commands:
            table.add_row(cmd, alias, desc)
        console.print(table)


HELP_COMMAND_INSTANCE = HelpCommand()
register_command(HELP_COMMAND_INSTANCE)
