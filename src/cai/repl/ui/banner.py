"""Cerberus AI startup banner and onboarding UI utilities."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import os
from pathlib import Path
import platform as py_platform
import random
import sys
import time
from typing import List, Optional

from rich import box
from rich.align import Align
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from cai.memory import MemoryManager
from cai.repl.commands.config import CONFIG_STORE
from cai.repl.commands.platform import get_system_auditor
from cai.tools.workspace import get_project_space

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib  # type: ignore[import-not-found]


@dataclass(frozen=True)
class BannerPalette:
    logo_colors: List[str]
    accent: str
    legal: str
    ok: str
    warn: str


@dataclass(frozen=True)
class BannerMetadata:
    version: str
    system: str
    brain: str
    workspace_status: str
    memory_status: str
    workspace_root: str
    startup_ms: int


class CerebroBanner:
    """High-impact startup renderer for the Cerberus AI REPL."""

    _TIPS = [
        "Tip: Use /mcp list to verify active tool servers before a scan run.",
        "Tip: Keep target seed files in shared/ and let agents write findings in private/.",
        "Tip: Use /workspace dashboard to review engagement isolation and artifacts.",
        "Tip: Launch risky tooling through /virtualization exec to contain blast radius.",
        "Tip: Use /run --max-turns to cap orchestration loops during noisy engagements.",
        "Tip: Use /platform --refresh before reporting host capability assumptions.",
    ]

    _ASCII_LINES = [
        r"   _____  _____  _____  _____  ____   ____   ___  ",
        r"  / ____|| ____||  _  || ____||  _ \ |  _ \ / _ \ ",
        r" | |     |  _|  | |_| ||  _|  | |_) || |_) | | | |",
        r" | |____ | |___ |  _  || |___ |  _ < |  _ <| |_| |",
        r"  \_____||_____||_| |_||_____||_| \_\|_| \_\\___/ ",
    ]

    def __init__(self, console: Optional[Console] = None) -> None:
        self.console = console or Console()
        self.palette = BannerPalette(
            logo_colors=["#2A0E61", "#3D1A82", "#00D1D1", "#00F5A0", "#34FFB3"],
            accent="#00D1D1",
            legal="#8E8AAE",
            ok="#00F5A0",
            warn="#FFD166",
        )

    def display(self) -> None:
        start = time.perf_counter()
        metadata = self._collect_metadata(start)

        loading_line = Text("Initializing Cerberus AI runtime ", style=f"bold {self.palette.accent}")
        loading_line.append("●", style=self.palette.logo_colors[1])
        loading_line.append("●", style=self.palette.logo_colors[2])
        loading_line.append("●", style=self.palette.logo_colors[3])
        self.console.print(loading_line)

        logo_panel = self._render_logo_panel()
        status_panel = self._render_status_panel(metadata)
        legal_panel = self._render_legal_panel()
        tip_panel = self._render_tip_panel(metadata)

        self.console.print(logo_panel)
        self.console.print(status_panel)
        self.console.print(legal_panel)
        self.console.print(tip_panel)

    def _collect_metadata(self, start: float) -> BannerMetadata:
        version = self._resolve_version()
        system = self._resolve_system_info()
        brain = self._resolve_brain_info()
        workspace_status, workspace_root = self._workspace_health()
        memory_status = self._memory_health()
        startup_ms = int((time.perf_counter() - start) * 1000)

        return BannerMetadata(
            version=version,
            system=system,
            brain=brain,
            workspace_status=workspace_status,
            memory_status=memory_status,
            workspace_root=workspace_root,
            startup_ms=startup_ms,
        )

    def _resolve_version(self) -> str:
        cfg_version = CONFIG_STORE.get("CEREBRO_VERSION")
        if cfg_version and cfg_version != "Not set":
            return cfg_version

        pyproject = Path.cwd() / "pyproject.toml"
        try:
            with pyproject.open("rb") as handle:
                data = tomllib.load(handle)
            return str(data.get("project", {}).get("version", "unknown"))
        except Exception:
            return "unknown"

    def _resolve_system_info(self) -> str:
        try:
            auditor = get_system_auditor()
            cached = getattr(auditor, "_cache", None)
            if cached is not None:
                os_name = f"{cached.os.distribution} {cached.os.version}".strip()
                arch = cached.architecture.machine or "unknown"
                return f"{os_name} / {arch}"
        except Exception:
            pass

        return f"{py_platform.system()} {py_platform.release()} / {py_platform.machine()}"

    def _resolve_brain_info(self) -> str:
        model = os.getenv("CEREBRO_MODEL", "cerebro1")
        provider = self._infer_provider(model)
        return f"{provider}: {model}"

    @staticmethod
    def _infer_provider(model: str) -> str:
        lowered = model.lower()
        if lowered.startswith(("claude", "anthropic")):
            return "Brain: Claude"
        if lowered.startswith(("gpt", "o1", "o3", "o4", "openai")):
            return "Brain: OpenAI"
        if lowered.startswith(("gemini", "google")):
            return "Brain: Gemini"
        if lowered.startswith(("llama", "qwen", "mistral", "ollama", "deepseek")):
            return "Brain: Local"
        return "Brain: Adaptive"

    def _workspace_health(self) -> tuple[str, str]:
        try:
            root = get_project_space().ensure_initialized().resolve()
            shared = root / "shared"
            private = root / "private"
            if shared.exists() and private.exists():
                return "healthy", str(root)
            return "active (legacy layout)", str(root)
        except Exception:
            fallback = os.getenv("WORKSPACE_ROOT", str(Path.cwd()))
            return "degraded", fallback

    def _memory_health(self) -> str:
        try:
            manager = MemoryManager()
            storage_root = manager.initialize()
            evidence_path = storage_root / "evidence.jsonl"
            if evidence_path.exists():
                return "healthy"
            return "initializing"
        except Exception:
            return "degraded"

    def _render_logo_panel(self) -> Panel:
        logo = Text()
        for idx, line in enumerate(self._ASCII_LINES):
            color = self.palette.logo_colors[min(idx, len(self.palette.logo_colors) - 1)]
            logo.append(line + "\n", style=f"bold {color}")

        subtitle = Text("Cerberus AI Local Security Orchestration", style=f"bold {self.palette.accent}")
        composed = Group(Align.center(logo), Align.center(subtitle))
        return Panel(
            composed,
            border_style=self.palette.logo_colors[2],
            box=box.ROUNDED,
            padding=(1, 2),
            title="CERBERUS AI",
        )

    def _render_status_panel(self, meta: BannerMetadata) -> Panel:
        table = Table(box=box.SIMPLE_HEAVY, expand=True, show_header=True)
        table.add_column("Signal", style=f"bold {self.palette.accent}", width=20)
        table.add_column("Value", style="white")

        table.add_row("Version", meta.version)
        table.add_row("System", meta.system)
        table.add_row("Provider", meta.brain)
        table.add_row("Workspace", self._health_text(meta.workspace_status))
        table.add_row("Memory", self._health_text(meta.memory_status))
        table.add_row("Workspace Root", meta.workspace_root)
        table.add_row("Render Time", f"{meta.startup_ms} ms")

        return Panel(table, title="Cerberus AI Runtime Status", border_style=self.palette.logo_colors[1])

    def _render_legal_panel(self) -> Panel:
        legal = Text()
        legal.append("Cerberus AI: Headless Security Orchestration\n", style=f"bold {self.palette.legal}")
        legal.append("Programmatic policy enforcement. Internal distribution only.", style=self.palette.legal)
        return Panel(legal, border_style=self.palette.legal, box=box.MINIMAL)

    def _render_tip_panel(self, meta: BannerMetadata) -> Panel:
        tip = self._pick_tip(meta)
        tip_text = Text(tip, style="white")
        return Panel(tip_text, title="Pro Tip", border_style=self.palette.logo_colors[3])

    def _pick_tip(self, meta: BannerMetadata) -> str:
        seed_material = f"{meta.workspace_root}|{datetime.now(tz=UTC).date().isoformat()}|{time.time_ns()}"
        seed = int(hashlib.sha256(seed_material.encode("utf-8")).hexdigest(), 16)
        rng = random.Random(seed)
        return self._TIPS[rng.randrange(len(self._TIPS))]

    def _health_text(self, state: str) -> str:
        lowered = state.lower()
        if "healthy" in lowered:
            return f"[{self.palette.ok}]{state}[/{self.palette.ok}]"
        if "active" in lowered or "initial" in lowered:
            return f"[{self.palette.warn}]{state}[/{self.palette.warn}]"
        return f"[{self.palette.warn}]{state}[/{self.palette.warn}]"


def display_banner(console: Console) -> None:
    """CLI compatibility entrypoint for startup banner rendering."""
    CerebroBanner(console).display()


def display_quick_guide(console: Console) -> None:
    """Render concise enterprise quick start guidance."""
    guide = Table(title="Cerberus AI Quick Guide", box=box.SIMPLE_HEAVY)
    guide.add_column("Action", style="cyan", no_wrap=True)
    guide.add_column("Command", style="white")

    guide.add_row("Create engagement", "/workspace new client_name")
    guide.add_row("Switch engagement", "/workspace switch client_name")
    guide.add_row("Launch sandbox", "/virtualization up kalilinux/kali-rolling")
    guide.add_row("Run contained command", "/virtualization exec nmap -sV target")
    guide.add_row("Inspect tool servers", "/mcp list")
    guide.add_row("Show model governance", "/model")

    console.print(Panel(guide, border_style="#14919B"))


def display_welcome_tips(console: Console) -> None:
    """Backwards-compatible helper for startup tips."""
    tip = CerebroBanner(console)._pick_tip(
        BannerMetadata(
            version="unknown",
            system="unknown",
            brain="unknown",
            workspace_status="unknown",
            memory_status="unknown",
            workspace_root=os.getenv("WORKSPACE_ROOT", str(Path.cwd())),
            startup_ms=0,
        )
    )
    console.print(Panel(tip, title="Pro Tip", border_style="#14919B"))
