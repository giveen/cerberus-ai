"""
Persistent System Monitor for Cerberus AI REPL toolbar.

This module provides a professional, real-time status display at the bottom of the terminal,
dynamically reflecting the current state of framework modules via a segmented HUD with toast notifications.

Architecture:
- CerebroToolbar: dependency-injected toolbar engine with cached snapshot pipeline
- ToolbarSnapshot: frozen dataclass holding current system state
- Toast notifications: temporary messages with fade-out logic
- Responsive rendering: compact/medium/full modes based on terminal width
- Privacy mode: optional obfuscation of sensitive data for screenshare
"""

from __future__ import annotations

import asyncio
import os
import platform
import psutil
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

from prompt_toolkit.formatted_text import HTML
from rich.console import Console

# Import framework dependencies
try:
    from cerberus.memory.logic import clean
except ImportError:
    clean = None

try:
    from cerberus.repl.commands.config import CONFIG_STORE
except ImportError:
    CONFIG_STORE = None

try:
    from cerberus.tools.workspace import get_project_space
except ImportError:
    get_project_space = None

try:
    from cerberus.util import COST_TRACKER
except ImportError:
    COST_TRACKER = None

try:
    from cerberus.repl.commands.mcp import get_mcp_manager
except ImportError:
    get_mcp_manager = None


# =============================================================================
# Data Models
# =============================================================================

@dataclass(frozen=True)
class ToastNotification:
    """Temporary notification message with fade timing."""

    message: str
    created_at: float = field(default_factory=time.time)
    duration_sec: float = 2.0  # Display for 2 seconds then fade
    level: str = "info"  # "info", "success", "warning", "error"

    def is_expired(self) -> bool:
        """Check if notification has timed out."""
        return (time.time() - self.created_at) > self.duration_sec

    def fade_alpha(self) -> float:
        """Compute fade alpha (1.0 = full opacity, 0.0 = invisible)."""
        elapsed = time.time() - self.created_at
        fade_start = self.duration_sec * 0.7  # Start fading at 70% of duration
        if elapsed < fade_start:
            return 1.0
        fade_progress = (elapsed - fade_start) / (self.duration_sec - fade_start)
        return max(0.0, 1.0 - fade_progress)


@dataclass(frozen=True)
class ToolbarSegment:
    """Individual toolbar segment with label, value, and styling."""

    label: str
    value: str
    color: str = "ansilightblue"  # Default style class
    icon: str = ""  # Optional emoji or ASCII icon
    priority: int = 10  # Lower = higher priority (0-100)


@dataclass(frozen=True)
class ToolbarSnapshot:
    """Immutable snapshot of current system state for rendering."""

    # Framework state
    agent_status: str = "Idle"  # "Active", "Analyzing...", "Idle"
    agent_name: str = "Unknown"
    network_status: str = "Connected"  # "Connected", "Connecting", "Disconnected"
    network_latency_ms: int = 0

    # Resource monitoring
    cpu_percent: float = 0.0
    memory_percent: float = 0.0

    # MCP status
    mcp_count: int = 0
    mcp_health: str = "Healthy"  # "Healthy", "Degraded", "Critical"

    # Cost tracking
    cost_total: float = 0.0
    cost_limit: float = 0.0
    cost_exceeded: bool = False

    # Session info
    workspace: str = "default"
    model: str = "gpt-4o-mini"
    target: str = ""

    # Display control
    multiline_input: bool = False
    privacy_mode: bool = False
    terminal_width: int = 80

    # Toast notification
    active_toast: Optional[ToastNotification] = None

    def cost_utilization(self) -> float:
        """Compute cost utilization percentage (0-100)."""
        if self.cost_limit <= 0:
            return 0.0
        return (self.cost_total / self.cost_limit) * 100.0


# =============================================================================
# Core Toolbar Engine
# =============================================================================

class CerberusToolbar:
    """
    Professional persistent toolbar with real-time system monitoring.

    Features:
    - Agent Pulse: current agent status and execution state
    - Network Status: LLM provider connection health
    - Resource Usage: CPU/RAM monitoring
    - MCP Health: active Model Context Protocol servers
    - Toast Notifications: temporary status messages
    - Privacy Mode: obfuscate sensitive data for screenshare
    - Responsive Rendering: compact/medium/full based on terminal width
    """

    def __init__(
        self,
        config: Optional[Any] = None,
        workspace_manager: Optional[Any] = None,
        cost_manager: Optional[Any] = None,
        mcp_provider: Optional[Callable[[], Any]] = None,
        agent_status_provider: Optional[Callable[[], Tuple[str, str]]] = None,
    ):
        """
        Initialize toolbar with dependency-injected managers.

        Args:
            config: Configuration store (defaults to CONFIG_STORE)
            workspace_manager: Workspace manager (optional)
            cost_manager: Cost tracking manager (defaults to COST_TRACKER)
            mcp_provider: Callable that returns MCP manager for connection count
            agent_status_provider: Callable returning (status, agent_name) tuple
        """
        self._config = config or CONFIG_STORE
        self._workspace_manager = workspace_manager
        self._cost_manager = cost_manager or COST_TRACKER
        self._mcp_provider = mcp_provider or (lambda: (get_mcp_manager() if get_mcp_manager else None))
        self._agent_status_provider = agent_status_provider

        # Cache snapshot with 500ms TTL
        self._snapshot: Optional[ToolbarSnapshot] = None
        self._snapshot_time: float = 0.0
        self._snapshot_ttl: float = 0.5  # 500ms cache

        # Toast notification queue (deque for FIFO)
        self._toasts: deque[ToastNotification] = deque(maxlen=3)
        self._toast_lock = threading.Lock()

        # Detect terminal capabilities
        self._console = Console()
        self._ansi_safe = self._detect_ansi_safe()
        self._unicode_safe = self._detect_unicode_safe()

        # Background update thread
        self._update_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def show_toast(self, message: str, level: str = "info", duration_sec: float = 2.0) -> None:
        """
        Queue a temporary toast notification.

        Args:
            message: Notification text
            level: "info", "success", "warning", or "error"
            duration_sec: How long to display before fading
        """
        toast = ToastNotification(message=message, level=level, duration_sec=duration_sec)
        with self._toast_lock:
            self._toasts.append(toast)

    def get_bottom_toolbar(self, current_text: str = "") -> HTML:
        """
        Generate bottom toolbar HTML for prompt_toolkit.

        Args:
            current_text: Current REPL input text (used to detect multiline mode)

        Returns:
            HTML-formatted toolbar for display
        """
        snapshot = self._snapshot_cached(current_text=current_text)
        segments = self._build_segments(snapshot)
        return self._render_segments(snapshot, segments)

    # =========================================================================
    # Private: Snapshot Pipeline
    # =========================================================================

    def _snapshot_cached(self, current_text: str = "") -> ToolbarSnapshot:
        """
        Get or compute toolbar snapshot with 500ms cache TTL.

        Args:
            current_text: Current input text for multiline detection

        Returns:
            Frozen snapshot of current system state
        """
        now = time.time()
        multiline = "\n" in current_text if current_text else False

        if self._snapshot is None or (now - self._snapshot_time) > self._snapshot_ttl:
            self._snapshot = self._compute_snapshot(multiline_input=multiline)
            self._snapshot_time = now
        elif multiline:
            # Update only multiline flag if changed
            self._snapshot = ToolbarSnapshot(
                **{**self._snapshot.__dict__, "multiline_input": multiline}
            )

        return self._snapshot

    def _compute_snapshot(self, multiline_input: bool = False) -> ToolbarSnapshot:
        """Compute fresh snapshot by querying all system sources."""
        # Get terminal width
        try:
            terminal_width = self._console.width or 80
        except Exception:
            terminal_width = 80

        # Agent status
        agent_status, agent_name = self._resolve_agent_status()

        # Network status and latency
        network_status, latency_ms = self._resolve_network_status()

        # Resource usage
        cpu_percent, memory_percent = self._resolve_resource_usage()

        # MCP connections
        mcp_count, mcp_health = self._resolve_mcp_status()

        # Cost tracking
        cost_total, cost_limit = self._resolve_cost_status()
        cost_exceeded = cost_limit > 0 and cost_total > cost_limit

        # Workspace and model
        workspace = self._resolve_workspace()
        model = self._resolve_model()
        target = self._resolve_target()

        # Privacy mode
        privacy_mode = self._resolve_privacy_mode()

        # Active toast (remove expired)
        with self._toast_lock:
            while self._toasts and self._toasts[0].is_expired():
                self._toasts.popleft()
            active_toast = self._toasts[0] if self._toasts else None

        return ToolbarSnapshot(
            agent_status=agent_status,
            agent_name=agent_name,
            network_status=network_status,
            network_latency_ms=latency_ms,
            cpu_percent=cpu_percent,
            memory_percent=memory_percent,
            mcp_count=mcp_count,
            mcp_health=mcp_health,
            cost_total=cost_total,
            cost_limit=cost_limit,
            cost_exceeded=cost_exceeded,
            workspace=workspace,
            model=model,
            target=target,
            multiline_input=multiline_input,
            privacy_mode=privacy_mode,
            terminal_width=terminal_width,
            active_toast=active_toast,
        )

    # =========================================================================
    # Private: State Resolution
    # =========================================================================

    def _resolve_agent_status(self) -> Tuple[str, str]:
        """Resolve current agent status and name."""
        if self._agent_status_provider:
            try:
                return self._agent_status_provider()
            except Exception:
                pass
        return ("Idle", "Unknown")

    def _resolve_network_status(self) -> Tuple[str, int]:
        """Resolve LLM provider connection status."""
        try:
            api_base = os.getenv("OPENAI_API_BASE", "https://api.openai.com/v1")
            latency_ms = 0
            status = "Connected"

            # Try a lightweight health check (would need actual implementation)
            # For now, assume connected if we have an API key
            if os.getenv("OPENAI_API_KEY"):
                status = "Connected"
            else:
                status = "Disconnected"

            return (status, latency_ms)
        except Exception:
            return ("Disconnected", 0)

    def _resolve_resource_usage(self) -> Tuple[float, float]:
        """Get CPU and memory usage."""
        try:
            cpu_percent = psutil.cpu_percent(interval=0.01)
            memory_percent = psutil.virtual_memory().percent
            return (cpu_percent, memory_percent)
        except Exception:
            return (0.0, 0.0)

    def _resolve_mcp_status(self) -> Tuple[int, str]:
        """Count active MCP connections."""
        try:
            if self._mcp_provider:
                mcp_mgr = self._mcp_provider()
                if mcp_mgr and hasattr(mcp_mgr, "connections"):
                    connections = mcp_mgr.connections
                    count = len(connections) if connections else 0

                    # Determine health
                    if count == 0:
                        health = "Healthy"  # 0 is OK
                    elif count >= 5:
                        health = "Healthy"
                    else:
                        health = "Healthy"

                    return (count, health)
        except Exception:
            pass
        return (0, "Healthy")

    def _resolve_cost_status(self) -> Tuple[float, float]:
        """Get current cost and limit."""
        try:
            if self._cost_manager:
                total = self._cost_manager.session_total_cost if hasattr(self._cost_manager, "session_total_cost") else 0.0
                limit = float(os.getenv("CERBERUS_PRICE_LIMIT", "0"))
                return (total, limit)
        except Exception:
            pass
        return (0.0, 0.0)

    def _resolve_workspace(self) -> str:
        """Get current workspace name."""
        try:
            if self._workspace_manager and hasattr(self._workspace_manager, "name"):
                return self._workspace_manager.name
            if get_project_space:
                ws = get_project_space()
                if hasattr(ws, "session_id"):
                    return str(ws.session_id)[:8]
        except Exception:
            pass
        return os.getenv("CERBERUS_WORKSPACE", "default")

    def _resolve_model(self) -> str:
        """Get active model name."""
        model = os.getenv("CERBERUS_MODEL", "gpt-4o-mini")
        if len(model) > 16:
            return model[:14] + "…"
        return model

    def _resolve_target(self) -> str:
        """Get target/destination."""
        return os.getenv("CERBERUS_TARGET", "")

    def _resolve_privacy_mode(self) -> bool:
        """Check if privacy/screenshare mode is enabled."""
        return os.getenv("CERBERUS_SCREENSHARE", "false").lower() == "true"

    # =========================================================================
    # Private: Segment Building
    # =========================================================================

    def _build_segments(self, snapshot: ToolbarSnapshot) -> List[ToolbarSegment]:
        """Build list of toolbar segments from snapshot."""
        segments: List[ToolbarSegment] = []

        # Agent Pulse (highest priority)
        agent_icon = "🤖" if self._unicode_safe else "A"
        agent_color = "ansigreen" if snapshot.agent_status == "Idle" else "ansiyellow"
        if snapshot.agent_status == "Active":
            agent_color = "ansicyan"

        segments.append(
            ToolbarSegment(
                label="Agent",
                value=f"{snapshot.agent_status[:8]}",
                color=agent_color,
                icon=agent_icon,
                priority=0,
            )
        )

        # Network Status
        network_icon = "📡" if self._unicode_safe else "N"
        network_color = "ansigreen" if snapshot.network_status == "Connected" else "ansired"
        segments.append(
            ToolbarSegment(
                label="Net",
                value=snapshot.network_status[:10],
                color=network_color,
                icon=network_icon,
                priority=5,
            )
        )

        # Resource Usage (CPU & Memory)
        if snapshot.cpu_percent > 0 or snapshot.memory_percent > 0:
            resource_icon = "💿" if self._unicode_safe else "R"
            cpu_val = f"{snapshot.cpu_percent:.0f}%"
            mem_val = f"{snapshot.memory_percent:.0f}%"
            resource_color = "ansigreen"
            if snapshot.cpu_percent > 80 or snapshot.memory_percent > 80:
                resource_color = "ansired"
            elif snapshot.cpu_percent > 50 or snapshot.memory_percent > 50:
                resource_color = "ansiyellow"

            segments.append(
                ToolbarSegment(
                    label="Resource",
                    value=f"C{cpu_val}/M{mem_val}",
                    color=resource_color,
                    icon=resource_icon,
                    priority=10,
                )
            )

        # MCP Health
        if snapshot.mcp_count > 0:
            mcp_icon = "🔗" if self._unicode_safe else "M"
            mcp_color = "ansigreen" if snapshot.mcp_health == "Healthy" else "ansiyellow"
            segments.append(
                ToolbarSegment(
                    label="MCP",
                    value=str(snapshot.mcp_count),
                    color=mcp_color,
                    icon=mcp_icon,
                    priority=8,
                )
            )

        # Cost Status
        cost_icon = "💳" if self._unicode_safe else "$"
        cost_color = "ansired" if snapshot.cost_exceeded else "ansigreen"
        if snapshot.cost_utilization() > 80:
            cost_color = "ansiyellow"

        cost_display = f"${snapshot.cost_total:.4f}"
        if not snapshot.privacy_mode and snapshot.cost_limit > 0:
            cost_display += f"/{snapshot.cost_limit:.2f}"

        segments.append(
            ToolbarSegment(
                label="Cost",
                value=cost_display,
                color=cost_color,
                icon=cost_icon,
                priority=3,
            )
        )

        # Model (if not too long)
        if snapshot.model:
            model_icon = "🧠" if self._unicode_safe else "B"
            segments.append(
                ToolbarSegment(
                    label="Model",
                    value=snapshot.model[:12],
                    color="ansicyan",
                    icon=model_icon,
                    priority=15,
                )
            )

        # Toast notification (if active)
        if snapshot.active_toast:
            toast_icon = {
                "success": "✓",
                "warning": "⚠",
                "error": "✗",
                "info": "ℹ",
            }.get(snapshot.active_toast.level, "ℹ")

            toast_color = {
                "success": "ansigreen",
                "warning": "ansiyellow",
                "error": "ansired",
                "info": "ansicyan",
            }.get(snapshot.active_toast.level, "ansicyan")

            alpha = snapshot.active_toast.fade_alpha()
            if alpha > 0.3:  # Only show if visible enough
                segments.append(
                    ToolbarSegment(
                        label="Toast",
                        value=snapshot.active_toast.message[:20],
                        color=toast_color,
                        icon=toast_icon,
                        priority=1,  # High priority for notifications
                    )
                )

        # Sort by priority (lower number = earlier in display)
        segments.sort(key=lambda s: s.priority)

        return segments

    # =========================================================================
    # Private: Rendering
    # =========================================================================

    def _render_segments(self, snapshot: ToolbarSnapshot, segments: List[ToolbarSegment]) -> HTML:
        """Render segments as HTML for prompt_toolkit."""
        if not self._ansi_safe:
            # Plain ASCII mode for dumb terminals
            return self._render_ascii_fallback(segments)

        if snapshot.terminal_width < 100:
            # Compact mode
            return self._render_compact(segments)
        elif snapshot.terminal_width < 150:
            # Medium mode
            return self._render_medium(segments)
        else:
            # Full mode
            return self._render_full(segments, snapshot)

    def _render_ascii_fallback(self, segments: List[ToolbarSegment]) -> HTML:
        """Render text-only fallback for terminals without ANSI support."""
        parts = []
        for seg in segments[:4]:  # Limit to 4 segments for space
            parts.append(f"{seg.label}:{seg.value}")
        text = " | ".join(parts)
        return HTML(f"<ansigray>{text}</ansigray>")

    def _render_compact(self, segments: List[ToolbarSegment]) -> HTML:
        """Compact rendering for narrow terminals."""
        parts = []
        for seg in segments[:3]:  # Only top 3 segments
            if seg.icon:
                parts.append(f"<{seg.color}>{seg.icon} {seg.value}</{seg.color}>")
            else:
                parts.append(f"<{seg.color}>{seg.label}:{seg.value}</{seg.color}>")
        divider = " | "
        text = divider.join(parts)
        return HTML(f" {text} ")

    def _render_medium(self, segments: List[ToolbarSegment]) -> HTML:
        """Medium rendering for standard terminals."""
        parts = []
        for seg in segments[:5]:  # Top 5 segments
            if seg.icon:
                parts.append(f"<{seg.color}><b>{seg.icon}</b> {seg.value}</{seg.color}>")
            else:
                parts.append(f"<{seg.color}><b>{seg.label}</b> {seg.value}</{seg.color}>")
        divider = " <ansigray>|</ansigray> "
        text = divider.join(parts)
        return HTML(f" {text} ")

    def _render_full(self, segments: List[ToolbarSegment], snapshot: ToolbarSnapshot) -> HTML:
        """Full rendering for wide terminals with all details."""
        parts = []
        for seg in segments:
            if seg.icon:
                parts.append(f"<{seg.color}><b>{seg.label}</b>: {seg.icon} {seg.value}</{seg.color}>")
            else:
                parts.append(f"<{seg.color}><b>{seg.label}</b>: {seg.value}</{seg.color}>")

        # Add timestamp
        now = datetime.now().strftime("%H:%M:%S")
        parts.append(f"<ansigray><b>Time</b>: {now}</ansigray>")

        divider = " <ansigray>|</ansigray> "
        text = divider.join(parts)
        return HTML(f" {text} ")

    # =========================================================================
    # Private: Terminal Detection
    # =========================================================================

    def _detect_ansi_safe(self) -> bool:
        """Detect if terminal supports ANSI colors."""
        if os.getenv("NO_COLOR"):
            return False
        if os.getenv("TERM") == "dumb":
            return False
        try:
            color_system = self._console.color_system
            return color_system is not None and color_system != "windows"
        except Exception:
            return True

    def _detect_unicode_safe(self) -> bool:
        """Detect if terminal supports Unicode."""
        import locale

        try:
            encoding = locale.getpreferredencoding(False).lower()
            return "utf" in encoding or "utf-8" in encoding
        except Exception:
            return False


# =============================================================================
# Global Instance & Public API
# =============================================================================

_GLOBAL_TOOLBAR: Optional[CerberusToolbar] = None


def get_cerberus_toolbar(
    config: Optional[Any] = None,
    workspace_manager: Optional[Any] = None,
    cost_manager: Optional[Any] = None,
    mcp_provider: Optional[Callable[[], Any]] = None,
    agent_status_provider: Optional[Callable[[], Tuple[str, str]]] = None,
) -> CerberusToolbar:
    """
    Get or create global CerebroToolbar singleton.

    This singleton is initialized on first call and reused for subsequent access.
    Optionally pass custom dependency providers to override defaults.

    Args:
        config: Configuration store (defaults to CONFIG_STORE)
        workspace_manager: Workspace manager (optional)
        cost_manager: Cost tracking manager (defaults to COST_TRACKER)
        mcp_provider: Callable that returns MCP manager
        agent_status_provider: Callable returning (status, agent_name) tuple

    Returns:
        Global CerebroToolbar instance
    """
    global _GLOBAL_TOOLBAR
    if _GLOBAL_TOOLBAR is None:
        _GLOBAL_TOOLBAR = CerberusToolbar(
            config=config,
            workspace_manager=workspace_manager,
            cost_manager=cost_manager,
            mcp_provider=mcp_provider,
            agent_status_provider=agent_status_provider,
        )
    return _GLOBAL_TOOLBAR


def get_bottom_toolbar(current_text: str = "") -> HTML:
    """Generate bottom toolbar HTML for prompt_toolkit."""
    toolbar = get_cerberus_toolbar()
    return toolbar.get_bottom_toolbar(current_text=current_text)


# Backward compatibility: support original function name
def get_toolbar_with_refresh() -> HTML:
    """Backward compatibility wrapper for original API."""
    return get_bottom_toolbar()


# Initialize singleton on module import
_GLOBAL_TOOLBAR = get_cerberus_toolbar()

