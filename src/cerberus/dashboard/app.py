import asyncio
import json
import os
import random
import re
import shlex
import shutil
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field
import reflex as rx
from reflex.event import noop
from reflex.components.base.error_boundary import error_boundary
from reflex.vars.base import Var

from cerberus.main import execute_headless_action, terminate_action
from cerberus.parsers import parse_json_lenient
from cerberus.core.policy_engine import PolicyEngine, PolicyReport
from cerberus.dashboard.state import (
    KALI_DOCKER_ENVIRONMENT_BADGE,
    environment_badge_text,
    extract_execution_environment_id,
)
from cerberus.infrastructure import env_manager
from cerberus.internal.redis_client import (
    get_redis_manager,
    push_history_line,
    broadcast_state_change,
)
from reflex_dashboard.commands import COMMAND_MENU_ITEMS, COMMAND_REGISTRY


MAX_SESSIONS = 4
MAX_LOG_ENTRIES = 60
POLICY_HISTORY_LIMIT = 10
PROMPT_STREAM_LINE_LIMIT = 400
HEADLESS_ACTION_TIMEOUT_S = 600
NEON_GREEN = "#00FF00"
NEON_CYAN = "#00FFFF"
BG_BLACK = "#000000"
MUTED_TEXT = "#8FD88F"
TEXT_PRIMARY = "#E7FFE7"
AUDIT_PENDING = "#94A3B8"
AUDIT_VERIFY = "#22D3EE"
AUDIT_CLEAR = "#00FF00"
AUDIT_VIOLATION = "#FF6B6B"
SESSION_ROLES = [
    "Lead Operator",
    "Recon Specialist",
    "Exploit Analyst",
    "Containment Monitor",
]
REPO_ROOT = Path(__file__).resolve().parents[1]
TOOL_EVENT_LOG_PATH = REPO_ROOT / ".cerberus" / "session" / "dashboard_tool_events.jsonl"
PROMPT_DISPATCH_TOOL = "run_supervised_prompt"
PROMPT_RESPONSE_MARKER = "final output"
PROMPT_RESPONSE_FALLBACK_MARKER = "response"
HIGH_RISK_LEVELS = {"high", "critical", "severe"}
PROMPT_META_MARKERS = (
    "technical safety constraints",
    "audit reasoning",
    "reasoning cycle recorded",
    "mode_critique",
    "mode mode_critique",
    "pivot_required",
    "cerebro supervised mission summary",
    "cerebro prompt redactions",
)
PROMPT_HIDDEN_RESPONSE_MARKERS = (
    "# session metadata",
    "role: validate and critique proposed actions. do not execute.",
    "policy engine found issues in the current plan",
    "[system][reflect]",
)
PROMPT_RESPONSE_NOISE_MARKERS = (
    "committing_json",
    "action system tool loaded:",
    "cerebro supervised mission summary",
    "turn journal |",
    "summary | /workspace",
    "field | value",
    "agent |",
    "status |",
    "tokens |",
    "tools |",
    "memory |",
    "level 25 a audit",
    "agent_factory lifecycle event",
    "this implies i should",
    "but to be safe and consistent",
    "actually, looking at the tools available",
    "let's assume the user is just saying hi",
)
PROMPT_INLINE_TRUNCATION_MARKERS = (
    "cerebro supervised mission summary",
    "turn journal |",
    "summary | /workspace",
    "field | value",
    "status |",
    "tokens |",
    "| field | value |",
    "| agent |",
)
PROMPT_RESPONSE_TAIL_MARKERS = (
    "cerebro supervised mission summary",
    "turn journal",
    "summary | /workspace",
    "field | value",
    "agent |",
    "status |",
    "tokens |",
    "tools |",
    "memory |",
)
ERROR_LOG_MARKERS = (
    "error",
    "failed",
    "failure",
    "exception",
    "traceback",
    "timed out",
    "timeout",
    "blocked",
    "denied",
    "terminated",
    "violation",
    "pending approval",
)
STATE_SNAPSHOT_VERSION = 1
STATE_SNAPSHOT_STORAGE_KEY = "cerberus_dashboard_snapshot_v1"
ANSI_ESCAPE_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
THINK_TAG_RE = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)
BOX_DRAWING_CHARS = set("+-=|│║─━═┌┐└┘├┤┬┴┼╭╮╰╯╔╗╚╝╠╣╦╩╬")
PANEL_EDGE_CHARS = {"|", "│", "║"}
CONFIG_CARD_ORDER = (
    "CERBERUS_API_BASE",
    "CEREBRO_MODEL",
    "CERBERUS_ACTIVE_CONTAINER",
    "REDIS_URL",
    "DEBUG_MODE",
)
CONFIG_CARD_DESCRIPTIONS = {
    "CERBERUS_API_BASE": "The URL for your local LLM endpoint or OpenAI-compatible gateway.",
    "CEREBRO_MODEL": "The default model identifier the dashboard will route prompts to.",
    "CERBERUS_ACTIVE_CONTAINER": "The active Kali or runtime container used for supervised command execution.",
    "REDIS_URL": "Connection string used for Reflex session persistence and shared dashboard state.",
    "DEBUG_MODE": "Enable additional runtime debugging for container-side services that honor this flag.",
}
CONFIG_CARD_PLACEHOLDERS = {
    "CERBERUS_API_BASE": "http://192.168.0.x:11434/v1",
    "CEREBRO_MODEL": "qwen2.5-coder:32b",
    "CERBERUS_ACTIVE_CONTAINER": "cerberus",
    "REDIS_URL": "redis://redis:6379",
}


def _display_env_target(key: str) -> str:
    target_path = env_manager.resolve_env_path_for_key(key)
    try:
        return str(target_path.relative_to(REPO_ROOT))
    except ValueError:
        return str(target_path)


CONFIG_CARD_TARGETS = {key: _display_env_target(key) for key in CONFIG_CARD_ORDER}
APPROVAL_REJECTION_MESSAGE = "The operator has denied execution of this tool. Suggest an alternative, lower-risk approach."
KNOWN_COMMAND_TOKENS = {
    "bash",
    "cat",
    "cd",
    "cerberus",
    "chmod",
    "cp",
    "curl",
    "docker",
    "echo",
    "env",
    "ffuf",
    "find",
    "git",
    "gobuster",
    "grep",
    "head",
    "hydra",
    "id",
    "john",
    "ls",
    "make",
    "mkdir",
    "msfconsole",
    "mv",
    "nc",
    "netcat",
    "nikto",
    "nmap",
    "openvpn",
    "ping",
    "pip",
    "pip3",
    "pwd",
    "python",
    "python3",
    "rm",
    "sed",
    "sh",
    "sqlmap",
    "ssh",
    "sudo",
    "tail",
    "tcpdump",
    "touch",
    "uname",
    "wget",
    "whatweb",
    "whoami",
}
SHELL_CONTROL_TOKENS = ("&&", "||", "|", ";", ">", "<", "$(", "`")
AUDIT_TIERS = [
    ("tier_1", "Tool Contract"),
    ("tier_2", "Workspace Bounds"),
    ("tier_3", "Loop Guard"),
    ("tier_4", "Risk Sweep"),
]


def _timestamp() -> str:
    return datetime.now().strftime("%H:%M:%S")


def _log_entry(role: str, content: str, *, environment_label: str = "") -> dict[str, str]:
    return {
        "role": role,
        "content": content,
        "timestamp": _timestamp(),
        "environment_label": environment_label,
    }


def _default_tier_status() -> dict[str, str]:
    return {tier_key: "standby" for tier_key, _ in AUDIT_TIERS}


def _default_workspaces_root() -> Path:
    configured = os.getenv("CERBERUS_WORKSPACE_ROOT", "").strip()
    if configured:
        return Path(configured).expanduser().resolve()

    dockerized_root = REPO_ROOT / "dockerized" / "volumes" / "workspaces"
    if (REPO_ROOT / "dockerized").exists():
        return dockerized_root.resolve()

    return (REPO_ROOT / "workspaces").resolve()


class AgentSession(BaseModel):
    session_id: str
    role: str
    workspace: str
    workspace_id: str
    logs: list[dict[str, str]] = Field(default_factory=list)
    command_input: str = ""
    status: str = "ready"
    is_busy: bool = False
    termination_requested: bool = False
    approval_required: bool = False
    pending_action: dict[str, Any] | None = None
    pending_approval_source: str = ""
    pending_tool_name: str = ""
    pending_raw_arguments: str = ""
    pending_repaired_arguments: str = ""
    pending_message: str = ""
    pending_risk_tier: int = 0
    policy_history: list[dict[str, Any]] = Field(default_factory=list)
    tier_status: dict[str, str] = Field(default_factory=_default_tier_status)
    last_command: str = ""
    active_tool_name: str = ""
    status_line: str = "Standing by for a prompt or command."
    prompt_stream_lines: list[str] = Field(default_factory=list)
    prompt_response_log_index: int | None = None
    stream_log_index: int | None = None
    stream_call_id: str = ""
    prompt_agent: str = "one_tool"
    execution_environment_id: str = ""


def _new_session(index: int) -> AgentSession:
    session_id = f"AGENT-{index + 1}"
    workspace_id = f"dashboard-agent-{index + 1}"
    workspace = str((_default_workspaces_root() / workspace_id).resolve())
    role = SESSION_ROLES[index]
    return AgentSession(
        session_id=session_id,
        role=role,
        workspace=workspace,
        workspace_id=workspace_id,
        logs=[],
    )


def _build_sessions() -> list[AgentSession]:
    return [_new_session(0)]


def _next_session_slot(sessions: list[AgentSession]) -> int | None:
    used_session_ids = {session.session_id for session in sessions}
    for index in range(MAX_SESSIONS):
        if f"AGENT-{index + 1}" not in used_session_ids:
            return index
    return None


def _strip_ansi(text: str) -> str:
    return ANSI_ESCAPE_RE.sub("", text or "")


def _contains_box_drawing(text: str) -> bool:
    return any(character in BOX_DRAWING_CHARS for character in text)


def _is_box_border_line(text: str) -> bool:
    stripped = _strip_ansi(text).strip()
    if not stripped:
        return False
    return all(character in BOX_DRAWING_CHARS or character.isspace() for character in stripped)


def _extract_panel_content(text: str) -> str | None:
    stripped = _strip_ansi(text).strip()
    if len(stripped) < 2:
        return None
    if stripped[0] not in PANEL_EDGE_CHARS or stripped[-1] not in PANEL_EDGE_CHARS:
        return None
    inner = stripped[1:-1]
    if inner.startswith(" "):
        inner = inner[1:]
    if inner.endswith(" "):
        inner = inner[:-1]
    return inner.rstrip()


def _join_prompt_response_lines(lines: list[str]) -> str:
    normalized = [line.rstrip() for line in lines]
    while normalized and not normalized[0].strip():
        normalized.pop(0)
    while normalized and not normalized[-1].strip():
        normalized.pop()

    collapsed: list[str] = []
    previous_blank = False
    for line in normalized:
        if not line.strip():
            if not previous_blank:
                collapsed.append("")
            previous_blank = True
            continue
        collapsed.append(line)
        previous_blank = False
    return "\n".join(collapsed).strip()


def _looks_like_model_request_payload(text: str) -> bool:
    try:
        parsed = parse_json_lenient(text, prefer_last=True)
    except Exception:
        return False

    if not isinstance(parsed, dict):
        return False
    return isinstance(parsed.get("messages"), list) and isinstance(parsed.get("model"), str)


def _extract_explicit_response_section(text: str) -> str:
    lines = str(text or "").splitlines()
    if not lines:
        return ""

    for line in lines:
        inline_match = re.match(r"^\s*response\s*:\s*(.+)$", line, flags=re.IGNORECASE)
        if inline_match:
            return _join_prompt_response_lines([inline_match.group(1).strip()])

    response_index: int | None = None
    for index, line in enumerate(lines):
        heading = line.strip().lower().rstrip(":")
        if heading == "response":
            response_index = index
            break

    if response_index is None:
        return str(text or "")

    section_lines: list[str] = []
    for line in lines[response_index + 1 :]:
        heading = line.strip().lower().rstrip(":")
        if heading in {"reasoning", "analysis", "thinking"}:
            break
        section_lines.append(line)

    return _join_prompt_response_lines(section_lines)


def _sanitize_prompt_response_text(text: str) -> str:
    cleaned = _join_prompt_response_lines(text.splitlines())
    if not cleaned:
        return ""

    cleaned = THINK_TAG_RE.sub("", cleaned)
    cleaned = cleaned.replace("<think>", "").replace("</think>", "").strip()
    if not cleaned:
        return ""

    # Check if this is a COMMITTING_JSON response - preserve it as-is
    if "COMMITTING_JSON:" in cleaned:
        return cleaned

    cleaned = _extract_explicit_response_section(cleaned)
    if not cleaned:
        return ""

    filtered_lines: list[str] = []
    for raw_line in cleaned.splitlines():
        line = raw_line.strip()
        lowered = line.lower()

        if not line:
            if filtered_lines and filtered_lines[-1] != "":
                filtered_lines.append("")
            continue

        # Preserve COMMITTING_JSON payloads even if they contain noise markers
        if line.startswith("COMMITTING_JSON:"):
            filtered_lines.append(line)
            continue

        if any(marker in lowered for marker in PROMPT_RESPONSE_NOISE_MARKERS):
            continue

        if re.match(r"^level\s+\d+\s+.*action system tool loaded:", lowered):
            continue
        if re.match(r"^\[[0-9]{2}/[0-9]{2}/[0-9]{2}\s+[0-9]{2}:[0-9]{2}:[0-9]{2}\]\s+level\s+\d+", lowered):
            continue

        if line in filtered_lines and len(line) >= 48:
            continue

        filtered_lines.append(line)

    cleaned = _join_prompt_response_lines(filtered_lines)
    if not cleaned:
        return ""

    lowered = cleaned.lower()
    if any(marker in lowered for marker in PROMPT_HIDDEN_RESPONSE_MARKERS):
        return ""
    if lowered.startswith("reasoning"):
        return ""
    if _looks_like_model_request_payload(cleaned):
        return ""
    return cleaned


def _visible_session_logs(
    logs: list[dict[str, str]],
    *,
    response_only: bool,
    show_audit_logs: bool,
) -> list[dict[str, str]]:
    if response_only:
        latest_user: dict[str, str] | None = None
        latest_assistant: dict[str, str] | None = None

        for entry in logs:
            role = str(entry.get("role", "") or "")
            if role == "Audit" and not show_audit_logs:
                continue

            if role == "User":
                latest_user = entry
                continue

            if role != "Assistant":
                continue

            raw_content = str(entry.get("content", "") or "")
            cleaned_content = _sanitize_prompt_response_text(raw_content)
            if cleaned_content:
                latest_assistant = {**entry, "content": cleaned_content}
                continue

            # Fallback: keep minimally cleaned assistant output instead of blanking the pane.
            fallback = THINK_TAG_RE.sub("", raw_content)
            fallback = fallback.replace("<think>", "").replace("</think>", "").strip()
            fallback = _extract_explicit_response_section(fallback)
            fallback = _join_prompt_response_lines(fallback.splitlines())
            if fallback:
                latest_assistant = {**entry, "content": fallback}

        result: list[dict[str, str]] = []
        if latest_user is not None:
            result.append(latest_user)
        if latest_assistant is not None:
            result.append(latest_assistant)
        return result

    visible_logs: list[dict[str, str]] = []

    for entry in logs:
        role = str(entry.get("role", "") or "")
        if role == "Audit" and not show_audit_logs:
            continue

        if role == "Assistant":
            cleaned_content = _sanitize_prompt_response_text(str(entry.get("content", "") or ""))
            if cleaned_content:
                visible_logs.append({**entry, "content": cleaned_content})
                continue

        visible_logs.append(entry)

    return visible_logs


def _is_prompt_response_tail_line(text: str) -> bool:
    lowered = str(text or "").strip().lower()
    if not lowered:
        return False

    if any(marker in lowered for marker in PROMPT_RESPONSE_TAIL_MARKERS):
        return True

    if re.match(r"^\[[0-9]{2}/[0-9]{2}/[0-9]{2}\s+[0-9]{2}:[0-9]{2}:[0-9]{2}\]\s+level\s+\d+", lowered):
        return True

    return False


def _is_error_log_content(text: str) -> bool:
    lowered = str(text or "").strip().lower()
    if not lowered:
        return False
    if "⚠" in lowered:
        return True
    return any(marker in lowered for marker in ERROR_LOG_MARKERS)


def _extract_prompt_response_from_lines(
    raw_lines: list[str],
    *,
    fallback_to_plain_text: bool = False,
) -> str:
    captured_lines: list[str] = []
    saw_final_output = False

    for raw_line in raw_lines:
        cleaned = _strip_ansi(raw_line).rstrip("\r\n")
        stripped = cleaned.strip()

        if not stripped:
            if saw_final_output and captured_lines:
                captured_lines.append("")
            continue

        lowered = stripped.lower()
        if PROMPT_RESPONSE_MARKER in lowered or lowered == PROMPT_RESPONSE_FALLBACK_MARKER:
            saw_final_output = True
            continue

        if not saw_final_output:
            continue

        panel_content = _extract_panel_content(cleaned)
        if panel_content is not None:
            if _is_prompt_response_tail_line(panel_content):
                # Tail markers may appear interleaved with streamed output; skip
                # these lines but continue collecting the full response.
                continue
            captured_lines.append(panel_content)
            continue

        if _is_box_border_line(stripped):
            # multiple framed blocks and markdown separators that would
            # otherwise cause premature truncation.
            continue

        if _is_prompt_response_tail_line(stripped):
            # Skip known telemetry tail lines without terminating capture.
            continue

        captured_lines.append(stripped)

    extracted = _join_prompt_response_lines(captured_lines)
    if extracted:
        return _sanitize_prompt_response_text(extracted)

    if not fallback_to_plain_text:
        return ""

    cleaned_lines = [_strip_ansi(line).rstrip("\r\n") for line in raw_lines]
    if any(marker in line.strip().lower() for line in cleaned_lines for marker in PROMPT_META_MARKERS):
        return ""
    if any(_contains_box_drawing(line) for line in cleaned_lines):
        return ""

    return _sanitize_prompt_response_text(_join_prompt_response_lines([line.strip() for line in cleaned_lines]))


def _upsert_assistant_response_log(
    logs: list[dict[str, str]],
    response_index: int | None,
    content: str,
) -> tuple[list[dict[str, str]], int]:
    updated_logs = [dict(entry) for entry in logs]
    if response_index is not None and 0 <= response_index < len(updated_logs):
        existing = updated_logs[response_index]
        if existing.get("role") == "Assistant":
            updated_logs[response_index] = {**existing, "content": content}
            return updated_logs, response_index

    updated_logs.append(_log_entry("Assistant", content))
    overflow = max(0, len(updated_logs) - MAX_LOG_ENTRIES)
    if overflow:
        updated_logs = updated_logs[overflow:]
    return updated_logs, len(updated_logs) - 1


def _serialize_dashboard_snapshot(
    sessions: list[AgentSession],
    *,
    active_session_id: str,
    cpu_usage: int,
    ram_usage: int,
    net_mbps: float,
    alert_count: int,
    sensor_health: str,
    project_id: str,
    target_ip: str,
    session_uuid: str,
    verbose_logs: bool,
    parallel_execution: bool,
    show_tool_logs: bool,
    show_audit_logs: bool,
    response_only: bool,
    tier_1_enabled: bool,
    tier_2_enabled: bool,
    tier_3_enabled: bool,
    tier_4_enabled: bool,
) -> str:
    payload = {
        "version": STATE_SNAPSHOT_VERSION,
        "active_session_id": active_session_id,
        "cpu_usage": int(cpu_usage),
        "ram_usage": int(ram_usage),
        "net_mbps": float(net_mbps),
        "alert_count": int(alert_count),
        "sensor_health": str(sensor_health),
        "project_id": str(project_id),
        "target_ip": str(target_ip),
        "session_uuid": str(session_uuid),
        "verbose_logs": bool(verbose_logs),
        "parallel_execution": bool(parallel_execution),
        "show_tool_logs": bool(show_tool_logs),
        "show_audit_logs": bool(show_audit_logs),
        "response_only": bool(response_only),
        "tier_1_enabled": bool(tier_1_enabled),
        "tier_2_enabled": bool(tier_2_enabled),
        "tier_3_enabled": bool(tier_3_enabled),
        "tier_4_enabled": bool(tier_4_enabled),
        "agent_sessions": [session.model_dump(mode="json") for session in sessions],
    }
    return json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def _deserialize_dashboard_snapshot(payload: str) -> dict[str, Any] | None:
    text = str(payload or "").strip()
    if not text:
        return None

    try:
        parsed = json.loads(text)
    except Exception:
        return None

    if not isinstance(parsed, dict):
        return None
    if int(parsed.get("version", -1)) != STATE_SNAPSHOT_VERSION:
        return None

    raw_sessions = parsed.get("agent_sessions")
    if not isinstance(raw_sessions, list):
        return None

    restored_sessions: list[AgentSession] = []
    seen_session_ids: set[str] = set()
    for raw_session in raw_sessions[:MAX_SESSIONS]:
        if not isinstance(raw_session, dict):
            continue
        try:
            session = AgentSession.model_validate(raw_session)
        except Exception:
            continue
        if session.session_id in seen_session_ids:
            continue
        seen_session_ids.add(session.session_id)
        restored_sessions.append(session)

    if not restored_sessions:
        return None

    restored_active = str(parsed.get("active_session_id", "") or "")
    if restored_active not in {session.session_id for session in restored_sessions}:
        restored_active = restored_sessions[0].session_id

    return {
        "agent_sessions": restored_sessions,
        "active_session_id": restored_active,
        "cpu_usage": int(parsed.get("cpu_usage", 24)),
        "ram_usage": int(parsed.get("ram_usage", 58)),
        "net_mbps": float(parsed.get("net_mbps", 8.4)),
        "alert_count": int(parsed.get("alert_count", 1)),
        "sensor_health": str(parsed.get("sensor_health", "Nominal") or "Nominal"),
        "project_id": str(parsed.get("project_id", "") or ""),
        "target_ip": str(parsed.get("target_ip", "") or ""),
        "session_uuid": str(parsed.get("session_uuid", "") or ""),
        "verbose_logs": bool(parsed.get("verbose_logs", False)),
        "parallel_execution": bool(parsed.get("parallel_execution", True)),
        "show_tool_logs": bool(parsed.get("show_tool_logs", True)),
        "show_audit_logs": bool(parsed.get("show_audit_logs", True)),
        "response_only": bool(parsed.get("response_only", True)),
        "tier_1_enabled": bool(parsed.get("tier_1_enabled", True)),
        "tier_2_enabled": bool(parsed.get("tier_2_enabled", True)),
        "tier_3_enabled": bool(parsed.get("tier_3_enabled", True)),
        "tier_4_enabled": bool(parsed.get("tier_4_enabled", True)),
    }


custom_css: dict[str, Any] = {
    "html, body": {
        "background": BG_BLACK,
        "color": TEXT_PRIMARY,
        "font-family": '"JetBrains Mono", "Courier New", monospace',
    },
    "body": {
        "margin": "0",
        "overflow": "hidden",
    },
    ".dashboard-root": {
        "background": "radial-gradient(circle at top right, rgba(0, 255, 255, 0.08), transparent 24%), radial-gradient(circle at left center, rgba(0, 255, 0, 0.08), transparent 20%), #000000",
        "min-height": "100vh",
    },
    ".neon-panel": {
        "border": f"1px solid {NEON_GREEN}",
        "box-shadow": f"0 0 8px {NEON_GREEN}",
        "background": "rgba(5, 5, 5, 0.96)",
    },
    ".audit-panel": {
        "border": f"1px solid {NEON_CYAN}",
        "box-shadow": f"0 0 8px {NEON_CYAN}",
        "background": "rgba(0, 24, 24, 0.76)",
    },
    ".terminal-flicker": {
        "animation": "none",
    },
    ".terminal-flicker::-webkit-scrollbar": {
        "width": "8px",
    },
    ".terminal-flicker::-webkit-scrollbar-thumb": {
        "background": "rgba(0, 255, 0, 0.4)",
        "border-radius": "999px",
    },
    ".command-bar": {
        "background": "rgba(0, 0, 0, 0.92)",
        "backdrop-filter": "blur(14px)",
    },
    "@keyframes intelAlertPulse": {
        "0%": {
            "boxShadow": "0 0 0 0 rgba(255, 107, 107, 0.42)",
        },
        "70%": {
            "boxShadow": "0 0 0 14px rgba(255, 107, 107, 0.0)",
        },
        "100%": {
            "boxShadow": "0 0 0 0 rgba(255, 107, 107, 0.0)",
        },
    },
    ".response-card": {
        "background": "linear-gradient(180deg, rgba(8, 22, 20, 0.96) 0%, rgba(5, 14, 13, 0.94) 100%)",
        "border": "1px solid rgba(0, 255, 255, 0.18)",
        "border-radius": "18px",
        "box-shadow": "0 18px 40px rgba(0, 0, 0, 0.34)",
        "padding": "20px 22px",
    },
    ".user-card": {
        "background": "linear-gradient(180deg, rgba(12, 22, 12, 0.96) 0%, rgba(6, 14, 6, 0.94) 100%)",
        "border": "1px solid rgba(0, 255, 0, 0.2)",
        "border-radius": "18px",
        "box-shadow": "0 18px 40px rgba(0, 0, 0, 0.34)",
        "padding": "20px 22px",
    },
    ".response-markdown": {
        "color": TEXT_PRIMARY,
        "font-family": '"IBM Plex Sans", "Segoe UI", sans-serif',
        "font-size": "1rem",
        "line-height": "1.75",
    },
    ".response-markdown > :first-child": {
        "margin-top": "0",
    },
    ".response-markdown > :last-child": {
        "margin-bottom": "0",
    },
    ".response-markdown p": {
        "margin": "0 0 1rem 0",
    },
    ".response-markdown h1, .response-markdown h2, .response-markdown h3, .response-markdown h4": {
        "color": "#EFFFF9",
        "font-family": '"IBM Plex Sans", "Segoe UI", sans-serif',
        "font-weight": "700",
        "line-height": "1.2",
        "margin": "1.25rem 0 0.75rem 0",
    },
    ".response-markdown ul, .response-markdown ol": {
        "margin": "0.75rem 0 1rem 1.25rem",
        "padding": "0",
    },
    ".response-markdown li": {
        "margin": "0.35rem 0",
    },
    ".response-markdown a": {
        "color": "#7CF7FF",
        "text-decoration": "underline",
    },
    ".response-markdown blockquote": {
        "margin": "1rem 0",
        "padding": "0.75rem 1rem",
        "border-left": "3px solid rgba(0, 255, 255, 0.35)",
        "background": "rgba(0, 255, 255, 0.05)",
        "color": "#CFFDFC",
    },
    ".response-markdown code": {
        "font-family": '"JetBrains Mono", "Courier New", monospace',
        "font-size": "0.92rem",
        "background": "rgba(0, 0, 0, 0.42)",
        "border": "1px solid rgba(143, 216, 143, 0.18)",
        "border-radius": "8px",
        "padding": "0.12rem 0.38rem",
    },
    ".response-markdown pre": {
        "background": "rgba(0, 0, 0, 0.48)",
        "border": "1px solid rgba(0, 255, 255, 0.16)",
        "border-radius": "14px",
        "padding": "1rem 1.1rem",
        "overflow-x": "auto",
        "margin": "1rem 0",
    },
    ".response-markdown pre code": {
        "background": "transparent",
        "border": "none",
        "padding": "0",
        "font-size": "0.9rem",
    },
    ".response-markdown table": {
        "width": "100%",
        "border-collapse": "collapse",
        "margin": "1rem 0",
        "font-size": "0.96rem",
    },
    ".response-markdown th, .response-markdown td": {
        "border": "1px solid rgba(143, 216, 143, 0.18)",
        "padding": "0.7rem 0.8rem",
        "text-align": "left",
        "vertical-align": "top",
    },
    ".response-markdown th": {
        "background": "rgba(0, 255, 255, 0.08)",
        "color": "#EFFFF9",
    },
    "@keyframes terminalFlicker": {
        "0%": {"opacity": "0.94", "filter": "drop-shadow(0 0 1px rgba(0, 255, 0, 0.35))"},
        "50%": {"opacity": "1", "filter": "drop-shadow(0 0 3px rgba(0, 255, 255, 0.18))"},
        "100%": {"opacity": "0.96", "filter": "drop-shadow(0 0 1px rgba(0, 255, 0, 0.28))"},
    },
    "@keyframes terminalBusy": {
        "0%": {"border-color": "rgba(0, 255, 255, 0.25)", "box-shadow": "0 0 0 0 rgba(0, 255, 255, 0.12)"},
        "50%": {"border-color": "rgba(0, 255, 255, 0.70)", "box-shadow": "0 0 0 4px rgba(0, 255, 255, 0.06)"},
        "100%": {"border-color": "rgba(0, 255, 255, 0.25)", "box-shadow": "0 0 0 0 rgba(0, 255, 255, 0.12)"},
    },
    ".terminal-busy": {
        "animation": "terminalBusy 1.6s ease-in-out infinite",
    },
    ".terminal-error": {
        "border": "1px solid rgba(255, 107, 107, 0.75) !important",
        "box-shadow": "0 0 0 2px rgba(255, 107, 107, 0.12) !important",
    },
}


def _render_css_declarations(declarations: dict[str, Any]) -> str:
    return ";".join(f"{property_name}: {value}" for property_name, value in declarations.items())


def _render_custom_css(rules: dict[str, Any]) -> str:
    blocks: list[str] = []
    for selector, declarations in rules.items():
        if selector.startswith("@keyframes"):
            frames = "".join(
                f"{frame_selector} {{{_render_css_declarations(frame_rules)}}}"
                for frame_selector, frame_rules in declarations.items()
            )
            blocks.append(f"{selector} {{{frames}}}")
            continue
        blocks.append(f"{selector} {{{_render_css_declarations(declarations)}}}")
    return "\n".join(blocks)


class DrawerState(rx.State):
    is_open: bool = False

    @rx.event
    def open_drawer(self) -> None:
        self.is_open = True

    @rx.event
    def close_drawer(self) -> None:
        self.is_open = False

    @rx.event
    def toggle_drawer(self) -> None:
        self.is_open = not bool(self.is_open)

    @rx.event
    def set_open(self, is_open: bool) -> None:
        self.is_open = bool(is_open)


class AgentDashboardState(rx.State):
    _PROMPT_AGENT_ALIASES = {
        "assistant": "one_tool",
        "default": "one_tool",
        "one_tool_agent": "one_tool",
    }

    @classmethod
    def _normalize_prompt_agent(cls, value: str) -> str:
        normalized = str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
        if not normalized:
            return "one_tool"
        return cls._PROMPT_AGENT_ALIASES.get(normalized, normalized)

    agent_sessions: list[AgentSession] = _build_sessions()
    active_session_id: str = "AGENT-1"
    cerberus_client_token: str = rx.LocalStorage("", name="cerberus_client_token", sync=True)
    dashboard_snapshot: str = rx.LocalStorage("", name=STATE_SNAPSHOT_STORAGE_KEY, sync=True)
    snapshot_hydrated: bool = False

    cpu_usage: int = 24
    ram_usage: int = 58
    net_mbps: float = 8.4
    alert_count: int = 1
    sensor_health: str = "Nominal"
    project_id: str = "unknown"
    target_ip: str = "unknown"
    session_uuid: str = "unknown"
    verbose_logs: bool = False
    parallel_execution: bool = True
    show_tool_logs: bool = True
    show_audit_logs: bool = True
    response_only: bool = True
    global_search_mode: bool = False
    admin_mode: bool = False
    clear_confirmation_required: bool = False
    tier_1_enabled: bool = True
    tier_2_enabled: bool = True
    tier_3_enabled: bool = True
    tier_4_enabled: bool = True
    show_config: bool = False
    env_dict: dict[str, str] = {}
    config_api_base_invalid: bool = False

    @staticmethod
    def _normalize_env_input(value: Any) -> str:
        if isinstance(value, bool):
            return "true" if value else "false"
        return str(value or "")

    @classmethod
    def _build_config_env_dict(cls, loaded: dict[str, str]) -> dict[str, str]:
        payload = {key: "" for key in CONFIG_CARD_ORDER}
        payload["CERBERUS_API_BASE"] = str(
            loaded.get("CERBERUS_API_BASE")
            or loaded.get("CEREBRO_API_BASE")
            or ""
        )
        payload["CEREBRO_MODEL"] = str(
            loaded.get("CEREBRO_MODEL")
            or loaded.get("CERBERUS_MODEL")
            or ""
        )
        payload["CERBERUS_ACTIVE_CONTAINER"] = str(
            loaded.get("CERBERUS_ACTIVE_CONTAINER")
            or loaded.get("CEREBRO_ACTIVE_CONTAINER")
            or ""
        )
        payload["REDIS_URL"] = str(
            loaded.get("REDIS_URL")
            or loaded.get("REFLEX_REDIS_URL")
            or ""
        )
        payload["DEBUG_MODE"] = cls._normalize_env_input(loaded.get("DEBUG_MODE", "false"))
        return payload

    def _intel_config_payload(self) -> dict[str, Any]:
        return {
            "version": 1,
            "verbose_logs": bool(self.verbose_logs),
            "parallel_execution": bool(self.parallel_execution),
            "show_tool_logs": bool(self.show_tool_logs),
            "show_audit_logs": bool(self.show_audit_logs),
            "response_only": bool(self.response_only),
            "global_search_mode": bool(self.global_search_mode),
            "admin_mode": bool(self.admin_mode),
            "tier_1_enabled": bool(self.tier_1_enabled),
            "tier_2_enabled": bool(self.tier_2_enabled),
            "tier_3_enabled": bool(self.tier_3_enabled),
            "tier_4_enabled": bool(self.tier_4_enabled),
        }

    def _schedule_intel_config_persist(self) -> None:
        client_token = str(self.cerberus_client_token or "").strip()
        if not client_token:
            return
        asyncio.create_task(self._persist_intel_config_to_redis(client_token))

    async def _persist_intel_config_to_redis(self, client_token: str) -> None:
        try:
            manager = await get_redis_manager()
            await manager.save_client_config(client_token, self._intel_config_payload())
        except Exception:
            # Redis persistence is optional; keep UI responsive if backend storage fails.
            return

    async def _hydrate_intel_config_from_redis(self, client_token: str) -> None:
        try:
            manager = await get_redis_manager()
            payload = await manager.load_client_config(client_token)
            if not isinstance(payload, dict):
                return

            async with self:
                self.verbose_logs = bool(payload.get("verbose_logs", self.verbose_logs))
                self.parallel_execution = bool(payload.get("parallel_execution", self.parallel_execution))
                self.show_tool_logs = bool(payload.get("show_tool_logs", self.show_tool_logs))
                self.show_audit_logs = bool(payload.get("show_audit_logs", self.show_audit_logs))
                self.response_only = bool(payload.get("response_only", self.response_only))
                self.global_search_mode = bool(payload.get("global_search_mode", self.global_search_mode))
                self.admin_mode = bool(payload.get("admin_mode", self.admin_mode))
                self.tier_1_enabled = bool(payload.get("tier_1_enabled", self.tier_1_enabled))
                self.tier_2_enabled = bool(payload.get("tier_2_enabled", self.tier_2_enabled))
                self.tier_3_enabled = bool(payload.get("tier_3_enabled", self.tier_3_enabled))
                self.tier_4_enabled = bool(payload.get("tier_4_enabled", self.tier_4_enabled))
                self._persist_dashboard_snapshot()
        except Exception:
            return

    def _resolve_active_session(self) -> AgentSession | None:
        index = self._index_for_session_id(self.active_session_id)
        if index is None:
            return None
        if index >= len(self.agent_sessions):
            return None
        return self.agent_sessions[index]

    def _refresh_session_metadata_from_runtime(self) -> None:
        active_session = self._resolve_active_session()

        env_project_id = str(os.getenv("CERBERUS_PROJECT_ID", "") or "").strip()
        env_target_ip = str(os.getenv("CERBERUS_TARGET_IP", "") or "").strip()
        env_session_uuid = str(os.getenv("CERBERUS_SESSION_UUID", "") or "").strip()
        token = str(self.cerberus_client_token or "").strip()
        project_fallback = f"dashboard-{token}" if token else (active_session.workspace_id if active_session else "unknown")
        session_fallback = token or (active_session.session_id if active_session else "unknown")

        self.project_id = env_project_id or project_fallback
        self.target_ip = env_target_ip or "unknown"
        self.session_uuid = env_session_uuid or session_fallback

    @rx.event
    def initialize_client_session(self) -> Any:
        if not str(self.cerberus_client_token or "").strip():
            self.cerberus_client_token = str(uuid.uuid4())
        self._refresh_session_metadata_from_runtime()
        self._persist_dashboard_snapshot()

        client_token = str(self.cerberus_client_token or "").strip()
        
        # Start Redis hydration and live subscription in background
        if client_token:
            asyncio.create_task(self._hydrate_intel_config_from_redis(client_token))
        asyncio.create_task(self._hydrate_from_redis())
        asyncio.create_task(self._subscribe_to_redis_live())
        
        return AgentDashboardState.ensure_snapshot_hydrated

    @rx.event
    def initialize_session_metadata(self) -> None:
        self._refresh_session_metadata_from_runtime()
        self._persist_dashboard_snapshot()

    @rx.var
    def session_uuid_short(self) -> str:
        value = str(self.session_uuid or "").strip()
        if len(value) <= 18:
            return value or "unknown"
        return f"{value[:8]}...{value[-6:]}"

    @rx.var
    def target_status_label(self) -> str:
        target = str(self.target_ip or "").strip().lower()
        return "TRACKED" if target and target not in {"unknown", "unset", "none"} else "UNSET"

    @rx.var
    def intel_drawer_alert(self) -> bool:
        return any(session.approval_required for session in self.agent_sessions)

    @rx.var
    def active_project(self) -> str:
        return str(self.project_id or "unknown")

    @rx.var
    def config_api_base(self) -> str:
        return str(self.env_dict.get("CERBERUS_API_BASE", "") or "")

    @rx.var
    def config_model(self) -> str:
        return str(self.env_dict.get("CEREBRO_MODEL", "") or "")

    @rx.var
    def config_active_container(self) -> str:
        return str(self.env_dict.get("CERBERUS_ACTIVE_CONTAINER", "") or "")

    @rx.var
    def config_redis_url(self) -> str:
        return str(self.env_dict.get("REDIS_URL", "") or "")

    @rx.var
    def config_debug_mode(self) -> bool:
        value = str(self.env_dict.get("DEBUG_MODE", "false") or "false").strip().lower()
        return value in {"1", "true", "yes", "on"}

    @rx.var
    def config_api_base_valid(self) -> bool:
        return not bool(self.config_api_base_invalid)

    @rx.var
    def config_save_disabled(self) -> bool:
        return bool(self.config_api_base_invalid)

    @rx.var
    def approval_modal_count(self) -> int:
        return sum(1 for session in self.agent_sessions if session.approval_required)

    @rx.event
    def toggle_config(self) -> Any:
        next_state = not bool(self.show_config)
        if next_state:
            try:
                self.env_dict = self._build_config_env_dict(env_manager.load_config())
                self.config_api_base_invalid = not bool(self.env_dict.get("CERBERUS_API_BASE", "").startswith(("http://", "https://")))
            except Exception as exc:
                return rx.toast.error(
                    "Configuration load failed.",
                    description=str(exc),
                    position="top-right",
                )
        self.show_config = next_state

    @rx.event
    def set_env_value(self, key: str, value: Any) -> None:
        updated = dict(self.env_dict)
        normalized_key = str(key or "")
        normalized_value = self._normalize_env_input(value)
        updated[normalized_key] = normalized_value
        self.env_dict = updated
        if normalized_key == "CERBERUS_API_BASE":
            self.config_api_base_invalid = not bool(normalized_value.startswith(("http://", "https://")))

    @rx.event
    def save_and_close(self) -> Any:
        if not self.config_api_base_valid:
            return rx.toast.error(
                "CERBERUS_API_BASE must start with http.",
                description="Use a full http:// or https:// URL before saving.",
                position="top-right",
            )

        restarted_services: list[str] = []
        try:
            for key in CONFIG_CARD_ORDER:
                restarted_services.extend(env_manager.update_env(key, self.env_dict.get(key, "")))
        except Exception as exc:
            return rx.toast.error(
                "Configuration save failed.",
                description=str(exc),
                position="top-right",
            )

        self.show_config = False
        self.env_dict = self._build_config_env_dict(env_manager.load_config())
        self.config_api_base_invalid = not bool(self.env_dict.get("CERBERUS_API_BASE", "").startswith(("http://", "https://")))
        self._refresh_session_metadata_from_runtime()
        self._persist_dashboard_snapshot()
        unique_services = sorted({service for service in restarted_services if service})
        return rx.toast.success(
            "Configuration updated.",
            description=(
                "Environment values were written to disk and applied to this process."
                + (f" Restarted: {', '.join(unique_services)}." if unique_services else "")
            ),
            position="top-right",
        )

    @rx.event
    def toggle_verbose_logs(self) -> None:
        self.verbose_logs = not bool(self.verbose_logs)
        self._persist_dashboard_snapshot()
        self._schedule_intel_config_persist()

    @rx.event
    def toggle_show_tool_logs(self) -> None:
        self.show_tool_logs = not bool(self.show_tool_logs)
        self._persist_dashboard_snapshot()
        self._schedule_intel_config_persist()

    @rx.event
    def toggle_show_audit_logs(self) -> None:
        self.show_audit_logs = not bool(self.show_audit_logs)
        self._persist_dashboard_snapshot()
        self._schedule_intel_config_persist()

    @rx.event
    def toggle_response_only(self) -> None:
        self.response_only = not bool(self.response_only)
        self._persist_dashboard_snapshot()
        self._schedule_intel_config_persist()

    @rx.event
    def toggle_global_search_mode(self) -> None:
        self.global_search_mode = not bool(self.global_search_mode)
        self._persist_dashboard_snapshot()
        self._schedule_intel_config_persist()

    @rx.event
    def toggle_admin_mode(self) -> None:
        self.admin_mode = not bool(self.admin_mode)
        self._persist_dashboard_snapshot()
        self._schedule_intel_config_persist()

    @rx.event
    def toggle_parallel_execution(self) -> None:
        self.parallel_execution = not bool(self.parallel_execution)
        self._persist_dashboard_snapshot()
        self._schedule_intel_config_persist()

    @rx.event
    def request_clear_all(self) -> None:
        self.clear_confirmation_required = True

    @rx.event
    def cancel_clear_all(self) -> None:
        self.clear_confirmation_required = False

    @rx.event(background=True)
    async def confirm_clear_all(self) -> None:
        async with self:
            sessions_to_clear = [session.model_copy(deep=True) for session in self.agent_sessions]
            client_token = str(self.cerberus_client_token or "").strip()
            self.clear_confirmation_required = False

        for session in sessions_to_clear:
            try:
                await terminate_action(self._orchestration_session_id_for_session(session))
            except Exception:
                continue

        workspace_root = _default_workspaces_root()
        try:
            workspace_root.mkdir(parents=True, exist_ok=True)
            for child in workspace_root.iterdir():
                try:
                    if child.is_dir():
                        shutil.rmtree(child, ignore_errors=True)
                    else:
                        child.unlink(missing_ok=True)
                except OSError:
                    continue
        except OSError:
            pass

        try:
            TOOL_EVENT_LOG_PATH.unlink(missing_ok=True)
        except OSError:
            pass

        if client_token:
            try:
                manager = await get_redis_manager()
                await manager.clear_history(client_token)
                await manager.client.delete(f"cerberus:config:{client_token}")
            except Exception:
                pass

        async with self:
            self.agent_sessions = []
            self.active_session_id = ""
            self.cpu_usage = 24
            self.ram_usage = 58
            self.net_mbps = 8.4
            self.alert_count = 0
            self.sensor_health = "Nominal"
            self.project_id = "unknown"
            self.target_ip = "unknown"
            self.session_uuid = "unknown"
            self._persist_dashboard_snapshot()

    @rx.event
    def toggle_risk_tier(self, tier_number: int) -> None:
        if tier_number == 1:
            self.tier_1_enabled = not bool(self.tier_1_enabled)
        elif tier_number == 2:
            self.tier_2_enabled = not bool(self.tier_2_enabled)
        elif tier_number == 3:
            self.tier_3_enabled = not bool(self.tier_3_enabled)
        elif tier_number == 4:
            self.tier_4_enabled = not bool(self.tier_4_enabled)
        self._persist_dashboard_snapshot()
        self._schedule_intel_config_persist()

    def _persist_dashboard_snapshot(self) -> None:
        self.dashboard_snapshot = _serialize_dashboard_snapshot(
            self.agent_sessions,
            active_session_id=self.active_session_id,
            cpu_usage=self.cpu_usage,
            ram_usage=self.ram_usage,
            net_mbps=self.net_mbps,
            alert_count=self.alert_count,
            sensor_health=self.sensor_health,
            project_id=self.project_id,
            target_ip=self.target_ip,
            session_uuid=self.session_uuid,
            verbose_logs=self.verbose_logs,
            parallel_execution=self.parallel_execution,
            show_tool_logs=self.show_tool_logs,
            show_audit_logs=self.show_audit_logs,
            response_only=self.response_only,
            tier_1_enabled=self.tier_1_enabled,
            tier_2_enabled=self.tier_2_enabled,
            tier_3_enabled=self.tier_3_enabled,
            tier_4_enabled=self.tier_4_enabled,
        )

    @rx.event
    def hydrate_from_snapshot(self) -> None:
        if self.snapshot_hydrated:
            return

        restored = _deserialize_dashboard_snapshot(self.dashboard_snapshot)
        if restored is None:
            # LocalStorage can arrive after initial on_load. Do not overwrite
            # existing browser state with defaults until hydration polling ends.
            if self.dashboard_snapshot.strip():
                self.snapshot_hydrated = True
                self._persist_dashboard_snapshot()
            return

        self.agent_sessions = restored["agent_sessions"]
        self.active_session_id = restored["active_session_id"]
        self.cpu_usage = restored["cpu_usage"]
        self.ram_usage = restored["ram_usage"]
        self.net_mbps = restored["net_mbps"]
        self.alert_count = restored["alert_count"]
        self.sensor_health = restored["sensor_health"]
        self.project_id = restored["project_id"] or self.project_id
        self.target_ip = restored["target_ip"] or self.target_ip
        self.session_uuid = restored["session_uuid"] or self.session_uuid
        self.verbose_logs = restored["verbose_logs"]
        self.parallel_execution = restored["parallel_execution"]
        self.show_tool_logs = restored["show_tool_logs"]
        self.show_audit_logs = restored["show_audit_logs"]
        self.response_only = restored["response_only"]
        self.tier_1_enabled = restored["tier_1_enabled"]
        self.tier_2_enabled = restored["tier_2_enabled"]
        self.tier_3_enabled = restored["tier_3_enabled"]
        self.tier_4_enabled = restored["tier_4_enabled"]
        self._refresh_session_metadata_from_runtime()
        self.snapshot_hydrated = True
        self._persist_dashboard_snapshot()

    @rx.event(background=True)
    async def ensure_snapshot_hydrated(self) -> None:
        async with self:
            if not str(self.cerberus_client_token or "").strip():
                self.cerberus_client_token = str(uuid.uuid4())
                self._refresh_session_metadata_from_runtime()
                self._persist_dashboard_snapshot()

        if self.snapshot_hydrated:
            return

        for _ in range(12):
            async with self:
                if self.snapshot_hydrated:
                    return

                restored = _deserialize_dashboard_snapshot(self.dashboard_snapshot)
                if restored is not None:
                    self.agent_sessions = restored["agent_sessions"]
                    self.active_session_id = restored["active_session_id"]
                    self.cpu_usage = restored["cpu_usage"]
                    self.ram_usage = restored["ram_usage"]
                    self.net_mbps = restored["net_mbps"]
                    self.alert_count = restored["alert_count"]
                    self.sensor_health = restored["sensor_health"]
                    self.project_id = restored["project_id"] or self.project_id
                    self.target_ip = restored["target_ip"] or self.target_ip
                    self.session_uuid = restored["session_uuid"] or self.session_uuid
                    self.verbose_logs = restored["verbose_logs"]
                    self.parallel_execution = restored["parallel_execution"]
                    self.show_tool_logs = restored["show_tool_logs"]
                    self.show_audit_logs = restored["show_audit_logs"]
                    self.response_only = restored["response_only"]
                    self.tier_1_enabled = restored["tier_1_enabled"]
                    self.tier_2_enabled = restored["tier_2_enabled"]
                    self.tier_3_enabled = restored["tier_3_enabled"]
                    self.tier_4_enabled = restored["tier_4_enabled"]
                    self._refresh_session_metadata_from_runtime()
                    self.snapshot_hydrated = True
                    self._persist_dashboard_snapshot()
                    return

            await asyncio.sleep(0.25)

        async with self:
            if not self.snapshot_hydrated:
                self._refresh_session_metadata_from_runtime()
                self.snapshot_hydrated = True
                self._persist_dashboard_snapshot()

    @rx.var
    def busy_count(self) -> int:
        return sum(1 for session in self.agent_sessions if session.is_busy)

    @rx.var
    def cleared_count(self) -> int:
        return sum(
            1
            for session in self.agent_sessions
            if all(status in {"cleared", "approved"} for status in session.tier_status.values())
        )

    @rx.var
    def review_count(self) -> int:
        return sum(1 for session in self.agent_sessions if session.approval_required)

    @rx.var
    def active_session_label(self) -> str:
        return self.active_session_id or "UNASSIGNED"

    @rx.var
    def layout_label(self) -> str:
        columns, rows = determine_grid_layout(self.session_count)
        return f"{columns}x{rows}"

    @rx.var
    def can_add_agent(self) -> bool:
        return self.session_count < MAX_SESSIONS

    def _refresh_system_health(self) -> None:
        active_load = sum(1 for session in self.agent_sessions if session.is_busy or session.approval_required)
        review_load = sum(1 for session in self.agent_sessions if session.approval_required)
        self.cpu_usage = min(98, random.randint(18, 34) + (active_load * 11))
        self.ram_usage = min(97, random.randint(42, 61) + (active_load * 7))
        self.net_mbps = round(random.uniform(1.2, 4.6) + (active_load * 1.8), 1)
        self.alert_count = review_load + random.randint(0, 1)
        self.sensor_health = "Elevated" if self.cpu_usage >= 70 or active_load >= 3 or review_load else "Nominal"
        self._persist_dashboard_snapshot()

    @rx.event
    def trigger_refresh_system_health(self) -> None:
        self._refresh_system_health()

    @rx.event
    def add_agent(self) -> None:
        if len(self.agent_sessions) >= MAX_SESSIONS:
            return

        next_slot = _next_session_slot(self.agent_sessions)
        if next_slot is None:
            return

        new_session = _new_session(next_slot)
        self.agent_sessions = sorted(
            [*self.agent_sessions, new_session],
            key=lambda session: session.session_id,
        )
        self.active_session_id = new_session.session_id
        self._refresh_session_metadata_from_runtime()
        self._refresh_system_health()
        self._persist_dashboard_snapshot()

    @rx.event
    def remove_agent(self, session_id: str) -> None:
        index = self._index_for_session_id(session_id)
        if index is None:
            return

        session = self.agent_sessions[index]
        if session.is_busy or session.approval_required:
            self._append_log(index, "System", "Detach is locked while the agent is busy or awaiting approval.")
            return

        self.agent_sessions = [item for item in self.agent_sessions if item.session_id != session_id]
        if self.active_session_id == session_id:
            self.active_session_id = self.agent_sessions[0].session_id if self.agent_sessions else ""
        self._refresh_session_metadata_from_runtime()
        self._refresh_system_health()
        self._persist_dashboard_snapshot()

    @rx.var
    def visible_sessions(self) -> list[AgentSession]:
        visible_sessions: list[AgentSession] = []

        for session in self.agent_sessions:
            visible_logs = _visible_session_logs(
                session.logs,
                response_only=bool(self.response_only),
                show_audit_logs=bool(self.show_audit_logs),
            )
            if visible_logs == session.logs:
                visible_sessions.append(session)
                continue

            session_copy = session.model_copy(deep=True)
            session_copy.logs = visible_logs
            visible_sessions.append(session_copy)

        return visible_sessions

    @rx.var
    def session_count(self) -> int:
        return len(self.agent_sessions)

    @rx.var
    def grid_cols(self) -> str:
        return determine_grid_layout(self.session_count)[0]

    @rx.var
    def grid_rows(self) -> str:
        return determine_grid_layout(self.session_count)[1]

    @rx.event
    def set_active_session(self, session_id: str) -> None:
        if self._index_for_session_id(session_id) is None:
            return
        self.active_session_id = session_id
        self._refresh_session_metadata_from_runtime()
        self._persist_dashboard_snapshot()

    @rx.event
    def set_session_command(self, session_id: str, value: str) -> None:
        index = self._index_for_session_id(session_id)
        if index is None:
            return

        session = self._session_copy(index)
        session.command_input = value
        self._store_session(index, session)

    def _index_for_session_id(self, session_id: str) -> int | None:
        for index, session in enumerate(self.agent_sessions):
            if session.session_id == session_id:
                return index
        return None

    def _index_for_origin_id(self, origin_id: str, *, fallback_index: int | None = None) -> int | None:
        normalized = str(origin_id or "").strip()
        if normalized:
            base_id = normalized.split(":")[-1]
            resolved = self._index_for_session_id(base_id)
            if resolved is not None:
                return resolved

        if isinstance(fallback_index, int) and 0 <= fallback_index < len(self.agent_sessions):
            return fallback_index

        if self.agent_sessions:
            return 0
        return None

    def _session_copy(self, index: int) -> AgentSession:
        return self.agent_sessions[index].model_copy(deep=True)

    def _store_session(self, index: int, session: AgentSession) -> None:
        sessions = list(self.agent_sessions)
        sessions[index] = session
        self.agent_sessions = sessions
        self._persist_dashboard_snapshot()

    def _append_log(self, index: int, role: str, content: str, *, environment_label: str = "") -> None:
        cleaned = content.rstrip()
        if not cleaned:
            return

        if role == "Audit" and not bool(self.show_audit_logs):
            return

        if role in {"System", "Audit"} and not _is_error_log_content(cleaned):
            return

        if role == "Tool":
            self._write_tool_event_log(index, cleaned, environment_label=environment_label)

        session = self._session_copy(index)
        updated_logs = [*session.logs, _log_entry(role, cleaned, environment_label=environment_label)]
        overflow = max(0, len(updated_logs) - MAX_LOG_ENTRIES)
        session.logs = updated_logs[-MAX_LOG_ENTRIES:]
        if session.prompt_response_log_index is not None:
            session.prompt_response_log_index -= overflow
            if session.prompt_response_log_index < 0:
                session.prompt_response_log_index = None
        if session.stream_log_index is not None:
            session.stream_log_index -= overflow
            if session.stream_log_index < 0:
                session.stream_log_index = None
                session.stream_call_id = ""
        self._store_session(index, session)

    def _append_or_update_stream_log(
        self,
        index: int,
        role: str,
        token: str,
        *,
        call_id: str = "",
    ) -> None:
        cleaned = token.rstrip("\r\n")
        if not cleaned:
            return

        if role == "Tool":
            self._write_tool_event_log(index, cleaned, call_id=call_id)

        session = self._session_copy(index)
        current_call_id = call_id or session.stream_call_id or session.active_tool_name

        # If we switched to a new call, start a fresh stream entry.
        if session.stream_call_id and current_call_id and session.stream_call_id != current_call_id:
            session.stream_log_index = None

        if session.stream_log_index is not None and 0 <= session.stream_log_index < len(session.logs):
            existing = dict(session.logs[session.stream_log_index])
            existing_content = str(existing.get("content", "") or "")
            existing["content"] = (
                f"{existing_content}\n{cleaned}" if existing_content else cleaned
            )
            existing["timestamp"] = _timestamp()
            logs = list(session.logs)
            logs[session.stream_log_index] = existing
            session.logs = logs
        else:
            logs = [*session.logs, _log_entry(role, cleaned)]
            overflow = max(0, len(logs) - MAX_LOG_ENTRIES)
            session.logs = logs[-MAX_LOG_ENTRIES:]
            session.stream_log_index = len(session.logs) - 1
            if session.prompt_response_log_index is not None:
                session.prompt_response_log_index -= overflow
                if session.prompt_response_log_index < 0:
                    session.prompt_response_log_index = None

        session.stream_call_id = current_call_id
        self._store_session(index, session)

    def _write_tool_event_log(
        self,
        index: int,
        content: str,
        *,
        call_id: str = "",
        environment_label: str = "",
    ) -> None:
        if index >= len(self.agent_sessions):
            return

        session = self.agent_sessions[index]
        payload = {
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "session_id": session.session_id,
            "workspace": session.workspace,
            "tool_name": session.active_tool_name,
            "call_id": call_id,
            "content": content,
            "environment_label": environment_label,
        }

        try:
            TOOL_EVENT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
            with TOOL_EVENT_LOG_PATH.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(payload, ensure_ascii=True) + "\n")
        except OSError:
            # Logging failures must never interrupt dashboard execution.
            return

    def _reset_stream_log(self, index: int) -> None:
        session = self._session_copy(index)
        session.stream_log_index = None
        session.stream_call_id = ""
        self._store_session(index, session)

    def _capture_prompt_dispatch_output(self, index: int, message: str) -> None:
        session = self._session_copy(index)
        stream_line_limit = max(PROMPT_STREAM_LINE_LIMIT, 2000)
        session.prompt_stream_lines = [*session.prompt_stream_lines, message][-stream_line_limit:]
        self._store_session(index, session)

        extracted = _extract_prompt_response_from_lines(session.prompt_stream_lines)
        if extracted:
            self._upsert_prompt_response_log(index, extracted)

    def _upsert_prompt_response_log(self, index: int, content: str) -> None:
        cleaned = content.strip()
        if not cleaned:
            return

        session = self._session_copy(index)
        logs, response_index = _upsert_assistant_response_log(
            session.logs,
            session.prompt_response_log_index,
            cleaned,
        )
        session.logs = logs
        session.prompt_response_log_index = response_index
        self._store_session(index, session)

    def _finalize_prompt_dispatch_output(self, index: int, output: Any) -> None:
        session = self._session_copy(index)
        combined_lines = list(session.prompt_stream_lines)
        if isinstance(output, str) and output:
            combined_lines.extend(output.splitlines())

        extracted = _extract_prompt_response_from_lines(
            combined_lines,
            fallback_to_plain_text=True,
        )
        if extracted:
            self._upsert_prompt_response_log(index, extracted)

        session = self._session_copy(index)
        session.prompt_stream_lines = []
        session.prompt_response_log_index = None
        session.stream_log_index = None
        session.stream_call_id = ""
        self._store_session(index, session)

    @staticmethod
    def _role_for_runtime_event(channel: str, active_tool_name: str) -> str:
        normalized_channel = str(channel or "stdout").strip().lower()
        if normalized_channel == "stderr":
            return "Audit"
        if normalized_channel == "status":
            return "System"
        if normalized_channel in {"stdout", "partial_stdout"} and active_tool_name == PROMPT_DISPATCH_TOOL:
            return "Assistant"
        return "Tool"

    def _set_pending_action(
        self,
        index: int,
        *,
        pending_action: dict[str, Any] | None,
        approval_required: bool,
    ) -> None:
        session = self._session_copy(index)
        session.pending_action = pending_action
        session.approval_required = approval_required
        source = ""
        pending_tool_name = ""
        raw_arguments = ""
        repaired_arguments = ""
        message = ""
        risk_tier = 0
        if isinstance(pending_action, dict):
            source = str(pending_action.get("approval_source", "policy_pre_dispatch") or "").strip()
            pending_tool_name = str(pending_action.get("tool_name", "") or "").strip()
            raw_arguments = self._stringify_pending_arguments(pending_action.get("raw_arguments"))
            repaired_arguments = self._stringify_pending_arguments(pending_action.get("repaired_arguments"))
            if not repaired_arguments or repaired_arguments == "{}":
                repaired_arguments = self._stringify_pending_arguments(pending_action.get("arguments"))
            message = str(pending_action.get("message", "") or "").strip()
            try:
                risk_tier = int(pending_action.get("risk_tier", 0) or 0)
            except Exception:
                risk_tier = 0

        session.pending_approval_source = source
        session.pending_tool_name = pending_tool_name
        session.pending_raw_arguments = raw_arguments
        session.pending_repaired_arguments = repaired_arguments
        session.pending_message = message
        session.pending_risk_tier = risk_tier
        self._store_session(index, session)

    def _append_terminal_feedback(self, index: int, content: str, *, role: str = "System") -> None:
        cleaned = str(content or "").strip()
        if not cleaned:
            return
        session = self._session_copy(index)
        session.logs = [*session.logs, _log_entry(role, cleaned)][-MAX_LOG_ENTRIES:]
        self._store_session(index, session)

    @staticmethod
    def _parse_slash_command(command_text: str) -> tuple[str, list[str]]:
        stripped = str(command_text or "").strip()
        if not stripped:
            return "", []
        try:
            tokens = shlex.split(stripped, posix=os.name != "nt")
        except Exception:
            tokens = stripped.split()
        if not tokens:
            return "", []
        return tokens[0].lower(), tokens[1:]

    @staticmethod
    def _build_help_summary() -> str:
        lines = ["Available slash commands:"]
        for command, metadata in COMMAND_REGISTRY.items():
            tier = int(metadata.get("tier", 1) or 1)
            desc = str(metadata.get("desc", "") or "")
            lines.append(f"{command} (Tier {tier}) - {desc}")
        return "\n".join(lines)

    async def _reset_session_context(self, index: int) -> None:
        session = self._session_copy(index)
        session.logs = []
        session.command_input = ""
        session.status = "ready"
        session.is_busy = False
        session.termination_requested = False
        session.approval_required = False
        session.pending_action = None
        session.pending_approval_source = ""
        session.pending_tool_name = ""
        session.pending_raw_arguments = ""
        session.pending_repaired_arguments = ""
        session.pending_message = ""
        session.pending_risk_tier = 0
        session.policy_history = []
        session.tier_status = _default_tier_status()
        session.last_command = ""
        session.active_tool_name = ""
        session.status_line = "Agent context reset by operator."
        session.prompt_stream_lines = []
        session.prompt_response_log_index = None
        session.stream_log_index = None
        session.stream_call_id = ""
        self._store_session(index, session)

        client_token = str(self.cerberus_client_token or "").strip()
        if client_token:
            try:
                manager = await get_redis_manager()
                await manager.clear_history(client_token)
            except Exception:
                pass

        self._append_terminal_feedback(index, "System: Agent session reset and Redis-backed history cleared.")
        self._refresh_system_health()

    def _export_session_logs(self, index: int) -> Path:
        session = self._session_copy(index)
        logs_dir = REPO_ROOT / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = logs_dir / f"{session.session_id.lower()}_{stamp}.jsonl"
        with output_path.open("w", encoding="utf-8") as handle:
            for entry in session.logs:
                handle.write(json.dumps(entry, ensure_ascii=True) + "\n")
        return output_path

    def _archive_session(self, index: int) -> Path:
        """Archive the current session as a Mission Report."""
        from cerberus.infrastructure.reporting import archive_session as archive_log
        
        session = self._session_copy(index)
        logs_dir = REPO_ROOT / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        
        # First export logs
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_path = logs_dir / f"{session.session_id.lower()}_{stamp}.jsonl"
        with log_path.open("w", encoding="utf-8") as handle:
            for entry in session.logs:
                handle.write(json.dumps(entry, ensure_ascii=True) + "\n")
        
        # Then archive to mission report
        archive_dir = REPO_ROOT / "archive"
        archive_dir.mkdir(parents=True, exist_ok=True)
        
        security_summary = f"Session {session.session_id} archived. Status: {session.status}"
        report_path = archive_log(log_path, archive_dir=archive_dir, custom_summary=security_summary)
        
        return report_path

    async def _dispatch_slash_command(self, index: int, command_text: str) -> None:
        command_name, _args = self._parse_slash_command(command_text)
        if not command_name:
            self._append_terminal_feedback(index, "System: Empty command received.")
            return

        if command_name == "/agent":
            if self._apply_agent_switch_command(index, command_text):
                self._persist_dashboard_snapshot()
            return

        metadata = COMMAND_REGISTRY.get(command_name)
        if metadata is None:
            self._append_terminal_feedback(index, f"System: Command not recognized: {command_name}")
            return

        command_tier = int(metadata.get("tier", 1) or 1)
        if command_tier >= 3 and not bool(self.admin_mode):
            self._append_terminal_feedback(
                index,
                f"System: Permission Required. {command_name} is Tier-{command_tier} and requires Admin mode.",
            )
            return

        if command_name == "/clear":
            session = self._session_copy(index)
            session.logs = []
            session.command_input = ""
            session.status = "ready"
            session.is_busy = False
            session.status_line = "Terminal cleared by operator command."
            self._store_session(index, session)
            self._append_terminal_feedback(index, "System: Active terminal cleared.")
            self._refresh_system_health()
            return

        if command_name == "/reset":
            await self._reset_session_context(index)
            return

        if command_name == "/search":
            self.global_search_mode = not bool(self.global_search_mode)
            self._persist_dashboard_snapshot()
            self._schedule_intel_config_persist()
            mode_label = "ON" if self.global_search_mode else "OFF"
            self._append_terminal_feedback(index, f"System: Global Search Mode is now {mode_label}.")
            return

        if command_name == "/approve":
            if index >= len(self.agent_sessions):
                return
            session = self._session_copy(index)
            if not isinstance(session.pending_action, dict):
                self._append_terminal_feedback(index, "System: No pending Tier-4 action is awaiting approval.")
                return
            await self.approve_pending_action(session.session_id)
            self._append_terminal_feedback(index, "System: Approval signal sent to release the Safety Cage.")
            return

        if command_name == "/logs":
            output_path = self._export_session_logs(index)
            try:
                relative_path = output_path.relative_to(REPO_ROOT)
                rendered_path = str(relative_path)
            except ValueError:
                rendered_path = str(output_path)
            self._append_terminal_feedback(index, f"System: Session logs exported to {rendered_path}.")
            return

        if command_name == "/archive":
            try:
                report_path = self._archive_session(index)
                if report_path.exists():
                    try:
                        relative_path = report_path.relative_to(REPO_ROOT)
                        rendered_path = str(relative_path)
                    except ValueError:
                        rendered_path = str(report_path)
                    self._append_terminal_feedback(index, f"System: Session archived to Mission Report: {rendered_path}")
                else:
                    self._append_terminal_feedback(index, "System: Failed to archive session.")
            except Exception as e:
                self._append_terminal_feedback(index, f"System: Archive error: {str(e)[:100]}")
            return

        if command_name == "/help":
            self._append_terminal_feedback(index, self._build_help_summary())
            return

    @rx.event
    def run_quick_command(self, command: str) -> Any:
        normalized = str(command or "").strip()
        index = self._index_for_session_id(self.active_session_id)
        if index is None:
            return rx.toast.error(
                "No active session.",
                description="Attach an agent terminal before executing quick commands.",
                position="top-right",
            )

        command_name, _args = self._parse_slash_command(normalized)
        metadata = COMMAND_REGISTRY.get(command_name)
        if metadata is None:
            return rx.toast.error(
                "Unknown command.",
                description=normalized or "(empty)",
                position="top-right",
            )

        command_tier = int(metadata.get("tier", 1) or 1)
        if command_tier >= 3 and not bool(self.admin_mode):
            return rx.toast.warning(
                "Permission Required",
                description=f"{command_name} is Tier-{command_tier}. Enable Admin Mode first.",
                position="top-right",
            )

        session = self._session_copy(index)
        session.command_input = normalized
        self._store_session(index, session)
        return [
            rx.toast.info(
                "Quick command queued.",
                description=normalized,
                position="top-right",
            ),
            AgentDashboardState.process_session_command(session.session_id),
        ]

    def _append_policy_history(
        self,
        index: int,
        *,
        action: dict[str, Any],
        report: PolicyReport,
        system_state: dict[str, Any],
    ) -> None:
        session = self._session_copy(index)
        session.policy_history = [
            *session.policy_history,
            {
                "tool_name": action.get("tool_name", ""),
                "arguments": action.get("arguments", {}),
                "system_state": system_state,
                "status": report.status,
            },
        ][-POLICY_HISTORY_LIMIT:]
        self._store_session(index, session)
    
    @staticmethod
    def _is_high_risk_report(report: PolicyReport) -> bool:
        risk_level = str(getattr(report, "risk_level", "") or "").strip().lower()
        if risk_level in HIGH_RISK_LEVELS:
            return True
        if bool(getattr(report, "manual_approval_required", False)):
            return True
        return bool(getattr(report, "blocked", False))

    @staticmethod
    def _workspace_dir() -> str:
        return str(_default_workspaces_root())

    def _project_id_for_session(self, session: AgentSession) -> str:
        token = re.sub(r"[^a-zA-Z0-9._-]", "-", str(self.cerberus_client_token or "").strip())
        workspace_id = session.workspace_id.strip() or "dashboard"
        return f"{token}-{workspace_id}" if token else workspace_id

    def _orchestration_session_id_for_session(self, session: AgentSession) -> str:
        token = re.sub(r"[^a-zA-Z0-9._-]", "-", str(self.cerberus_client_token or "").strip())
        base_session_id = session.session_id.strip() or "AGENT"
        return f"{token}:{base_session_id}" if token else base_session_id

    @staticmethod
    def _system_state_for_session(session: AgentSession) -> dict[str, Any]:
        return {
            "workspace": session.workspace,
            "status": session.status,
            "approval_required": session.approval_required,
            "status_line": session.status_line,
            "tier_status": dict(session.tier_status),
        }

    @staticmethod
    def _parse_prompt_to_action(prompt: str) -> dict[str, Any]:
        text = prompt.strip()
        parsed = None
        if text:
            try:
                parsed = parse_json_lenient(text, prefer_last=True)
            except Exception:
                parsed = None
        if isinstance(parsed, dict):
            action = dict(parsed)
            if "command" in action and "tool_name" not in action:
                action["tool_name"] = "execute_cli_command"
            if "prompt" in action and "tool_name" not in action:
                action["tool_name"] = PROMPT_DISPATCH_TOOL
                action["arguments"] = {"prompt": str(action.get("prompt", "") or "").strip()}
            if not isinstance(action.get("arguments"), dict):
                action["arguments"] = {}
            return action

        lowered = text.lower()
        if lowered.startswith("read "):
            return {"tool_name": "read_file", "arguments": {"file_path": text[5:].strip()}}
        if lowered.startswith("list "):
            return {"tool_name": "list_dir", "arguments": {"path": text[5:].strip()}}
        if AgentDashboardState._looks_like_explicit_command(text):
            return {
                "tool_name": "execute_cli_command",
                "arguments": {"command": text},
                "command": text,
            }
        return {
            "tool_name": PROMPT_DISPATCH_TOOL,
            "arguments": {"prompt": text},
            "prompt": text,
        }

    @staticmethod
    def _parse_agent_switch_command(text: str) -> tuple[str, str] | None:
        stripped = text.strip()
        if not stripped.lower().startswith("/agent"):
            return None

        try:
            tokens = shlex.split(stripped, posix=os.name != "nt")
        except Exception:
            tokens = stripped.split()

        if not tokens:
            return ("show", "")

        if len(tokens) == 1:
            return ("show", "")

        sub = tokens[1].strip().lower()
        if sub in {"show", "current", "status"}:
            return ("show", "")
        if sub == "select":
            if len(tokens) < 3:
                return ("invalid", "")
            return ("set", tokens[2].strip())
        return ("set", tokens[1].strip())

    def _apply_agent_switch_command(self, index: int, command_text: str) -> bool:
        parsed = self._parse_agent_switch_command(command_text)
        if parsed is None:
            return False

        operation, value = parsed
        self._append_log(index, "User", command_text)
        session = self._session_copy(index)

        if operation == "invalid":
            self._append_log(index, "System", "Usage: /agent <name> or /agent select <name>")
            session.status = "ready"
            session.status_line = "Agent switch command requires an agent name."
            self._store_session(index, session)
            self._refresh_system_health()
            return True

        if operation == "show":
            active_agent = (session.prompt_agent or "one_tool").strip() or "one_tool"
            self._append_log(index, "System", f"Active prompt agent: {active_agent}")
            session.status = "ready"
            session.status_line = f"Prompt agent unchanged ({active_agent})."
            self._store_session(index, session)
            self._refresh_system_health()
            return True

        normalized = self._normalize_prompt_agent(value)
        if not normalized:
            self._append_log(index, "System", "Usage: /agent <name> or /agent select <name>")
            session.status = "ready"
            session.status_line = "Agent switch command requires an agent name."
            self._store_session(index, session)
            self._refresh_system_health()
            return True

        session.prompt_agent = normalized
        self._append_log(index, "System", f"Prompt agent set to {normalized}")
        session.status = "ready"
        session.status_line = f"Prompt agent switched to {normalized}."
        self._store_session(index, session)
        self._refresh_system_health()
        return True

    @staticmethod
    def _looks_like_explicit_command(text: str) -> bool:
        stripped = text.strip()
        if not stripped:
            return False
        if stripped.startswith("/"):
            return True
        if any(token in stripped for token in SHELL_CONTROL_TOKENS):
            return True

        try:
            tokens = shlex.split(stripped, posix=os.name != "nt")
        except Exception:
            tokens = stripped.split()

        if not tokens:
            return False

        first_token = tokens[0].strip()
        if not first_token:
            return False
        if first_token.startswith(("./", "../", "/", "~/")):
            return True

        normalized = Path(first_token).name.lower()
        if normalized in KNOWN_COMMAND_TOKENS:
            return True
        return shutil.which(normalized) is not None

    def _policy_engine_for_session(self, session: AgentSession) -> PolicyEngine:
        return PolicyEngine(
            workspace_dir=self._workspace_dir(),
            project_id=self._project_id_for_session(session),
        )

    @staticmethod
    def _format_policy_message(report: PolicyReport) -> str:
        primary = report.primary_finding
        if primary is not None:
            return primary.message
        return f"PolicyEngine PASS. Risk={report.risk_level}."

    @staticmethod
    def _format_execution_output(output: Any) -> str:
        if isinstance(output, (dict, list)):
            return json.dumps(output, ensure_ascii=True, indent=2, sort_keys=True)
        return str(output)

    @staticmethod
    def _stringify_pending_arguments(value: Any) -> str:
        if isinstance(value, str):
            cleaned = value.strip()
            return cleaned if cleaned else "{}"
        if isinstance(value, (dict, list)):
            return json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True)
        if value is None:
            return "{}"
        return str(value)

    @staticmethod
    def _is_runtime_pending_approval_payload(output: Any) -> bool:
        if not isinstance(output, dict):
            return False
        status = str(output.get("status", "") or "").strip().upper()
        return status == "PENDING_APPROVAL" and output.get("error") == "tool_execution_pending_approval"

    def _build_runtime_pending_action(
        self,
        *,
        action: dict[str, Any],
        output: dict[str, Any],
    ) -> dict[str, Any]:
        tool_name = str(output.get("tool", "") or action.get("tool_name", "")).strip()
        raw_arguments = output.get("raw_arguments")
        repaired_arguments = output.get("repaired_arguments")
        parsed_arguments = output.get("arguments") if isinstance(output.get("arguments"), dict) else action.get("arguments", {})
        risk_tier = int(output.get("risk_tier", 0) or 0)
        return {
            "approval_source": "runtime_tool_validation",
            "approval_state": "AWAITING_APPROVAL",
            "tool_name": tool_name,
            "status": "PENDING_APPROVAL",
            "message": str(output.get("message", "Tool execution paused pending operator approval.") or "").strip(),
            "policy": output.get("policy", {}),
            "risk_tier": risk_tier,
            "raw_arguments": raw_arguments,
            "repaired_arguments": repaired_arguments,
            "arguments": parsed_arguments if isinstance(parsed_arguments, dict) else {},
            "call_id": str(output.get("call_id", "") or "").strip(),
            "original_action": {
                "tool_name": action.get("tool_name", ""),
                "arguments": action.get("arguments", {}),
                "prompt": action.get("prompt"),
                "command": action.get("command"),
            },
        }

    @staticmethod
    def _derive_tier_status(
        report: PolicyReport,
        *,
        manual_approval_granted: bool = False,
    ) -> dict[str, str]:
        tier_findings: dict[int, list[Any]] = {tier_number: [] for tier_number in range(1, len(AUDIT_TIERS) + 1)}
        for finding in report.findings:
            tier_findings.setdefault(finding.tier, []).append(finding)

        blocking_tier = next((finding.tier for finding in report.findings if finding.level == "block"), None)
        statuses: dict[str, str] = {}

        for tier_number, (tier_key, _) in enumerate(AUDIT_TIERS, start=1):
            if blocking_tier is not None and tier_number > blocking_tier:
                statuses[tier_key] = "standby"
                continue

            findings = tier_findings.get(tier_number, [])
            if tier_number == 4 and report.manual_approval_required:
                statuses[tier_key] = "review"
            elif tier_number == 4 and manual_approval_granted and findings:
                statuses[tier_key] = "approved"
            elif any(finding.level == "block" for finding in findings):
                statuses[tier_key] = "blocked"
            elif findings:
                statuses[tier_key] = "warning"
            else:
                statuses[tier_key] = "cleared"

        return statuses

    @staticmethod
    def _derive_session_status(
        report: PolicyReport,
        *,
        is_busy: bool,
        manual_approval_granted: bool = False,
    ) -> str:
        if is_busy:
            return "busy"
        if report.manual_approval_required:
            return "review"
        if report.blocked:
            return "blocked"
        if manual_approval_granted:
            return "approved"
        if report.findings:
            return "warning"
        return "ready"

    def _apply_report_state(
        self,
        index: int,
        report: PolicyReport,
        *,
        is_busy: bool,
        status_line: str,
        manual_approval_granted: bool = False,
        status: str | None = None,
    ) -> None:
        session = self._session_copy(index)
        session.is_busy = is_busy
        session.status = status or self._derive_session_status(
            report,
            is_busy=is_busy,
            manual_approval_granted=manual_approval_granted,
        )
        session.status_line = status_line
        if not is_busy:
            session.active_tool_name = ""
        session.tier_status = self._derive_tier_status(report, manual_approval_granted=manual_approval_granted)
        self._store_session(index, session)
        
        # Broadcast state change to Redis pub/sub
        client_token = str(self.cerberus_client_token or "").strip()
        if client_token:
            asyncio.create_task(
                broadcast_state_change(
                    client_token,
                    "BUSY" if is_busy else "ACTIVE",
                    index=index,
                    metadata={
                        "session_id": session.session_id,
                        "status": session.status,
                        "status_line": status_line,
                        "active_tool": session.active_tool_name,
                    },
                )
            )

    def _prime_session(self, index: int, command: str, tool_name: str) -> None:
        session = self._session_copy(index)
        session.is_busy = True
        session.status = "verifying"
        session.termination_requested = False
        session.approval_required = False
        session.pending_action = None
        session.pending_approval_source = ""
        session.pending_tool_name = ""
        session.pending_raw_arguments = ""
        session.pending_repaired_arguments = ""
        session.pending_message = ""
        session.pending_risk_tier = 0
        session.command_input = ""
        session.last_command = command
        session.active_tool_name = tool_name
        session.status_line = "Running policy verification."
        session.prompt_stream_lines = []
        session.prompt_response_log_index = None
        session.stream_log_index = None
        session.stream_call_id = ""
        session.tier_status = {tier_key: "pending" for tier_key, _ in AUDIT_TIERS}
        session.logs = [
            *session.logs,
            _log_entry("User", command),
        ][-MAX_LOG_ENTRIES:]
        self._store_session(index, session)
        self.active_session_id = session.session_id
        
        # Broadcast state change to Redis pub/sub
        client_token = str(self.cerberus_client_token or "").strip()
        if client_token:
            asyncio.create_task(
                broadcast_state_change(
                    client_token,
                    "BUSY",
                    index=index,
                    metadata={
                        "session_id": session.session_id,
                        "status": "verifying",
                        "status_line": "Running policy verification.",
                        "active_tool": tool_name,
                    },
                )
            )

    async def _handle_runtime_event(self, index: int, event: dict[str, Any]) -> None:
        # Extract client token for Redis history/pub-sub (injected by _log_emitter)
        client_token = str(event.get("cerberus_client_token", "") or "").strip()
        
        channel = str(event.get("channel", "stdout") or "stdout").strip().lower()
        if channel == "on_token":
            channel = "partial_stdout"
        elif channel == "on_tool_call":
            channel = "status"
        tool_name = str(event.get("tool_name", "") or "").strip()
        if channel == "partial_stdout":
            channel = "stdout"
        raw_message = str(event.get("message", "") or "")
        if channel in {"stdout", "stderr"}:
            message = raw_message.rstrip("\r\n")
            if message == "":
                # Preserve blank streaming lines so terminal output shape remains intact.
                message = " "
        else:
            message = raw_message.rstrip()
        call_id = str(event.get("call_id", "") or "").strip()

        # Push to Redis history and broadcast live (non-blocking)
        if client_token and message:
            origin_id = ""
            if 0 <= index < len(self.agent_sessions):
                origin_id = self.agent_sessions[index].session_id
            asyncio.create_task(self._push_to_redis_history(client_token, channel, message, origin_id=origin_id))

        if channel == "on_tool_start":
            anchor = message or f"Starting {tool_name or 'tool'}..."
            async with self:
                if index >= len(self.agent_sessions):
                    return

                session = self._session_copy(index)
                if tool_name:
                    session.active_tool_name = tool_name
                if message:
                    session.status_line = message
                self._store_session(index, session)
                self._append_or_update_stream_log(
                    index,
                    "Tool",
                    anchor,
                    call_id=call_id or tool_name or session.active_tool_name,
                )
            return

        if not message:
            return

        async with self:
            if index >= len(self.agent_sessions):
                return

            session = self._session_copy(index)

            if channel == "stdout" and session.active_tool_name == PROMPT_DISPATCH_TOOL:
                self._capture_prompt_dispatch_output(index, message)
                return

            role = "Tool"
            if channel == "status":
                session.status_line = message
                role = self._role_for_runtime_event(channel, session.active_tool_name)
                self._store_session(index, session)
            else:
                role = self._role_for_runtime_event(channel, session.active_tool_name)
            if role in {"System", "Audit"} and not _is_error_log_content(message):
                return
            if channel in {"stdout", "stderr"} and session.is_busy:
                self._append_or_update_stream_log(index, role, message, call_id=call_id)
            else:
                self._append_log(index, role, message)

    async def _push_to_redis_history(
        self,
        client_token: str,
        channel: str,
        message: str,
        *,
        origin_id: str = "",
    ) -> None:
        """Push streaming message to Redis history list and broadcast to live channel.
        
        This runs in the background (via asyncio.create_task) to avoid blocking
        the main state update flow. Both history (RPUSH to list) and live broadcast
        (PUBLISH to channel) ensure persistence and real-time delivery.
        """
        try:
            manager = await get_redis_manager()
            
            payload = {
                "type": "runtime_log",
                "origin_id": str(origin_id or "").strip(),
                "channel": str(channel or "stdout").strip(),
                "message": str(message or ""),
            }
            formatted_message = json.dumps(payload, ensure_ascii=True, separators=(",", ":"))
            
            # Push to Redis history list for persistence
            await manager.push_history(client_token, formatted_message)
            
            # Broadcast to live channel for connected clients
            await manager.publish_live(client_token, formatted_message)
        except Exception as e:
            # Log but don't crash - Redis is optional enhancement
            import logging
            logging.warning(f"Failed to push to Redis history for {client_token}: {e}")

    async def _append_hydrated_log(self, *, origin_id: str, channel: str, message: str) -> None:
        text = str(message or "").strip()
        if not text:
            return

        async with self:
            index = self._index_for_origin_id(origin_id)
            if index is None:
                return
            session = self._session_copy(index)
            role = self._role_for_runtime_event(channel, session.active_tool_name)
            if role == "Audit" and not bool(self.show_audit_logs):
                return
            if role in {"System", "Audit"} and not _is_error_log_content(text):
                return
            session.logs = [
                *session.logs,
                _log_entry(role, text),
            ][-MAX_LOG_ENTRIES:]
            self._store_session(index, session)

    async def _hydrate_from_redis(self) -> None:
        """Restore terminal state from Redis history on page load.
        
        Queries cerberus:history:<token> and replays all prior messages to restore
        the session to its pre-refresh state. Also restores terminal border state
        (BUSY/ACTIVE) from the last state-change event.
        """
        client_token = str(self.cerberus_client_token or "").strip()
        if not client_token:
            return
        
        try:
            manager = await get_redis_manager()
            
            # Retrieve all history entries (start=0, end=-1 gets everything)
            history_entries = await manager.get_history(client_token)
            
            if not history_entries:
                # No prior history - start fresh
                return
            
            # Parse history entries and reconstruct session logs
            state_change_events = []  # Track state changes for terminal border restoration
            
            for entry in history_entries:
                # Entries are formatted as "channel: message"
                # Parse them back to reconstruct logs
                try:
                    if entry.startswith("{") and entry.endswith("}"):
                        # This is a JSON state-change event
                        payload = json.loads(entry)
                        if payload.get("type") == "state_change":
                            state_change_events.append(payload)
                            # Apply state change to dashboard state
                            await self._apply_hydrated_state_change(payload)
                        elif payload.get("type") == "runtime_log":
                            await self._append_hydrated_log(
                                origin_id=str(
                                    payload.get("origin_id")
                                    or payload.get("session_id")
                                    or payload.get("terminal_id")
                                    or ""
                                ),
                                channel=str(payload.get("channel", "stdout") or "stdout"),
                                message=str(payload.get("message", "") or ""),
                            )
                        else:
                            # Generic JSON payload fallback
                            await self._append_hydrated_log(
                                origin_id=str(
                                    payload.get("origin_id")
                                    or payload.get("session_id")
                                    or payload.get("terminal_id")
                                    or ""
                                ),
                                channel=str(payload.get("channel", "stdout") or "stdout"),
                                message=str(payload.get("message", "") or entry),
                            )
                    else:
                        # Regular message entry: "channel: message"
                        if ": " in entry:
                            parts = entry.split(": ", 1)
                            channel = parts[0].strip()
                            message = parts[1] if len(parts) > 1 else ""
                        else:
                            channel = "stdout"
                            message = entry
                        
                        await self._append_hydrated_log(origin_id="", channel=channel, message=message)
                except json.JSONDecodeError:
                    # Not JSON - treat as regular message
                    if ": " in entry:
                        parts = entry.split(": ", 1)
                        channel = parts[0].strip()
                        message = parts[1] if len(parts) > 1 else ""
                    else:
                        channel = "stdout"
                        message = entry
                    
                    await self._append_hydrated_log(origin_id="", channel=channel, message=message)
                except Exception as e:
                    import logging
                    logging.warning(f"Failed to parse history entry: {e}")
            
            # Restore terminal border state from last state-change event
            if state_change_events:
                last_state = state_change_events[-1]
                async with self:
                    self._restore_state_from_last_change(last_state)
            
            import logging
            logging.info(f"✅ Hydrated {len(history_entries)} history entries for token {client_token[:8]}...")
            
        except Exception as e:
            import logging
            logging.error(f"Failed to hydrate from Redis: {e}")

    async def _apply_hydrated_state_change(self, payload: dict[str, Any]) -> None:
        """Apply a state-change event from history to restore session state."""
        try:
            index = payload.get("index", 0)
            state = payload.get("state", "ACTIVE")
            metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
            origin_id = str(
                payload.get("origin_id")
                or payload.get("session_id")
                or payload.get("terminal_id")
                or metadata.get("session_id")
                or metadata.get("origin_id")
                or ""
            )
            
            async with self:
                resolved_index = self._index_for_origin_id(
                    origin_id,
                    fallback_index=index if isinstance(index, int) else None,
                )
                if resolved_index is None:
                    return
                
                session = self._session_copy(resolved_index)
                session.is_busy = state == "BUSY"
                session.status = "running" if state == "BUSY" else "ready"
                if "status_line" in payload:
                    session.status_line = payload.get("status_line", "")
                if "active_tool" in payload:
                    session.active_tool_name = payload.get("active_tool", "")
                if "status_line" in metadata:
                    session.status_line = str(metadata.get("status_line", "") or session.status_line)
                if "active_tool" in metadata:
                    session.active_tool_name = str(metadata.get("active_tool", "") or session.active_tool_name)
                self._store_session(resolved_index, session)
        except Exception as e:
            import logging
            logging.warning(f"Failed to apply hydrated state change: {e}")

    def _restore_state_from_last_change(self, last_state: dict[str, Any]) -> None:
        """Restore terminal border state (BUSY/ACTIVE) from last state-change event."""
        try:
            index = last_state.get("index", 0)
            state = last_state.get("state", "ACTIVE")
            metadata = last_state.get("metadata", {})
            origin_id = str(
                last_state.get("origin_id")
                or last_state.get("session_id")
                or last_state.get("terminal_id")
                or (metadata.get("session_id") if isinstance(metadata, dict) else "")
                or ""
            )
            
            resolved_index = self._index_for_origin_id(
                origin_id,
                fallback_index=index if isinstance(index, int) else None,
            )
            if resolved_index is None:
                return
            
            session = self._session_copy(resolved_index)
            session.is_busy = state == "BUSY"
            session.status = "running" if state == "BUSY" else "ready"
            
            # Restore metadata if available
            if metadata:
                if "status" in metadata:
                    session.status = metadata["status"]
                if "status_line" in metadata:
                    session.status_line = metadata["status_line"]
                if "active_tool" in metadata:
                    session.active_tool_name = metadata["active_tool"]
            
            self._store_session(resolved_index, session)
        except Exception as e:
            import logging
            logging.warning(f"Failed to restore state from last change: {e}")

    async def _subscribe_to_redis_live(self) -> None:
        """Subscribe to Redis Pub/Sub channel and stream live updates to UI.
        
        Continuously listens to cerberus:live:<token> channel and merges new messages
        with existing session logs. Handles both regular messages and state-change events.
        """
        client_token = str(self.cerberus_client_token or "").strip()
        if not client_token:
            return
        
        try:
            manager = await get_redis_manager()
            
            import logging
            logging.info(f"🔵 Starting Redis Pub/Sub subscription for token {client_token[:8]}...")
            
            # Subscribe to live channel
            async with manager.subscribe(client_token) as pubsub:
                async for message in pubsub.listen():
                    if message is None:
                        continue
                    
                    if message.get("type") != "message":
                        continue
                    
                    data = message.get("data", "")
                    if not data:
                        continue
                    
                    # Parse message: could be JSON (state change) or text (regular message)
                    try:
                        if isinstance(data, str) and data.strip().startswith("{"):
                            payload = json.loads(data)
                            if payload.get("type") == "state_change":
                                # Handle state change
                                await self._apply_hydrated_state_change(payload)
                                continue
                            if payload.get("type") == "runtime_log":
                                await self._append_hydrated_log(
                                    origin_id=str(
                                        payload.get("origin_id")
                                        or payload.get("session_id")
                                        or payload.get("terminal_id")
                                        or ""
                                    ),
                                    channel=str(payload.get("channel", "stdout") or "stdout"),
                                    message=str(payload.get("message", "") or ""),
                                )
                                continue
                    except (json.JSONDecodeError, ValueError):
                        pass
                    
                    # Regular message: parse channel and content
                    message_str = str(data)
                    if ": " in message_str:
                        parts = message_str.split(": ", 1)
                        channel = parts[0].strip()
                        content = parts[1] if len(parts) > 1 else ""
                    else:
                        channel = "stdout"
                        content = message_str
                    
                    # Add to session logs
                    if content.strip():
                        await self._append_hydrated_log(origin_id="", channel=channel, message=content)
        
        except asyncio.CancelledError:
            import logging
            logging.info(f"🔴 Redis subscription cancelled for token {client_token[:8]}...")
        except Exception as e:
            import logging
            logging.error(f"Failed to subscribe to Redis live channel: {e}")

    async def _dispatch_verified_action(
        self,
        index: int,
        *,
        action: dict[str, Any],
        session: AgentSession,
        report: PolicyReport,
        manual_approval_granted: bool = False,
    ) -> None:
        async def _log_emitter(event: dict[str, Any]) -> None:
            # Inject client token into event for Redis history/pub-sub tracking
            event["cerberus_client_token"] = str(self.cerberus_client_token or "").strip()
            await self._handle_runtime_event(index, event)

        execution_result = await execute_headless_action(
            action,
            workspace_dir=self._workspace_dir(),
            project_id=self._project_id_for_session(session),
            session_id=self._orchestration_session_id_for_session(session),
            log_emitter=_log_emitter,
        )

        async with self:
            current_session = self._session_copy(index)
            if current_session.termination_requested:
                current_session.termination_requested = False
                current_session.is_busy = False
                current_session.status = "stopped"
                current_session.approval_required = False
                current_session.pending_action = None
                current_session.pending_approval_source = ""
                current_session.pending_tool_name = ""
                current_session.pending_raw_arguments = ""
                current_session.pending_repaired_arguments = ""
                current_session.pending_message = ""
                current_session.pending_risk_tier = 0
                current_session.active_tool_name = ""
                current_session.status_line = "Action terminated by user."
                if not current_session.logs or current_session.logs[-1]["content"] != "⚠️ Action Terminated by User":
                    current_session.logs = [
                        *current_session.logs,
                        _log_entry("System", "⚠️ Action Terminated by User"),
                    ][-MAX_LOG_ENTRIES:]
                self._store_session(index, current_session)
                self._refresh_system_health()
                return

            if not execution_result.ok:
                if self._is_runtime_pending_approval_payload(execution_result.output):
                    pending_action = self._build_runtime_pending_action(
                        action=action,
                        output=execution_result.output,
                    )
                    self._set_pending_action(index, pending_action=pending_action, approval_required=True)
                    client_token = str(self.cerberus_client_token or "").strip()
                    if client_token:
                        asyncio.create_task(
                            broadcast_state_change(
                                client_token,
                                "AWAITING_APPROVAL",
                                index=index,
                                metadata={
                                    "session_id": current_session.session_id,
                                    "tool_name": str(pending_action.get("tool_name", "") or ""),
                                    "arguments": pending_action.get("arguments", {}),
                                    "risk_tier": int(pending_action.get("risk_tier", 4) or 4),
                                    "approval_source": str(pending_action.get("approval_source", "") or ""),
                                },
                            )
                        )
                    self._append_log(
                        index,
                        "Audit",
                        f"Runtime approval required for {pending_action.get('tool_name', action.get('tool_name', 'tool'))} (Tier 4).",
                    )
                    self._apply_report_state(
                        index,
                        report,
                        is_busy=False,
                        status_line="Runtime approval required for repaired tool arguments.",
                        manual_approval_granted=manual_approval_granted,
                        status="review",
                    )
                    self._refresh_system_health()
                    return

                self._append_log(
                    index,
                    "Agent",
                    f"Execution failed: {execution_result.error or 'Unknown execution error.'}",
                )
                self._apply_report_state(
                    index,
                    report,
                    is_busy=False,
                    status_line="Execution failed.",
                    manual_approval_granted=manual_approval_granted,
                    status="error",
                )
                self._refresh_system_health()
                return

            if execution_result.tool_name == PROMPT_DISPATCH_TOOL:
                status_line = "LLM response received."
                try:
                    self._finalize_prompt_dispatch_output(index, execution_result.output)
                except Exception as exc:
                    # Never let prompt formatting failures keep the command bar locked.
                    status_line = "LLM response received (formatter fallback)."
                    self._append_log(index, "Audit", f"⚠ Prompt finalize fallback engaged: {exc}")
                    fallback_text = ""
                    if isinstance(execution_result.output, str):
                        fallback_text = _sanitize_prompt_response_text(execution_result.output)
                    if fallback_text:
                        self._upsert_prompt_response_log(index, fallback_text)
                finally:
                    self._apply_report_state(
                        index,
                        report,
                        is_busy=False,
                        status_line=status_line,
                        manual_approval_granted=manual_approval_granted,
                    )
                    self._refresh_system_health()
                return

            arguments = execution_result.arguments or action.get("arguments", {})
            details = json.dumps(arguments, sort_keys=True, default=str) if arguments else "{}"
            environment_id = extract_execution_environment_id(execution_result.output)
            if environment_id:
                current_session.execution_environment_id = environment_id
                self._store_session(index, current_session)
            self._append_log(
                index,
                "Agent",
                f"Executed {execution_result.tool_name or action.get('tool_name', 'action')} in {execution_result.workspace_root or session.workspace}.",
            )
            self._append_log(index, "System", f"Arguments: {details}")
            if execution_result.tool_name == "execute_cli_command" and isinstance(execution_result.output, dict):
                telemetry = execution_result.output.get("telemetry", {})
                if isinstance(telemetry, dict):
                    exit_code = telemetry.get("exit_code", "?")
                    duration_ms = telemetry.get("duration_ms", "?")
                    self._append_log(index, "System", f"Command stream closed with exit code {exit_code} after {duration_ms} ms.")
                else:
                    self._append_log(index, "System", "Command stream closed.")
            else:
                badge_text = environment_badge_text(execution_result.output)
                if badge_text == "" and environment_id == "Kali-Docker":
                    badge_text = KALI_DOCKER_ENVIRONMENT_BADGE
                self._append_log(
                    index,
                    "Tool",
                    self._format_execution_output(execution_result.output),
                    environment_label=badge_text,
                )
            self._apply_report_state(
                index,
                report,
                is_busy=False,
                status_line=f"{execution_result.tool_name or action.get('tool_name', 'Action')} completed.",
                manual_approval_granted=manual_approval_granted,
            )
            self._refresh_system_health()

    async def _run_session_command(self, index: int, command: str, action: dict[str, Any]) -> None:
        async with self:
            if index >= len(self.agent_sessions):
                return
            session = self._session_copy(index)

        system_state = self._system_state_for_session(session)
        action["chat_history"] = list(session.policy_history)
        action["system_state"] = system_state
        report = self._policy_engine_for_session(session).verify(action)

        async with self:
            self._append_policy_history(index, action=action, report=report, system_state=system_state)
            if self._is_high_risk_report(report):
                self._append_log(index, "Audit", self._format_policy_message(report))
            self._refresh_system_health()

            if report.manual_approval_required:
                self._set_pending_action(index, pending_action=action, approval_required=True)
                self._append_log(index, "System", "Manual approval required before dispatch.")
                self._apply_report_state(
                    index,
                    report,
                    is_busy=False,
                    status_line="Tier 4 review pending manual approval.",
                )
                return

            self._set_pending_action(index, pending_action=None, approval_required=False)

            if report.blocked:
                blocked_message = report.primary_finding.message if report.primary_finding is not None else "Action blocked by policy engine."
                self._apply_report_state(
                    index,
                    report,
                    is_busy=False,
                    status_line=blocked_message,
                )
                return

            self._apply_report_state(
                index,
                report,
                is_busy=True,
                status_line="Policy cleared. Dispatching headless action.",
            )

        try:
            await asyncio.wait_for(
                self._dispatch_verified_action(index, action=action, session=session, report=report),
                timeout=HEADLESS_ACTION_TIMEOUT_S,
            )
        except asyncio.TimeoutError:
            async with self:
                self._append_log(index, "System", "⚠ Headless action timed out after 600 seconds.")
                self._apply_report_state(
                    index,
                    report,
                    is_busy=False,
                    status="error",
                    status_line="Execution timed out.",
                )
                self._refresh_system_health()
        except Exception as exc:
            async with self:
                self._append_log(index, "System", f"⚠ Unexpected runtime failure: {exc}")
                self._apply_report_state(
                    index,
                    report,
                    is_busy=False,
                    status="error",
                    status_line="Execution failed unexpectedly. Prompt unlocked.",
                )
                self._refresh_system_health()

    async def _start_session_command(self, session_id: str, command: str | None = None) -> None:
        slash_command_text = ""
        async with self:
            index = self._index_for_session_id(session_id)
            if index is None:
                return

            session = self._session_copy(index)
            command_text = (command if command is not None else session.command_input).strip()
            if not command_text or session.is_busy or session.status == "error":
                return

            if self._apply_agent_switch_command(index, command_text):
                self._persist_dashboard_snapshot()
                return

            if command_text.startswith("/"):
                slash_command_text = command_text
                session.command_input = ""
                self._store_session(index, session)
                self._refresh_system_health()

        if slash_command_text:
            await self._dispatch_slash_command(index, slash_command_text)
            return

        async with self:
            if index >= len(self.agent_sessions):
                return

            session = self._session_copy(index)
            command_text = (command if command is not None else session.command_input).strip()
            if not command_text or session.is_busy or session.status == "error":
                return

            action = self._parse_prompt_to_action(command_text)

            if str(action.get("tool_name", "")) == PROMPT_DISPATCH_TOOL:
                session_after = self._session_copy(index)
                action_arguments = action.get("arguments")
                if not isinstance(action_arguments, dict):
                    action_arguments = {}
                prompt_agent = self._normalize_prompt_agent(session_after.prompt_agent or "one_tool")
                if prompt_agent:
                    action_arguments["agent"] = prompt_agent
                action["arguments"] = action_arguments

            self._prime_session(index, command_text, str(action.get("tool_name", "") or ""))
            self._refresh_system_health()

        await self._run_session_command(index, command_text, action)

    @rx.event(background=True)
    async def stop_session(self, session_id: str) -> None:
        async with self:
            index = self._index_for_session_id(session_id)
            if index is None:
                return

            if index >= len(self.agent_sessions):
                return

            session = self._session_copy(index)
            if not session.is_busy:
                return

            session.is_busy = False
            session.status = "stopping"
            session.termination_requested = True
            session.status_line = "Termination requested. Waiting for process shutdown."
            session.logs = [
                *session.logs,
                _log_entry("Audit", "Emergency stop requested by operator."),
                _log_entry("System", "⚠️ Action Terminated by User"),
            ][-MAX_LOG_ENTRIES:]
            self._store_session(index, session)
            self._refresh_system_health()

        result = await terminate_action(self._orchestration_session_id_for_session(session))

        async with self:
            if index >= len(self.agent_sessions):
                return

            session = self._session_copy(index)
            if not session.termination_requested:
                return

            found = int(result.get("found", 0) or 0)
            killed = int(result.get("killed", 0) or 0)

            if found > 0:
                session.status = "stopped"
                session.status_line = "Action terminated by user."
                session.logs = [
                    *session.logs,
                    _log_entry("Audit", f"Stop signal sent to {found} registered process(es); kill fallback applied to {killed}."),
                ][-MAX_LOG_ENTRIES:]
            else:
                session.termination_requested = False
                session.status = "ready"
                session.status_line = "No active subprocess found for termination."
                session.logs = [
                    *session.logs,
                    _log_entry("Audit", "Emergency stop requested, but no active subprocess was registered."),
                ][-MAX_LOG_ENTRIES:]

            self._store_session(index, session)
            self._refresh_system_health()

    @rx.event(background=True)
    async def process_session_command(self, session_id: str) -> None:
        await self._start_session_command(session_id)

    @rx.event
    def clear_error(self, session_id: str) -> None:
        index = self._index_for_session_id(session_id)
        if index is None:
            return
        session = self._session_copy(index)
        if session.status not in {"busy", "error"}:
            return
        session.is_busy = False
        session.status = "ready"
        session.status_line = "Ready. Error cleared by operator."
        session.logs = [
            *session.logs,
            _log_entry("System", "⚠ Error cleared. Terminal reset."),
        ][-MAX_LOG_ENTRIES:]
        self._store_session(index, session)
        self._refresh_system_health()

    @rx.event(background=True)
    async def submit_session_command(self, session_id: str, form_data: dict[str, str]) -> None:
        await self._start_session_command(session_id, str(form_data.get("command_input", "") or ""))

    @rx.event(background=True)
    async def approve_pending_action(self, session_id: str) -> None:
        async with self:
            index = self._index_for_session_id(session_id)
            if index is None:
                return

            if index >= len(self.agent_sessions):
                return

            session = self._session_copy(index)
            pending_action = session.pending_action
            if session.is_busy or not isinstance(pending_action, dict):
                return

            runtime_approval = str(pending_action.get("approval_source", "") or "").strip() == "runtime_tool_validation"

            session.is_busy = True
            session.status = "verifying"
            session.approval_required = False
            session.active_tool_name = str(pending_action.get("tool_name", "") or "")
            session.status_line = (
                "Runtime approval granted. Dispatching repaired tool arguments."
                if runtime_approval
                else "Manual approval granted. Re-verifying before dispatch."
            )
            session.logs = [
                *session.logs,
                _log_entry(
                    "Audit",
                    "Runtime Tier-4 approval granted. Executing with repaired arguments."
                    if runtime_approval
                    else "Manual approval granted. Re-verifying headless action.",
                ),
            ][-MAX_LOG_ENTRIES:]
            self._store_session(index, session)
            self._refresh_system_health()
            
            # Broadcast state change to Redis pub/sub
            client_token = str(self.cerberus_client_token or "").strip()
            if client_token:
                asyncio.create_task(
                    broadcast_state_change(
                        client_token,
                        "BUSY",
                        index=index,
                        metadata={
                            "session_id": session.session_id,
                            "status": "verifying",
                            "status_line": session.status_line,
                            "active_tool": session.active_tool_name,
                        },
                    )
                )

        approved_action = dict(pending_action)
        if str(pending_action.get("approval_source", "") or "").strip() == "runtime_tool_validation":
            repaired_arguments = pending_action.get("repaired_arguments")
            arguments = repaired_arguments if isinstance(repaired_arguments, dict) and repaired_arguments else pending_action.get("arguments", {})
            approved_action = {
                "tool_name": str(pending_action.get("tool_name", "") or ""),
                "arguments": arguments if isinstance(arguments, dict) else {},
                "manual_approval_granted": True,
                "approval_decision": "APPROVE",
                "approval_source": "runtime_tool_validation",
                "runtime_pending": pending_action,
            }
        approved_action["manual_approval_granted"] = True
        approved_action["chat_history"] = list(session.policy_history)
        approved_action["system_state"] = self._system_state_for_session(session)
        report = self._policy_engine_for_session(session).verify(approved_action)

        async with self:
            self._append_policy_history(
                index,
                action=approved_action,
                report=report,
                system_state=self._system_state_for_session(session),
            )
            self._set_pending_action(index, pending_action=None, approval_required=False)
            if self._is_high_risk_report(report):
                self._append_log(index, "Audit", self._format_policy_message(report))

            if report.blocked:
                self._apply_report_state(
                    index,
                    report,
                    is_busy=False,
                    status_line="Approval failed.",
                )
                self._refresh_system_health()
                return

            self._apply_report_state(
                index,
                report,
                is_busy=True,
                status_line="Manual approval granted. Dispatching headless action.",
                manual_approval_granted=True,
            )
            self._refresh_system_health()

        await self._dispatch_verified_action(
            index,
            action=approved_action,
            session=session,
            report=report,
            manual_approval_granted=True,
        )

    @rx.event(background=True)
    async def deny_pending_action(self, session_id: str) -> None:
        async with self:
            index = self._index_for_session_id(session_id)
            if index is None:
                return

            if index >= len(self.agent_sessions):
                return

            session = self._session_copy(index)
            if session.is_busy or not isinstance(session.pending_action, dict):
                return

            runtime_approval = str(session.pending_action.get("approval_source", "") or "").strip() == "runtime_tool_validation"
            denied_tool = str(session.pending_action.get("tool_name", "") or "")

            if runtime_approval:
                rejection_payload = {
                    "ok": False,
                    "status": "REJECTED_BY_OPERATOR",
                    "error": "tool_execution_rejected_by_operator",
                    "tool": denied_tool,
                    "message": APPROVAL_REJECTION_MESSAGE,
                    "raw_arguments": session.pending_action.get("raw_arguments"),
                    "repaired_arguments": session.pending_action.get("repaired_arguments"),
                    "risk_tier": session.pending_action.get("risk_tier", 4),
                    "approval_source": "runtime_tool_validation",
                }
                session.logs = [
                    *session.logs,
                    _log_entry("Audit", f"Runtime approval denied for {denied_tool or 'tool'}; rejection payload returned to orchestration context."),
                    _log_entry("Tool", self._format_execution_output(rejection_payload)),
                ][-MAX_LOG_ENTRIES:]

            session.pending_action = None
            session.approval_required = False
            session.pending_approval_source = ""
            session.pending_tool_name = ""
            session.pending_raw_arguments = ""
            session.pending_repaired_arguments = ""
            session.pending_message = ""
            session.pending_risk_tier = 0
            session.is_busy = False
            session.status = "blocked"
            session.status_line = "Operator denied action. Strategic reassessment required."
            session.tier_status["tier_4"] = "blocked"
            if not runtime_approval:
                session.logs = [
                    *session.logs,
                    _log_entry("Audit", "Manual approval denied. Action was not dispatched. Strategic reassessment required."),
                ][-MAX_LOG_ENTRIES:]
            self._store_session(index, session)
            self._refresh_system_health()


def neon_panel(*children: rx.Component, class_name: str = "", **props: Any) -> rx.Component:
    panel_class_name = "neon-panel" if not class_name else f"neon-panel {class_name}"
    panel_props = {
        "border_radius": "14px",
        "padding": "14px",
        "width": "100%",
        **props,
    }
    return rx.box(
        *children,
        class_name=panel_class_name,
        **panel_props,
    )


def audit_status_chip(status: Any) -> rx.Component:
    color = rx.cond(
        status == "ready",
        NEON_GREEN,
        rx.cond(
            status == "busy",
            NEON_CYAN,
            rx.cond(
                status == "verifying",
                AUDIT_VERIFY,
                rx.cond(
                    status == "approved",
                    NEON_CYAN,
                    rx.cond(
                        status == "review",
                        "#FFD166",
                        rx.cond(
                            status == "blocked",
                            "#FF6B6B",
                            rx.cond(
                                status == "error",
                                "#FF6B6B",
                                rx.cond(
                                    status == "stopped",
                                    MUTED_TEXT,
                                    rx.cond(
                                        status == "warning",
                                        "#D9F99D",
                                        rx.cond(
                                            status == "pending",
                                            "#D9F99D",
                                            rx.cond(status == "cleared", NEON_CYAN, MUTED_TEXT),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        ),
    )
    border = rx.cond(
        status == "ready",
        f"1px solid {NEON_GREEN}",
        rx.cond(
            status == "busy",
            f"1px solid {NEON_CYAN}",
            rx.cond(
                status == "verifying",
                f"1px solid {AUDIT_VERIFY}",
                rx.cond(
                    status == "approved",
                    f"1px solid {NEON_CYAN}",
                    rx.cond(
                        status == "review",
                        "1px solid #FFD166",
                        rx.cond(
                            status == "blocked",
                            "1px solid #FF6B6B",
                            rx.cond(
                                status == "error",
                                "1px solid #FF6B6B",
                                rx.cond(
                                    status == "stopped",
                                    "1px solid #4B5563",
                                    rx.cond(
                                        status == "warning",
                                        "1px solid #8AA800",
                                        rx.cond(
                                            status == "pending",
                                            "1px solid #8AA800",
                                            rx.cond(status == "cleared", f"1px solid {NEON_CYAN}", "1px solid #305030"),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        ),
    )
    background = rx.cond(
        status == "ready",
        "rgba(0, 255, 0, 0.12)",
        rx.cond(
            status == "busy",
            "rgba(0, 255, 255, 0.14)",
            rx.cond(
                status == "verifying",
                "rgba(34, 211, 238, 0.12)",
                rx.cond(
                    status == "approved",
                    "rgba(0, 255, 255, 0.16)",
                    rx.cond(
                        status == "review",
                        "rgba(255, 209, 102, 0.14)",
                        rx.cond(
                            status == "blocked",
                            "rgba(255, 107, 107, 0.14)",
                            rx.cond(
                                status == "error",
                                "rgba(255, 107, 107, 0.14)",
                                rx.cond(
                                    status == "stopped",
                                    "rgba(75, 85, 99, 0.18)",
                                    rx.cond(
                                        status == "warning",
                                        "rgba(202, 255, 112, 0.12)",
                                        rx.cond(
                                            status == "pending",
                                            "rgba(202, 255, 112, 0.12)",
                                            rx.cond(status == "cleared", "rgba(0, 255, 255, 0.12)", "rgba(8, 24, 8, 0.72)"),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        ),
    )

    return rx.box(
        rx.text(
            status,
            text_transform="uppercase",
            font_size="0.66rem",
            font_weight="700",
            letter_spacing="0.08em",
            color=color,
        ),
        border=border,
        background=background,
        border_radius="999px",
        padding="4px 8px",
    )


def audit_tier_tile(tier_code: str, tier_label: str, status: Any) -> rx.Component:
    accent = rx.cond(
        status == "cleared",
        AUDIT_CLEAR,
        rx.cond(
            status == "approved",
            AUDIT_CLEAR,
            rx.cond(
                status == "pending",
                AUDIT_VERIFY,
                rx.cond(
                    status == "review",
                    AUDIT_VERIFY,
                    rx.cond(
                        status == "blocked",
                        AUDIT_VIOLATION,
                        rx.cond(status == "warning", AUDIT_VIOLATION, AUDIT_PENDING),
                    ),
                ),
            ),
        ),
    )
    background = rx.cond(
        status == "cleared",
        "rgba(0, 255, 0, 0.12)",
        rx.cond(
            status == "approved",
            "rgba(0, 255, 0, 0.16)",
            rx.cond(
                status == "pending",
                "rgba(34, 211, 238, 0.12)",
                rx.cond(
                    status == "review",
                    "rgba(34, 211, 238, 0.14)",
                    rx.cond(
                        status == "blocked",
                        "rgba(255, 107, 107, 0.12)",
                        rx.cond(status == "warning", "rgba(255, 107, 107, 0.12)", "rgba(148, 163, 184, 0.10)"),
                    ),
                ),
            ),
        ),
    )
    summary = rx.cond(
        status == "cleared",
        "CLEARED",
        rx.cond(
            status == "approved",
            "CLEARED",
            rx.cond(
                status == "pending",
                "VERIFYING",
                rx.cond(
                    status == "review",
                    "VERIFYING",
                    rx.cond(
                        status == "blocked",
                        "VIOLATION",
                        rx.cond(status == "warning", "VIOLATION", "PENDING"),
                    ),
                ),
            ),
        ),
    )

    return rx.box(
        rx.hstack(
            rx.badge(
                tier_code,
                variant="solid",
                background=background,
                color=accent,
                border_width="1px",
                border_style="solid",
                border_color=accent,
            ),
            rx.spacer(),
            rx.text(summary, color=accent, font_size="0.66rem", font_weight="700", letter_spacing="0.08em"),
            width="100%",
            align="center",
        ),
        rx.text(tier_label, color=TEXT_PRIMARY, font_size="0.74rem", font_weight="700"),
        rx.text(status, color=MUTED_TEXT, font_size="0.66rem", letter_spacing="0.08em", text_transform="uppercase"),
        border_width="1px",
        border_style="solid",
        border_color=accent,
        background=background,
        border_radius="12px",
        padding="10px",
        min_height="84px",
        width="100%",
    )


def render_log_entry(entry: dict[str, str]) -> rx.Component:
    return rx.cond(
        entry["role"] == "Tool",
        rx.cond(
            AgentDashboardState.show_tool_logs,
            rx.box(
            rx.vstack(
                rx.hstack(
                    rx.text("Tool", color="#9ADADA", font_size="0.72rem", font_weight="700", letter_spacing="0.06em"),
                    rx.spacer(),
                    rx.text(entry["timestamp"], color="#6FAFAD", font_size="0.68rem"),
                    width="100%",
                    align="center",
                ),
                rx.text("Tool event recorded", color=TEXT_PRIMARY, font_size="0.84rem", width="100%"),
                rx.el.details(
                    rx.el.summary(
                        "View Raw",
                        style={
                            "cursor": "pointer",
                            "color": "#7CF7FF",
                            "fontSize": "0.72rem",
                            "fontWeight": "700",
                            "letterSpacing": "0.04em",
                        },
                    ),
                    rx.el.pre(
                        entry["content"],
                        style={
                            "marginTop": "8px",
                            "maxHeight": "220px",
                            "overflow": "auto",
                            "background": "rgba(0, 0, 0, 0.62)",
                            "border": "1px solid rgba(0, 255, 255, 0.22)",
                            "borderRadius": "10px",
                            "padding": "10px",
                            "color": "#C9F6F7",
                            "fontSize": "0.68rem",
                            "whiteSpace": "pre-wrap",
                        },
                    ),
                    style={"width": "100%"},
                ),
                spacing="3",
                align="stretch",
                width="100%",
            ),
            class_name="response-card",
            width="100%",
            background="linear-gradient(180deg, rgba(6, 14, 16, 0.95) 0%, rgba(4, 8, 12, 0.94) 100%)",
            border="1px solid rgba(124, 247, 255, 0.24)",
        ),
        rx.box(),  # hidden when show_tool_logs is False
        ),
        rx.cond(
        entry["role"] == "Assistant",
        rx.box(
            rx.vstack(
                rx.hstack(
                    rx.text("Assistant", color=NEON_CYAN, font_size="0.72rem", font_weight="700", letter_spacing="0.06em"),
                    rx.spacer(),
                    rx.text(entry["timestamp"], color="#6FAFAD", font_size="0.68rem"),
                    width="100%",
                    align="center",
                ),
                rx.markdown(
                    entry["content"],
                    class_name="response-markdown",
                    use_raw=False,
                    width="100%",
                ),
                spacing="3",
                align="stretch",
                width="100%",
            ),
            class_name="response-card",
            width="100%",
        ),
        rx.cond(
            entry["role"] == "User",
            rx.box(
                rx.vstack(
                    rx.hstack(
                        rx.text("User", color=NEON_GREEN, font_size="0.72rem", font_weight="700", letter_spacing="0.06em"),
                        rx.spacer(),
                        rx.text(entry["timestamp"], color="#74C874", font_size="0.68rem"),
                        width="100%",
                        align="center",
                    ),
                    rx.markdown(
                        entry["content"],
                        class_name="response-markdown",
                        use_raw=False,
                        width="100%",
                    ),
                    spacing="3",
                    align="stretch",
                    width="100%",
                ),
                class_name="user-card",
                width="100%",
            ),
            rx.box(
                rx.vstack(
                    rx.hstack(
                        rx.text(entry["role"], color=MUTED_TEXT, font_size="0.72rem", font_weight="700", letter_spacing="0.06em"),
                        rx.cond(
                            (entry.get("environment_label", "") != ""),
                            rx.badge(
                                entry.get("environment_label", ""),
                                variant="soft",
                                color_scheme="teal",
                                font_size="0.58rem",
                                border_radius="999px",
                                padding="0.15rem 0.5rem",
                            ),
                            rx.box(display="none"),
                        ),
                        rx.spacer(),
                        rx.text(entry["timestamp"], color="#5B7A70", font_size="0.68rem"),
                        width="100%",
                        align="center",
                    ),
                    rx.markdown(
                        entry["content"],
                        class_name="response-markdown",
                        use_raw=False,
                        width="100%",
                    ),
                    spacing="3",
                    align="stretch",
                    width="100%",
                ),
                class_name="response-card",
                width="100%",
                background="linear-gradient(180deg, rgba(9, 14, 12, 0.92) 0%, rgba(4, 8, 7, 0.9) 100%)",
                border="1px solid rgba(96, 130, 119, 0.28)",
            ),
        ),
        ),
    )


def terminal_window(session: AgentSession) -> rx.Component:
    is_focus_terminal = session.is_busy | (session.session_id == AgentDashboardState.active_session_id)

    return rx.box(
        rx.scroll_area(
            rx.vstack(
                rx.foreach(session.logs, render_log_entry),
                width="100%",
                align="stretch",
                spacing="4",
                min_height="100%",
            ),
            type="always",
            scrollbars="vertical",
            class_name="terminal-flicker",
            height="100%",
            width="100%",
            background="transparent",
            border_radius="0",
            padding="24px 24px 28px 24px",
        ),
        rx.cond(
            session.approval_required & (session.pending_approval_source == "runtime_tool_validation"),
            rx.box(
                rx.vstack(
                    rx.text("PENDING APPROVAL", color="#FF6B6B", font_size="0.9rem", font_weight="700", letter_spacing="0.09em"),
                    rx.hstack(
                        rx.text("Tool:", color=TEXT_PRIMARY, font_size="0.78rem", font_weight="700"),
                        rx.text(
                            rx.cond(session.pending_tool_name == "", "unknown", session.pending_tool_name),
                            color=TEXT_PRIMARY,
                            font_size="0.78rem",
                        ),
                        width="100%",
                        align="center",
                    ),
                    rx.text(
                        rx.cond(session.pending_message == "", "Repaired tool arguments require operator approval.", session.pending_message),
                        color="#FFD166",
                        font_size="0.74rem",
                    ),
                    rx.text(
                        "Raw Arguments",
                        color=MUTED_TEXT,
                        font_size="0.67rem",
                        text_transform="uppercase",
                        letter_spacing="0.08em",
                    ),
                    rx.el.pre(
                        session.pending_raw_arguments,
                        width="100%",
                        max_height="110px",
                        overflow="auto",
                        background="rgba(0, 0, 0, 0.8)",
                        border="1px solid rgba(255, 107, 107, 0.35)",
                        border_radius="10px",
                        padding="10px",
                        color="#FFC9C9",
                        font_size="0.66rem",
                        white_space="pre-wrap",
                    ),
                    rx.text(
                        "Repaired Arguments",
                        color=MUTED_TEXT,
                        font_size="0.67rem",
                        text_transform="uppercase",
                        letter_spacing="0.08em",
                    ),
                    rx.el.pre(
                        session.pending_repaired_arguments,
                        width="100%",
                        max_height="110px",
                        overflow="auto",
                        background="rgba(0, 0, 0, 0.8)",
                        border="1px solid rgba(0, 255, 255, 0.35)",
                        border_radius="10px",
                        padding="10px",
                        color="#BBFFFF",
                        font_size="0.66rem",
                        white_space="pre-wrap",
                    ),
                    rx.hstack(
                        rx.button(
                            "Reject",
                            on_click=AgentDashboardState.deny_pending_action(session.session_id),
                            custom_attrs={"data-approval-reject": session.session_id},
                            background="rgba(255, 107, 107, 0.12)",
                            color="#FF9B9B",
                            border="1px solid rgba(255, 107, 107, 0.65)",
                            width="100%",
                            _hover={"background": "rgba(255, 107, 107, 0.2)"},
                        ),
                        rx.button(
                            "Approve",
                            on_click=AgentDashboardState.approve_pending_action(session.session_id),
                            custom_attrs={"data-approval-approve": session.session_id},
                            background="rgba(0, 255, 255, 0.14)",
                            color=NEON_CYAN,
                            border=f"1px solid {NEON_CYAN}",
                            width="100%",
                            _hover={"background": "rgba(0, 255, 255, 0.24)"},
                        ),
                        width="100%",
                        spacing="3",
                    ),
                    spacing="2",
                    width="100%",
                    align="stretch",
                ),
                position="absolute",
                inset="14px",
                z_index="4",
                custom_attrs={"data-terminal-approval-panel": session.session_id},
                border="1px solid rgba(255, 107, 107, 0.7)",
                border_radius="14px",
                background="linear-gradient(180deg, rgba(35, 6, 6, 0.94) 0%, rgba(14, 4, 4, 0.95) 100%)",
                box_shadow="0 0 28px rgba(255, 107, 107, 0.35)",
                padding="12px",
            ),
            rx.box(display="none"),
        ),
        background="linear-gradient(180deg, rgba(4, 12, 10, 0.96) 0%, rgba(1, 5, 5, 0.96) 100%)",
        width="100%",
        height="100%",
        min_height="0",
        border_radius="18px",
        border=rx.cond(
            session.status == "error",
            "1px solid rgba(255, 107, 107, 0.75)",
            rx.cond(
                session.is_busy,
                "1px solid rgba(0, 255, 255, 0.55)",
                rx.cond(
                    session.session_id == AgentDashboardState.active_session_id,
                    "1px solid rgba(0, 255, 0, 0.55)",
                    "1px solid rgba(0, 255, 0, 0.20)",
                ),
            ),
        ),
        class_name=rx.cond(
            session.status == "error",
            "terminal-error",
            rx.cond(session.is_busy, "terminal-busy", ""),
        ),
        opacity=rx.cond(is_focus_terminal, "1", "0.46"),
        filter=rx.cond(is_focus_terminal, "none", "saturate(0.6)"),
        position="relative",
        overflow="hidden",
        transition="opacity 180ms ease, filter 180ms ease, border-color 180ms ease",
        custom_attrs={
            "data-session-id": session.session_id,
            "data-session-state": rx.cond(session.is_busy, "busy", "active"),
        },
    )


def approval_modal(session: AgentSession) -> rx.Component:
    return rx.cond(
        session.approval_required,
        rx.box(
            rx.box(
                rx.vstack(
                    rx.hstack(
                        rx.vstack(
                            rx.text(
                                "Approval Required",
                                color="#FF9B9B",
                                font_size="1.1rem",
                                font_weight="700",
                                letter_spacing="0.08em",
                                text_transform="uppercase",
                            ),
                            rx.text(
                                "A Tier-4 tool requested operator approval before execution.",
                                color=MUTED_TEXT,
                                font_size="0.78rem",
                            ),
                            spacing="1",
                            align="start",
                        ),
                        rx.spacer(),
                        rx.text(
                            f"Tier {session.pending_risk_tier}",
                            color=NEON_CYAN,
                            font_size="0.72rem",
                            border="1px solid rgba(0, 255, 255, 0.32)",
                            border_radius="999px",
                            padding="4px 10px",
                            background="rgba(0, 24, 24, 0.7)",
                        ),
                        width="100%",
                        align="start",
                    ),
                    rx.hstack(
                        rx.text("Agent", color=MUTED_TEXT, font_size="0.7rem", text_transform="uppercase"),
                        rx.spacer(),
                        rx.text(session.session_id, color=TEXT_PRIMARY, font_size="0.8rem", font_weight="700"),
                        width="100%",
                    ),
                    rx.hstack(
                        rx.text("Tool", color=MUTED_TEXT, font_size="0.7rem", text_transform="uppercase"),
                        rx.spacer(),
                        rx.text(session.pending_tool_name, color=TEXT_PRIMARY, font_size="0.8rem", font_weight="700"),
                        width="100%",
                    ),
                    rx.text(session.pending_message, color="#FFD166", font_size="0.76rem", width="100%"),
                    rx.text("Arguments", color=MUTED_TEXT, font_size="0.68rem", letter_spacing="0.08em", text_transform="uppercase"),
                    rx.el.pre(
                        session.pending_repaired_arguments,
                        custom_attrs={"data-approval-arguments": session.session_id},
                        width="100%",
                        max_height="180px",
                        overflow="auto",
                        background="rgba(0, 0, 0, 0.82)",
                        border="1px solid rgba(0, 255, 255, 0.25)",
                        border_radius="12px",
                        padding="12px",
                        color="#BBFFFF",
                        font_size="0.68rem",
                        white_space="pre-wrap",
                    ),
                    rx.hstack(
                        rx.button(
                            "APPROVE",
                            on_click=AgentDashboardState.approve_pending_action(session.session_id),
                            custom_attrs={"data-approval-modal-approve": session.session_id},
                            background="rgba(0, 255, 255, 0.14)",
                            color=NEON_CYAN,
                            border=f"1px solid {NEON_CYAN}",
                            min_width="10rem",
                            _hover={"background": "rgba(0, 255, 255, 0.22)"},
                        ),
                        rx.button(
                            "REJECT",
                            on_click=AgentDashboardState.deny_pending_action(session.session_id),
                            custom_attrs={"data-approval-modal-reject": session.session_id},
                            background="rgba(255, 107, 107, 0.12)",
                            color="#FF9B9B",
                            border="1px solid rgba(255, 107, 107, 0.62)",
                            min_width="10rem",
                            _hover={"background": "rgba(255, 107, 107, 0.2)"},
                        ),
                        width="100%",
                        justify="end",
                        spacing="3",
                    ),
                    spacing="3",
                    align="stretch",
                    width="min(40rem, 92vw)",
                ),
                custom_attrs={"data-approval-modal": session.session_id},
                border="1px solid rgba(255, 107, 107, 0.68)",
                border_radius="18px",
                background="linear-gradient(180deg, rgba(22, 5, 5, 0.98) 0%, rgba(10, 2, 2, 0.98) 100%)",
                box_shadow="0 24px 80px rgba(0, 0, 0, 0.55)",
                padding="20px",
                width="min(40rem, 92vw)",
            ),
            position="fixed",
            inset="0",
            z_index="1500",
            display="flex",
            align_items="center",
            justify_content="center",
            background="rgba(0, 0, 0, 0.72)",
            backdrop_filter="blur(6px)",
        ),
        rx.box(display="none"),
    )


def session_selector_button(session: AgentSession) -> rx.Component:
    is_active = session.session_id == AgentDashboardState.active_session_id
    return rx.button(
        rx.vstack(
            rx.text(session.session_id, font_size="0.72rem", font_weight="700", color=TEXT_PRIMARY),
            rx.text(session.role, font_size="0.64rem", color=MUTED_TEXT),
            spacing="0",
            align="start",
        ),
        on_click=AgentDashboardState.set_active_session(session.session_id),
        background=rx.cond(is_active, "rgba(0, 255, 0, 0.14)", "rgba(0, 0, 0, 0.72)"),
        border=rx.cond(is_active, f"1px solid {NEON_GREEN}", "1px solid rgba(143, 216, 143, 0.22)"),
        color=TEXT_PRIMARY,
        min_width="132px",
        padding="10px 12px",
        border_radius="12px",
        _hover={"background": "rgba(0, 255, 0, 0.1)"},
    )


def system_stat(label: str, value: Any, detail: str) -> rx.Component:
    stat_key = str(label or "").strip().lower().replace(" ", "-")
    return neon_panel(
        rx.vstack(
            rx.text(
                label,
                color=MUTED_TEXT,
                font_size="0.7rem",
                font_weight="700",
                letter_spacing="0.08em",
                custom_attrs={"data-stat-label": stat_key},
            ),
            rx.text(
                value,
                color=NEON_GREEN,
                font_size="1.2rem",
                font_weight="700",
                custom_attrs={"data-stat-value": stat_key},
            ),
            rx.text(detail, color="#89B889", font_size="0.68rem"),
            spacing="1",
            align="start",
            width="100%",
        ),
        border_radius="12px",
        padding="12px",
        width="100%",
    )


def system_sidebar() -> rx.Component:
    def control_row(control_key: str, label: str, value: Any, on_click: Any) -> rx.Component:
        return rx.hstack(
            rx.text(label, color=MUTED_TEXT, font_size="0.72rem", letter_spacing="0.06em"),
            rx.spacer(),
            rx.badge(
                rx.cond(value, "ON", "OFF"),
                on_click=on_click,
                background=rx.cond(value, "rgba(0, 255, 0, 0.14)", "rgba(255, 107, 107, 0.14)"),
                color=rx.cond(value, NEON_GREEN, "#FF6B6B"),
                border=f"1px solid {NEON_GREEN}",
                cursor="pointer",
                padding_x="10px",
                padding_y="2px",
                _hover={
                    "background": rx.cond(value, "rgba(0, 255, 0, 0.22)", "rgba(255, 107, 107, 0.22)"),
                    "boxShadow": "0 0 0 1px rgba(0, 255, 255, 0.18)",
                },
                custom_attrs={"data-control-value": control_key, "data-control-toggle": control_key},
            ),
            width="100%",
            align="center",
            spacing="2",
            custom_attrs={"data-control-row": control_key},
        )
    
    def health_metric(label: str, value: rx.Var | str, unit: str = "", color_dynamic: rx.Var[str] | str = NEON_CYAN) -> rx.Component:
        """Display a system health metric (CPU, RAM, Network)."""
        return rx.hstack(
            rx.text(label, color=MUTED_TEXT, font_size="0.68rem", letter_spacing="0.06em", width="50px"),
            rx.spacer(),
            rx.hstack(
                rx.text(
                    value,
                    color=color_dynamic,
                    font_size="0.84rem",
                    font_weight="700",
                    font_family='"JetBrains Mono", monospace',
                ),
                rx.text(
                    unit,
                    color=color_dynamic,
                    font_size="0.84rem",
                    font_weight="700",
                    font_family='"JetBrains Mono", monospace',
                ) if unit else rx.text(""),
                   spacing="0",
            ),
            width="100%",
            align="center",
            spacing="2",
        )

    return neon_panel(
        rx.vstack(
            rx.text("INTEL DRAWER", color=NEON_GREEN, font_size="0.98rem", font_weight="700", letter_spacing="0.08em"),
            rx.text("Live runtime controls and metadata.", color=MUTED_TEXT, font_size="0.72rem"),
            # System Health Section
            rx.el.details(
                rx.el.summary(
                    "System Health",
                    style={
                        "cursor": "pointer",
                        "color": NEON_CYAN,
                        "fontSize": "0.76rem",
                        "fontWeight": "700",
                        "letterSpacing": "0.08em",
                        "textTransform": "uppercase",
                    },
                ),
                rx.vstack(
                    health_metric("CPU", AgentDashboardState.cpu_usage, "%"),
                    health_metric("RAM", AgentDashboardState.ram_usage, "%"),
                    health_metric("NET", AgentDashboardState.net_mbps, " Mb/s"),
                    rx.text(
                        f"Agents: {0}",  # Placeholder - will be dynamic
                        color=NEON_GREEN,
                        font_size="0.72rem",
                        font_weight="600",
                    ),
                    spacing="2",
                    width="100%",
                    align="stretch",
                    padding_top="8px",
                    padding_bottom="8px",
                    border_bottom="1px solid rgba(0, 255, 0, 0.12)",
                ),
                style={"width": "100%"},
                open=True,  # Keep open by default for visibility
            ),
            rx.cond(
                AgentDashboardState.intel_drawer_alert,
                neon_panel(
                    rx.vstack(
                        rx.text("HITL HALT ACTIVE", color="#FF6B6B", font_size="0.72rem", font_weight="700", letter_spacing="0.08em"),
                        rx.text("Tier-4 action paused pending operator decision.", color="#FFB4B4", font_size="0.68rem"),
                        spacing="1",
                        align="start",
                        width="100%",
                    ),
                    border="1px solid rgba(255, 107, 107, 0.7)",
                    background="rgba(46, 8, 8, 0.72)",
                    animation="intelAlertPulse 1.4s ease-in-out infinite",
                ),
                rx.box(display="none"),
            ),
            rx.el.details(
                rx.el.summary(
                    "Operational Controls",
                    style={
                        "cursor": "pointer",
                        "color": NEON_CYAN,
                        "fontSize": "0.76rem",
                        "fontWeight": "700",
                        "letterSpacing": "0.08em",
                        "textTransform": "uppercase",
                    },
                ),
                rx.vstack(
                    control_row("verbose_logs", "Verbose Logs", AgentDashboardState.verbose_logs, AgentDashboardState.toggle_verbose_logs),
                    control_row("parallel_execution", "Parallel Execution", AgentDashboardState.parallel_execution, AgentDashboardState.toggle_parallel_execution),
                    control_row("show_tool_logs", "Show Tool Logs", AgentDashboardState.show_tool_logs, AgentDashboardState.toggle_show_tool_logs),
                    control_row("show_audit_logs", "Show Audit Logs", AgentDashboardState.show_audit_logs, AgentDashboardState.toggle_show_audit_logs),
                    control_row("response_only", "Response Only", AgentDashboardState.response_only, AgentDashboardState.toggle_response_only),
                    control_row("global_search_mode", "Global Search Mode", AgentDashboardState.global_search_mode, AgentDashboardState.toggle_global_search_mode),
                    control_row("admin_mode", "Admin Mode", AgentDashboardState.admin_mode, AgentDashboardState.toggle_admin_mode),
                    spacing="2",
                    width="100%",
                    align="stretch",
                    padding_top="8px",
                ),
                style={"width": "100%"},
            ),
            rx.el.details(
                rx.el.summary(
                    "Risk Management",
                    style={
                        "cursor": "pointer",
                        "color": NEON_CYAN,
                        "fontSize": "0.76rem",
                        "fontWeight": "700",
                        "letterSpacing": "0.08em",
                        "textTransform": "uppercase",
                    },
                ),
                rx.vstack(
                    control_row("tier_1", "Tier 1", AgentDashboardState.tier_1_enabled, AgentDashboardState.toggle_risk_tier(1)),
                    control_row("tier_2", "Tier 2", AgentDashboardState.tier_2_enabled, AgentDashboardState.toggle_risk_tier(2)),
                    control_row("tier_3", "Tier 3", AgentDashboardState.tier_3_enabled, AgentDashboardState.toggle_risk_tier(3)),
                    control_row("tier_4", "Tier 4", AgentDashboardState.tier_4_enabled, AgentDashboardState.toggle_risk_tier(4)),
                    spacing="2",
                    width="100%",
                    align="stretch",
                    padding_top="8px",
                ),
                style={"width": "100%"},
            ),
            rx.el.details(
                rx.el.summary(
                    "HitL Veto Console",
                    style={
                        "cursor": "pointer",
                        "color": "#FF6B6B",
                        "fontSize": "0.76rem",
                        "fontWeight": "700",
                        "letterSpacing": "0.08em",
                        "textTransform": "uppercase",
                    },
                ),
                rx.vstack(
                    rx.foreach(
                        AgentDashboardState.visible_sessions,
                        lambda item: rx.cond(
                            item.approval_required,
                            neon_panel(
                                rx.vstack(
                                    rx.hstack(
                                        rx.text(item.session_id, color=NEON_GREEN, font_size="0.7rem", font_weight="700"),
                                        rx.spacer(),
                                        rx.badge(
                                            f"Tier {item.pending_risk_tier}",
                                            background="rgba(255, 107, 107, 0.16)",
                                            color="#FF6B6B",
                                            border="1px solid rgba(255, 107, 107, 0.68)",
                                        ),
                                        width="100%",
                                        align="center",
                                    ),
                                    rx.text(item.pending_message, color="#FFB4B4", font_size="0.68rem"),
                                    rx.text("raw_arguments", color=MUTED_TEXT, font_size="0.66rem", letter_spacing="0.06em"),
                                    rx.el.pre(
                                        item.pending_raw_arguments,
                                        style={
                                            "maxHeight": "120px",
                                            "overflow": "auto",
                                            "background": "rgba(0, 0, 0, 0.58)",
                                            "border": "1px solid rgba(255, 107, 107, 0.3)",
                                            "borderRadius": "8px",
                                            "padding": "8px",
                                            "fontSize": "0.64rem",
                                            "whiteSpace": "pre-wrap",
                                            "color": "#FFD0D0",
                                            "width": "100%",
                                        },
                                    ),
                                    rx.text("repaired_arguments", color=MUTED_TEXT, font_size="0.66rem", letter_spacing="0.06em"),
                                    rx.el.pre(
                                        item.pending_repaired_arguments,
                                        style={
                                            "maxHeight": "120px",
                                            "overflow": "auto",
                                            "background": "rgba(0, 0, 0, 0.58)",
                                            "border": "1px solid rgba(0, 255, 255, 0.3)",
                                            "borderRadius": "8px",
                                            "padding": "8px",
                                            "fontSize": "0.64rem",
                                            "whiteSpace": "pre-wrap",
                                            "color": "#C8FFFF",
                                            "width": "100%",
                                        },
                                    ),
                                    rx.hstack(
                                        rx.button(
                                            "APPROVE",
                                            on_click=AgentDashboardState.approve_pending_action(item.session_id),
                                            background="rgba(0, 255, 0, 0.1)",
                                            color=NEON_GREEN,
                                            border=f"1px solid {NEON_GREEN}",
                                            _hover={"background": "rgba(0, 255, 0, 0.18)"},
                                            width="50%",
                                        ),
                                        rx.button(
                                            "REJECT",
                                            on_click=AgentDashboardState.deny_pending_action(item.session_id),
                                            background="rgba(255, 107, 107, 0.1)",
                                            color="#FF6B6B",
                                            border="1px solid rgba(255, 107, 107, 0.68)",
                                            _hover={"background": "rgba(255, 107, 107, 0.18)"},
                                            width="50%",
                                        ),
                                        width="100%",
                                        spacing="2",
                                    ),
                                    spacing="2",
                                    align="stretch",
                                    width="100%",
                                ),
                                border="1px solid rgba(255, 107, 107, 0.62)",
                                background="rgba(30, 6, 6, 0.72)",
                                padding="10px",
                                border_radius="10px",
                                width="100%",
                            ),
                            rx.box(display="none"),
                        ),
                    ),
                    rx.cond(
                        AgentDashboardState.review_count == 0,
                        rx.text("No halted Tier-4 actions pending approval.", color=MUTED_TEXT, font_size="0.68rem"),
                        rx.box(display="none"),
                    ),
                    spacing="2",
                    width="100%",
                    align="stretch",
                    padding_top="8px",
                ),
                style={"width": "100%"},
            ),
            rx.el.details(
                rx.el.summary(
                    "System Metadata",
                    style={
                        "cursor": "pointer",
                        "color": NEON_CYAN,
                        "fontSize": "0.76rem",
                        "fontWeight": "700",
                        "letterSpacing": "0.08em",
                        "textTransform": "uppercase",
                    },
                ),
                neon_panel(
                    rx.vstack(
                        rx.text("active_project", color=MUTED_TEXT, font_size="0.66rem", letter_spacing="0.08em"),
                        rx.text(AgentDashboardState.active_project, color=TEXT_PRIMARY, font_size="0.74rem", white_space="pre-wrap"),
                        rx.text("target_ip", color=MUTED_TEXT, font_size="0.66rem", letter_spacing="0.08em"),
                        rx.hstack(
                            rx.box(
                                width="8px",
                                height="8px",
                                border_radius="999px",
                                background=rx.cond(
                                    AgentDashboardState.target_status_label == "TRACKED",
                                    NEON_GREEN,
                                    "#7A7A7A",
                                ),
                                box_shadow=rx.cond(
                                    AgentDashboardState.target_status_label == "TRACKED",
                                    f"0 0 8px {NEON_GREEN}",
                                    "none",
                                ),
                            ),
                            rx.text(AgentDashboardState.target_status_label, color=NEON_CYAN, font_size="0.66rem", font_weight="700"),
                            rx.spacer(),
                            rx.text(AgentDashboardState.target_ip, color=TEXT_PRIMARY, font_size="0.74rem"),
                            width="100%",
                            align="center",
                            spacing="2",
                        ),
                        rx.text("session_uuid", color=MUTED_TEXT, font_size="0.66rem", letter_spacing="0.08em"),
                        rx.text(AgentDashboardState.session_uuid_short, color=TEXT_PRIMARY, font_size="0.74rem"),
                        spacing="2",
                        align="start",
                        width="100%",
                    ),
                ),
                style={"width": "100%"},
            ),
            rx.el.details(
                rx.el.summary(
                    "Clear",
                    style={
                        "cursor": "pointer",
                        "color": "#FF6B6B",
                        "fontSize": "0.76rem",
                        "fontWeight": "700",
                        "letterSpacing": "0.08em",
                        "textTransform": "uppercase",
                    },
                ),
                neon_panel(
                    rx.vstack(
                        rx.text("Delete all logs, workspaces, and sessions.", color="#FFB4B4", font_size="0.68rem"),
                        rx.cond(
                            AgentDashboardState.clear_confirmation_required,
                            rx.vstack(
                                rx.text("Are you sure?", color="#FF6B6B", font_size="0.74rem", font_weight="700"),
                                rx.hstack(
                                    rx.button(
                                        "YES, CLEAR ALL",
                                        on_click=AgentDashboardState.confirm_clear_all,
                                        background="rgba(255, 107, 107, 0.16)",
                                        color="#FF6B6B",
                                        border="1px solid rgba(255, 107, 107, 0.72)",
                                        _hover={"background": "rgba(255, 107, 107, 0.24)"},
                                        width="100%",
                                    ),
                                    rx.button(
                                        "CANCEL",
                                        on_click=AgentDashboardState.cancel_clear_all,
                                        background="rgba(0, 255, 255, 0.10)",
                                        color=NEON_CYAN,
                                        border=f"1px solid {NEON_CYAN}",
                                        _hover={"background": "rgba(0, 255, 255, 0.18)"},
                                        width="100%",
                                    ),
                                    spacing="2",
                                    width="100%",
                                ),
                                spacing="2",
                                width="100%",
                                align="stretch",
                            ),
                            rx.button(
                                "CLEAR",
                                on_click=AgentDashboardState.request_clear_all,
                                background="rgba(255, 107, 107, 0.12)",
                                color="#FF6B6B",
                                border="1px solid rgba(255, 107, 107, 0.68)",
                                _hover={"background": "rgba(255, 107, 107, 0.2)"},
                                width="100%",
                            ),
                        ),
                        spacing="2",
                        width="100%",
                        align="stretch",
                    ),
                    border="1px solid rgba(255, 107, 107, 0.62)",
                    background="rgba(30, 6, 6, 0.72)",
                    padding="10px",
                    border_radius="10px",
                    width="100%",
                ),
                style={"width": "100%"},
            ),
            spacing="3",
            align="stretch",
            width="100%",
        ),
        width="100%",
        height="100%",
    )


def active_command_form(session: AgentSession) -> rx.Component:
    return rx.cond(
        session.session_id == AgentDashboardState.active_session_id,
        rx.vstack(
            rx.hstack(
                rx.text(f"Active Session: {session.session_id}", color=NEON_GREEN, font_size="0.72rem", font_weight="700"),
                rx.spacer(),
                rx.text(
                    session.status_line,
                    color=MUTED_TEXT,
                    font_size="0.68rem",
                ),
                width="100%",
                align="center",
            ),
            rx.hstack(
                rx.el.textarea(
                    value=session.command_input,
                    on_change=lambda value: AgentDashboardState.set_session_command(session.session_id, value),
                    auto_height=True,
                    custom_attrs={
                        "data-command-submit": "true",
                        "onKeyDown": Var(
                            _js_expr="(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); const runButton = document.querySelector('[data-run-command=\"true\"]'); if (runButton) { window.setTimeout(() => runButton.click(), 150); } } }",
                        ),
                    },
                    placeholder="Type a prompt for the active agent. Press Enter to send.",
                    rows=1,
                    resize="none",
                    disabled=session.is_busy | (session.status == "error"),
                    width="100%",
                    min_height="56px",
                    max_height="180px",
                    padding="14px 16px",
                    background="rgba(0, 0, 0, 0.86)",
                    color=TEXT_PRIMARY,
                    border=f"1px solid {NEON_GREEN}",
                    border_radius="12px",
                    line_height="1.5",
                    _focus={
                        "outline": "none",
                        "border": f"1px solid {NEON_CYAN}",
                        "box_shadow": f"0 0 0 1px {NEON_CYAN}",
                    },
                ),
                rx.button(
                    "EXECUTE",
                    on_click=[
                        DrawerState.close_drawer,
                        AgentDashboardState.process_session_command(session.session_id),
                    ],
                    custom_attrs={"data-run-command": "true"},
                    background="rgba(0, 255, 0, 0.08)",
                    color=NEON_GREEN,
                    border=f"1px solid {NEON_GREEN}",
                    min_width="96px",
                    height="56px",
                    _hover={"background": "rgba(0, 255, 0, 0.14)"},
                    is_disabled=rx.cond(session.is_busy | (session.status == "error"), True, session.command_input == ""),
                ),
                width="100%",
                align="stretch",
                spacing="3",
            ),
            rx.cond(
                (session.status == "error") | (session.status == "busy"),
                rx.button(
                    "Clear Error",
                    on_click=AgentDashboardState.clear_error(session.session_id),
                    background="rgba(255, 107, 107, 0.10)",
                    color="#FF8F8F",
                    border="1px solid rgba(255, 107, 107, 0.55)",
                    border_radius="10px",
                    width="100%",
                    _hover={"background": "rgba(255, 107, 107, 0.18)"},
                ),
                rx.box(display="none"),
            ),
            rx.text(
                "Enter sends the prompt. Shift+Enter inserts a new line.",
                color=MUTED_TEXT,
                font_size="0.66rem",
            ),
            width="100%",
            spacing="3",
            align="stretch",
        ),
        rx.box(display="none"),
    )


def bottom_command_bar() -> rx.Component:
    return rx.box(
        rx.cond(
            AgentDashboardState.session_count == 0,
            rx.hstack(
                rx.text(
                    "No active terminal is attached. Start one to begin sending prompts.",
                    color=MUTED_TEXT,
                    font_size="0.8rem",
                ),
                rx.spacer(),
                rx.button(
                    "Attach Agent",
                    on_click=AgentDashboardState.add_agent,
                    background="rgba(0, 255, 0, 0.08)",
                    color=NEON_GREEN,
                    border=f"1px solid {NEON_GREEN}",
                    _hover={"background": "rgba(0, 255, 0, 0.14)"},
                ),
                width="100%",
                align="center",
            ),
            rx.vstack(
                rx.hstack(
                    rx.hstack(
                        rx.foreach(AgentDashboardState.visible_sessions, session_selector_button),
                        spacing="2",
                        wrap="wrap",
                        width="100%",
                    ),
                    rx.button(
                        "Add Agent",
                        on_click=AgentDashboardState.add_agent,
                        background="rgba(0, 255, 255, 0.08)",
                        color=NEON_CYAN,
                        border=f"1px solid {NEON_CYAN}",
                        _hover={"background": "rgba(0, 255, 255, 0.14)"},
                        is_disabled=rx.cond(AgentDashboardState.can_add_agent, False, True),
                    ),
                    width="100%",
                    align="start",
                    spacing="3",
                ),
                rx.foreach(AgentDashboardState.visible_sessions, active_command_form),
                width="100%",
                spacing="3",
                align="stretch",
            ),
        ),
        class_name="command-bar",
        border_top=f"1px solid {NEON_GREEN}",
        box_shadow="0 -10px 32px rgba(0, 0, 0, 0.55)",
        padding="14px 18px 18px",
        width="100vw",
        position="fixed",
        bottom="0",
        left="0",
        right="0",
        z_index="999",
        flex_shrink="0",
    )


def determine_grid_layout(count: int) -> tuple[str, str]:
    """Return (columns, rows) strings for a simple deterministic layout.

    Rules:
    - 0 or 1 session -> 1x1 (single focused terminal)
    - 2 sessions -> 2x1 (side-by-side)
    - 3-4+ sessions -> 2x2 (fill grid, extras will be paginated/hidden by design)
    """
    if count <= 1:
        return "1", "1"
    if count == 2:
        return "2", "1"
    return "2", "2"


def workspace_grid() -> rx.Component:
    empty_state = rx.box(
        neon_panel(
            rx.vstack(
                rx.text("No active terminals", color=MUTED_TEXT, font_size="1rem", font_weight="700"),
                rx.text(
                    "Use the sidebar to attach an agent terminal and the workspace will snap back into view.",
                    color=MUTED_TEXT,
                    font_size="0.85rem",
                ),
                rx.button(
                    "Attach First Agent",
                    on_click=AgentDashboardState.add_agent,
                    background="#021402",
                    color=NEON_GREEN,
                    border=f"1px solid {NEON_GREEN}",
                    _hover={"background": "#042004"},
                ),
                spacing="3",
                align="center",
            ),
            align="center",
        ),
        width="100%",
        align="center",
        padding="18px",
    )

    grid = rx.grid(
        rx.foreach(AgentDashboardState.visible_sessions, terminal_window),
        columns=AgentDashboardState.grid_cols,
        rows=AgentDashboardState.grid_rows,
        gap="18px",
        width="100%",
        flex="1",
        min_height="0",
        align_items="stretch",
    )
    main = rx.vstack(grid, spacing="3", width="100%", height="100%", min_height="0")

    return rx.box(
        rx.cond(AgentDashboardState.session_count == 0, empty_state, main),
        width="100%",
        height="100%",
        min_height="0",
        filter="none",
    )


def metadata_drawer() -> rx.Component:
    return rx.drawer.root(
        rx.drawer.trigger(
            rx.button(
                "☰",
                custom_attrs={"data-drawer-trigger": "metadata"},
                background="rgba(0, 0, 0, 0.82)",
                color=rx.cond(AgentDashboardState.intel_drawer_alert, "#FF6B6B", "#00FF00"),
                border=rx.cond(
                    AgentDashboardState.intel_drawer_alert,
                    "1px solid #FF6B6B",
                    "1px solid #00FF00",
                ),
                border_radius="10px",
                width="42px",
                height="42px",
                padding="0",
                font_size="1.2rem",
                position="fixed",
                top="20px",
                left="20px",
                z_index="1200",
                box_shadow=rx.cond(
                    AgentDashboardState.intel_drawer_alert,
                    "0 0 12px rgba(255, 107, 107, 0.9)",
                    "0 0 10px rgba(0, 255, 0, 0.7)",
                ),
                animation=rx.cond(
                    AgentDashboardState.intel_drawer_alert,
                    "intelAlertPulse 1.4s ease-in-out infinite",
                    "none",
                ),
                _hover={"background": "rgba(0, 255, 0, 0.14)"},
            )
        ),
        rx.drawer.portal(
            rx.drawer.overlay(
                background="rgba(0, 0, 0, 0.32)",
                z_index="1190",
            ),
            rx.drawer.content(
                system_sidebar(),
                background="rgba(0, 0, 0, 0.9)",
                border_right="1px solid #00FF00",
                border_radius="0 16px 16px 0",
                height="100vh",
                width="340px",
                max_width="90vw",
                padding="16px",
                z_index="1201",
                transition="transform 220ms ease",
                custom_attrs={"data-intel-drawer": "content"},
            ),
        ),
        direction="left",
        open=DrawerState.is_open,
        on_open_change=DrawerState.set_open,
    )


def top_header_bar() -> rx.Component:
    return rx.hstack(
        rx.vstack(
            rx.text(
                "Cerberus AI",
                color=TEXT_PRIMARY,
                font_size="1rem",
                font_weight="700",
                letter_spacing="0.12em",
                text_transform="uppercase",
            ),
            rx.text(
                "Operator grid and runtime configuration",
                color=MUTED_TEXT,
                font_size="0.72rem",
            ),
            spacing="1",
            align="start",
        ),
        rx.spacer(),
        rx.button(
            rx.hstack(
                rx.icon(tag="settings", size=16),
                rx.text("Config", font_weight="700"),
                spacing="2",
                align="center",
            ),
            custom_attrs={"data-config-button": "true"},
            on_click=AgentDashboardState.toggle_config,
            background="rgba(0, 0, 0, 0.82)",
            color=NEON_GREEN,
            border=f"1px solid {NEON_GREEN}",
            border_radius="12px",
            font_family='"JetBrains Mono", "Courier New", monospace',
            box_shadow="0 0 14px rgba(0, 255, 0, 0.28)",
            _hover={"background": "rgba(0, 255, 0, 0.12)"},
        ),
        rx.menu.root(
            rx.menu.trigger(
                rx.button(
                    rx.hstack(
                        rx.icon(tag="terminal", size=16),
                        rx.text("Commands", font_weight="700"),
                        spacing="2",
                        align="center",
                    ),
                    custom_attrs={"data-command-menu-button": "true"},
                    background="rgba(0, 20, 0, 0.92)",
                    color=NEON_GREEN,
                    border=f"1px solid {NEON_GREEN}",
                    border_radius="12px",
                    font_family='"JetBrains Mono", "Courier New", monospace',
                    box_shadow="0 0 16px rgba(0, 255, 0, 0.33)",
                    _hover={"background": "rgba(0, 255, 0, 0.16)"},
                ),
            ),
            rx.menu.content(
                rx.foreach(
                    COMMAND_MENU_ITEMS,
                    lambda item: rx.menu.item(
                        rx.hstack(
                            rx.vstack(
                                rx.text(item["command"], color=TEXT_PRIMARY, font_size="0.74rem", font_weight="700"),
                                rx.text(item["desc"], color=MUTED_TEXT, font_size="0.68rem"),
                                spacing="1",
                                align="start",
                            ),
                            rx.spacer(),
                            rx.badge(
                                rx.hstack(
                                    rx.text("T", color=NEON_GREEN, font_size="0.68rem", font_weight="700"),
                                    rx.text(item["tier"], color=NEON_GREEN, font_size="0.68rem", font_weight="700"),
                                    spacing="1",
                                    align="center",
                                ),
                                background="rgba(0, 255, 0, 0.1)",
                                color=NEON_GREEN,
                                border="1px solid rgba(0, 255, 0, 0.45)",
                            ),
                            width="100%",
                            align="center",
                            spacing="2",
                        ),
                        custom_attrs={"data-command-menu-item": "true"},
                        on_select=AgentDashboardState.run_quick_command(item["command"]),
                    ),
                ),
                background="rgba(0, 0, 0, 0.96)",
                border="1px solid rgba(0, 255, 0, 0.42)",
                border_radius="12px",
                min_width="360px",
                padding="8px",
            ),
        ),
        position="fixed",
        top="18px",
        left="76px",
        right="20px",
        z_index="1100",
        background="rgba(0, 0, 0, 0.72)",
        border=f"1px solid rgba(0, 255, 0, 0.22)",
        border_radius="16px",
        box_shadow="0 18px 32px rgba(0, 0, 0, 0.36)",
        backdrop_filter="blur(12px)",
        padding="12px 16px",
        align="center",
        width="auto",
    )


def config_text_card(key: str, label: str, description: str, value: Var | str, placeholder: str = "") -> rx.Component:
    return neon_panel(
        rx.vstack(
            rx.hstack(
                rx.vstack(
                    rx.text(label, color=TEXT_PRIMARY, font_size="0.86rem", font_weight="700"),
                    rx.text(description, color=MUTED_TEXT, font_size="0.72rem", line_height="1.5"),
                    spacing="1",
                    align="start",
                ),
                rx.spacer(),
                rx.text(
                    CONFIG_CARD_TARGETS[key],
                    color=NEON_CYAN,
                    font_size="0.66rem",
                    padding="4px 8px",
                    border="1px solid rgba(0, 255, 255, 0.25)",
                    border_radius="999px",
                    background="rgba(0, 24, 24, 0.68)",
                ),
                width="100%",
                align="start",
            ),
            rx.input(
                value=value,
                placeholder=placeholder,
                custom_attrs={"data-config-input": key},
                on_change=lambda next_value: AgentDashboardState.set_env_value(key, next_value),
                background="rgba(0, 0, 0, 0.88)",
                color=TEXT_PRIMARY,
                border=f"1px solid rgba(0, 255, 0, 0.26)",
                focus_border_color=NEON_CYAN,
                font_family='"JetBrains Mono", "Courier New", monospace',
                size="3",
            ),
            spacing="3",
            align="stretch",
            width="100%",
        )
    )


def config_switch_card(key: str, label: str, description: str, checked: Var | bool) -> rx.Component:
    return neon_panel(
        rx.hstack(
            rx.vstack(
                rx.text(label, color=TEXT_PRIMARY, font_size="0.86rem", font_weight="700"),
                rx.text(description, color=MUTED_TEXT, font_size="0.72rem", line_height="1.5"),
                rx.text(
                    CONFIG_CARD_TARGETS[key],
                    color=NEON_CYAN,
                    font_size="0.66rem",
                    padding="4px 8px",
                    border="1px solid rgba(0, 255, 255, 0.25)",
                    border_radius="999px",
                    background="rgba(0, 24, 24, 0.68)",
                    width="fit-content",
                ),
                spacing="2",
                align="start",
            ),
            rx.spacer(),
            rx.vstack(
                rx.switch(
                    checked=checked,
                    custom_attrs={"data-config-switch": key},
                    on_change=lambda next_value: AgentDashboardState.set_env_value(key, next_value),
                    color_scheme="green",
                    size="3",
                ),
                rx.text(
                    rx.cond(checked, "Enabled", "Disabled"),
                    color=rx.cond(checked, NEON_GREEN, MUTED_TEXT),
                    font_size="0.72rem",
                    font_weight="700",
                ),
                spacing="2",
                align="center",
            ),
            width="100%",
            align="center",
            spacing="4",
        )
    )


def config_manager_overlay() -> rx.Component:
    return rx.box(
        rx.vstack(
            rx.hstack(
                rx.vstack(
                    rx.text(
                        "Configuration Manager",
                        color=TEXT_PRIMARY,
                        font_size="1.35rem",
                        font_weight="700",
                        letter_spacing="0.08em",
                        text_transform="uppercase",
                    ),
                    rx.text(
                        "Edit live runtime values and persist them back to the repository env files.",
                        color=MUTED_TEXT,
                        font_size="0.8rem",
                    ),
                    spacing="1",
                    align="start",
                ),
                rx.spacer(),
                rx.text(
                    "Root aliases resolve to .env. Dashboard-only values resolve to dockerized/.env/*.",
                    color=NEON_CYAN,
                    font_size="0.72rem",
                    max_width="26rem",
                    text_align="right",
                ),
                width="100%",
                align="start",
            ),
            rx.cond(
                AgentDashboardState.config_api_base_valid,
                rx.box(display="none"),
                rx.text(
                    "CERBERUS_API_BASE must start with http:// or https:// before you can save.",
                    color="#FF6B6B",
                    font_size="0.76rem",
                    padding="10px 12px",
                    border="1px solid rgba(255, 107, 107, 0.35)",
                    border_radius="12px",
                    background="rgba(44, 10, 10, 0.72)",
                    width="100%",
                ),
            ),
            rx.box(
                rx.vstack(
                    config_text_card(
                        "CERBERUS_API_BASE",
                        "CERBERUS_API_BASE",
                        CONFIG_CARD_DESCRIPTIONS["CERBERUS_API_BASE"],
                        AgentDashboardState.config_api_base,
                        placeholder=CONFIG_CARD_PLACEHOLDERS["CERBERUS_API_BASE"],
                    ),
                    config_text_card(
                        "CEREBRO_MODEL",
                        "CEREBRO_MODEL",
                        CONFIG_CARD_DESCRIPTIONS["CEREBRO_MODEL"],
                        AgentDashboardState.config_model,
                        placeholder=CONFIG_CARD_PLACEHOLDERS["CEREBRO_MODEL"],
                    ),
                    config_text_card(
                        "CERBERUS_ACTIVE_CONTAINER",
                        "CERBERUS_ACTIVE_CONTAINER",
                        CONFIG_CARD_DESCRIPTIONS["CERBERUS_ACTIVE_CONTAINER"],
                        AgentDashboardState.config_active_container,
                        placeholder=CONFIG_CARD_PLACEHOLDERS["CERBERUS_ACTIVE_CONTAINER"],
                    ),
                    config_text_card(
                        "REDIS_URL",
                        "REDIS_URL",
                        CONFIG_CARD_DESCRIPTIONS["REDIS_URL"],
                        AgentDashboardState.config_redis_url,
                        placeholder=CONFIG_CARD_PLACEHOLDERS["REDIS_URL"],
                    ),
                    config_switch_card(
                        "DEBUG_MODE",
                        "DEBUG_MODE",
                        CONFIG_CARD_DESCRIPTIONS["DEBUG_MODE"],
                        AgentDashboardState.config_debug_mode,
                    ),
                    spacing="4",
                    align="stretch",
                    width="100%",
                    padding_bottom="112px",
                ),
                width="100%",
                flex="1",
                min_height="0",
                overflow_y="auto",
                padding_right="8px",
            ),
            rx.hstack(
                rx.button(
                    "Save",
                    color_scheme="green",
                    on_click=AgentDashboardState.save_and_close,
                    custom_attrs={"data-config-save": "true"},
                    disabled=AgentDashboardState.config_save_disabled,
                    font_family='"JetBrains Mono", "Courier New", monospace',
                ),
                rx.button(
                    "Close",
                    color_scheme="red",
                    on_click=AgentDashboardState.toggle_config,
                    custom_attrs={"data-config-close": "true"},
                    font_family='"JetBrains Mono", "Courier New", monospace',
                    variant="soft",
                ),
                rx.spacer(),
                rx.text(
                    "Changes update os.environ immediately for the running dashboard process where possible.",
                    color=MUTED_TEXT,
                    font_size="0.72rem",
                ),
                width="100%",
                align="center",
                spacing="3",
                position="sticky",
                bottom="0",
                border_top=f"1px solid rgba(0, 255, 0, 0.18)",
                background="rgba(0, 0, 0, 0.94)",
                box_shadow="0 -10px 24px rgba(0, 0, 0, 0.42)",
                padding="14px 0 4px",
            ),
            width="100%",
            height="100%",
            spacing="4",
            align="stretch",
        ),
        position="fixed",
        custom_attrs={"data-config-overlay": "true"},
        inset="0",
        z_index="1300",
        background="radial-gradient(circle at top right, rgba(0, 255, 255, 0.1), transparent 26%), radial-gradient(circle at left center, rgba(0, 255, 0, 0.08), transparent 22%), rgba(0, 0, 0, 0.98)",
        padding="24px 24px 16px",
        width="100vw",
        height="100vh",
        overflow="hidden",
    )


def index() -> rx.Component:
    return rx.box(
        rx.toast.provider(position="top-right", rich_colors=True, close_button=True),
        metadata_drawer(),
        rx.cond(
            AgentDashboardState.show_config,
            config_manager_overlay(),
            rx.box(
                top_header_bar(),
                rx.box(
                    rx.vstack(
                        workspace_grid(),
                        spacing="4",
                        align="stretch",
                        width="100%",
                        height="100%",
                        min_height="0",
                        margin_top="5rem",
                    ),
                    width="100%",
                    height="100%",
                    min_height="0",
                    padding="20px 20px 240px 20px",
                    margin_left=rx.cond(DrawerState.is_open, "356px", "0"),
                    transition="margin-left 220ms ease",
                    box_sizing="border-box",
                    overflow="hidden",
                    custom_attrs={"data-workspace-shell": "true"},
                ),
                bottom_command_bar(),
                width="100%",
                height="100%",
            ),
        ),
        rx.foreach(AgentDashboardState.visible_sessions, approval_modal),
        class_name="dashboard-root",
        background=BG_BLACK,
        color=TEXT_PRIMARY,
        font_family='"JetBrains Mono", "Courier New", monospace',
        width="100vw",
        height="100vh",
        padding="0",
        overflow="hidden",
        position="relative",
    )


app = rx.App(
        theme=rx.theme(
                appearance="dark",
                color_mode="dark",
                accent_color="green",
                gray_color="slate",
                radius="large",
                scaling="100%",
                theme_panel=False,
        ),
        style={
                "background": BG_BLACK,
                "color": TEXT_PRIMARY,
                "font_family": '"JetBrains Mono", "Courier New", monospace',
        },
        stylesheets=[
            "https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap"
        ],
        head_components=[
                rx.el.style(_render_custom_css(custom_css)),
        ],
)
# Override the default Reflex ErrorBoundary fallback when the runtime
# exposes app-level wrappers (newer Reflex releases).
if hasattr(app, "app_wraps"):
    app.app_wraps[(55, "ErrorBoundary")] = lambda stateful: error_boundary(
        **({"on_error": noop()} if not stateful else {}),
        fallback_render=rx.box(
            rx.vstack(
                rx.heading(
                    "An error occurred while rendering this page.",
                    font_size="1.5rem",
                    font_weight="bold",
                ),
                rx.text(
                    "This is an application error. Refreshing may help.",
                    opacity="0.75",
                ),
            ),
            height="100%",
            width="100%",
            display="flex",
            align_items="center",
            justify_content="center",
            background="#fff",
            color="#000",
        ),
    )

app.add_page(index, route="/", on_load=AgentDashboardState.initialize_client_session)
