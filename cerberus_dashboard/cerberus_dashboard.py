import json
import os
import random
import shlex
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field
import reflex as rx

from cerberus.main import execute_headless_action, terminate_action
from cerberus.parsers import parse_json_lenient
from cerberus.verification.policy_engine import PolicyEngine, PolicyReport


MAX_SESSIONS = 4
MAX_LOG_ENTRIES = 60
POLICY_HISTORY_LIMIT = 10
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
PROMPT_DISPATCH_TOOL = "run_supervised_prompt"
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


def _log_entry(role: str, content: str) -> dict[str, str]:
    return {
        "role": role,
        "content": content,
        "timestamp": _timestamp(),
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
    policy_history: list[dict[str, Any]] = Field(default_factory=list)
    tier_status: dict[str, str] = Field(default_factory=_default_tier_status)
    last_command: str = ""
    active_tool_name: str = ""
    status_line: str = "Standing by for a prompt or command."


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
        logs=[
            _log_entry("System", f"{session_id} linked to live headless execution."),
            _log_entry("System", f"Role assigned: {role}. Workspace tether locked to {workspace}."),
        ],
    )


def _build_sessions() -> list[AgentSession]:
    return [_new_session(0)]


def _next_session_slot(sessions: list[AgentSession]) -> int | None:
    used_session_ids = {session.session_id for session in sessions}
    for index in range(MAX_SESSIONS):
        if f"AGENT-{index + 1}" not in used_session_ids:
            return index
    return None


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
        "animation": "terminalFlicker 4s linear infinite",
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
    "@keyframes terminalFlicker": {
        "0%": {"opacity": "0.94", "filter": "drop-shadow(0 0 1px rgba(0, 255, 0, 0.35))"},
        "50%": {"opacity": "1", "filter": "drop-shadow(0 0 3px rgba(0, 255, 255, 0.18))"},
        "100%": {"opacity": "0.96", "filter": "drop-shadow(0 0 1px rgba(0, 255, 0, 0.28))"},
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


class AgentDashboardState(rx.State):
    agent_sessions: list[AgentSession] = _build_sessions()
    active_session_id: str = "AGENT-1"

    cpu_usage: int = 24
    ram_usage: int = 58
    net_mbps: float = 8.4
    alert_count: int = 1
    sensor_health: str = "Nominal"

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
        self._refresh_system_health()

    @rx.event
    def remove_agent(self, session_id: str) -> None:
        index = self._index_for_session_id(session_id)
        if index is None:
            return

        session = self.agent_sessions[index]
        if session.is_busy or session.approval_required:
            self._append_log(index, "Audit", "Detach is locked while the agent is busy or awaiting approval.")
            return

        self.agent_sessions = [item for item in self.agent_sessions if item.session_id != session_id]
        if self.active_session_id == session_id:
            self.active_session_id = self.agent_sessions[0].session_id if self.agent_sessions else ""
        self._refresh_system_health()

    @rx.var
    def visible_sessions(self) -> list[AgentSession]:
        return self.agent_sessions

    @rx.var
    def session_count(self) -> int:
        return len(self.agent_sessions)

    @rx.var
    def grid_cols(self) -> str:
        return determine_grid_layout(self.session_count)[0]

    @rx.var
    def grid_rows(self) -> str:
        return determine_grid_layout(self.session_count)[1]

    def set_active_session(self, session_id: str) -> None:
        if self._index_for_session_id(session_id) is None:
            return
        self.active_session_id = session_id

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

    def _session_copy(self, index: int) -> AgentSession:
        return self.agent_sessions[index].model_copy(deep=True)

    def _store_session(self, index: int, session: AgentSession) -> None:
        sessions = list(self.agent_sessions)
        sessions[index] = session
        self.agent_sessions = sessions

    def _append_log(self, index: int, role: str, content: str) -> None:
        cleaned = content.rstrip()
        if not cleaned:
            return
        session = self._session_copy(index)
        session.logs = [*session.logs, _log_entry(role, cleaned)][-MAX_LOG_ENTRIES:]
        self._store_session(index, session)

    @staticmethod
    def _role_for_runtime_event(channel: str, active_tool_name: str) -> str:
        normalized_channel = str(channel or "stdout").strip().lower()
        if normalized_channel == "stderr":
            return "Audit"
        if normalized_channel == "status":
            return "System"
        if normalized_channel == "stdout" and active_tool_name == PROMPT_DISPATCH_TOOL:
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
        self._store_session(index, session)

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
    def _workspace_dir() -> str:
        return str(_default_workspaces_root())

    @staticmethod
    def _project_id_for_session(session: AgentSession) -> str:
        return session.workspace_id.strip() or "dashboard"

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

    def _prime_session(self, index: int, command: str, tool_name: str) -> None:
        session = self._session_copy(index)
        session.is_busy = True
        session.status = "verifying"
        session.termination_requested = False
        session.approval_required = False
        session.pending_action = None
        session.command_input = ""
        session.last_command = command
        session.active_tool_name = tool_name
        session.status_line = "Running policy verification."
        session.tier_status = {tier_key: "pending" for tier_key, _ in AUDIT_TIERS}
        session.logs = [
            *session.logs,
            _log_entry("User", command),
            _log_entry("Audit", "Policy engine verification started for live headless execution."),
        ][-MAX_LOG_ENTRIES:]
        self._store_session(index, session)
        self.active_session_id = session.session_id

    async def _handle_runtime_event(self, index: int, event: dict[str, Any]) -> None:
        channel = str(event.get("channel", "stdout") or "stdout").strip().lower()
        message = str(event.get("message", "") or "").rstrip()
        if not message:
            return

        async with self:
            role = "Tool"
            if channel == "status" and index < len(self.agent_sessions):
                session = self._session_copy(index)
                session.status_line = message
                role = self._role_for_runtime_event(channel, session.active_tool_name)
                self._store_session(index, session)
            elif index < len(self.agent_sessions):
                session = self._session_copy(index)
                role = self._role_for_runtime_event(channel, session.active_tool_name)
            self._append_log(index, role, message)

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
            await self._handle_runtime_event(index, event)

        execution_result = await execute_headless_action(
            action,
            workspace_dir=self._workspace_dir(),
            project_id=self._project_id_for_session(session),
            session_id=session.session_id,
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
                self._apply_report_state(
                    index,
                    report,
                    is_busy=False,
                    status_line="LLM response received.",
                    manual_approval_granted=manual_approval_granted,
                )
                self._refresh_system_health()
                return

            arguments = execution_result.arguments or action.get("arguments", {})
            details = json.dumps(arguments, sort_keys=True, default=str) if arguments else "{}"
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
                self._append_log(index, "Tool", self._format_execution_output(execution_result.output))
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

        await self._dispatch_verified_action(index, action=action, session=session, report=report)

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

        result = await terminate_action(session.session_id)

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
        async with self:
            index = self._index_for_session_id(session_id)
            if index is None:
                return

            session = self._session_copy(index)
            command = session.command_input.strip()
            if not command or session.is_busy:
                return

            action = self._parse_prompt_to_action(command)

            self._prime_session(index, command, str(action.get("tool_name", "") or ""))
            self._refresh_system_health()

        await self._run_session_command(index, command, action)

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

            session.is_busy = True
            session.status = "verifying"
            session.approval_required = False
            session.active_tool_name = str(pending_action.get("tool_name", "") or "")
            session.status_line = "Manual approval granted. Re-verifying before dispatch."
            session.logs = [
                *session.logs,
                _log_entry("Audit", "Manual approval granted. Re-verifying headless action."),
            ][-MAX_LOG_ENTRIES:]
            self._store_session(index, session)
            self._refresh_system_health()

        approved_action = dict(pending_action)
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

            session.pending_action = None
            session.approval_required = False
            session.is_busy = False
            session.status = "blocked"
            session.status_line = "Operator denied the high-risk action."
            session.tier_status["tier_4"] = "blocked"
            session.logs = [
                *session.logs,
                _log_entry("Audit", "Manual approval denied. Action was not dispatched."),
            ][-MAX_LOG_ENTRIES:]
            self._store_session(index, session)
            self._refresh_system_health()


def neon_panel(*children: rx.Component, class_name: str = "", **props: Any) -> rx.Component:
    panel_class_name = "neon-panel" if not class_name else f"neon-panel {class_name}"
    return rx.box(
        *children,
        class_name=panel_class_name,
        border_radius="14px",
        padding="14px",
        width="100%",
        **props,
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
        entry["role"] == "Assistant",
        rx.box(
            rx.text(
                entry["content"],
                color=TEXT_PRIMARY,
                font_size="1rem",
                line_height="1.75",
                white_space="pre-wrap",
            ),
            width="100%",
        ),
        rx.box(display="none"),
    )


def terminal_window(session: AgentSession) -> rx.Component:
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
            background="#000000",
            border_radius="0",
            padding="32px 36px",
        ),
        background="#000000",
        width="100%",
        height="100%",
        min_height="0",
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


def active_command_form(session: AgentSession) -> rx.Component:
    return rx.cond(
        session.session_id == AgentDashboardState.active_session_id,
        rx.vstack(
            rx.hstack(
                rx.vstack(
                    rx.text(session.session_id, color=NEON_GREEN, font_size="0.78rem", font_weight="700"),
                    rx.text(session.status_line, color=MUTED_TEXT, font_size="0.68rem"),
                    spacing="1",
                    align="start",
                ),
                rx.spacer(),
                rx.button(
                    "Stop",
                    on_click=AgentDashboardState.stop_session(session.session_id),
                    background="rgba(255, 107, 107, 0.08)",
                    color="#FF8F8F",
                    border="1px solid rgba(255, 107, 107, 0.55)",
                    _hover={"background": "rgba(255, 107, 107, 0.14)"},
                    is_disabled=rx.cond(session.is_busy, False, True),
                ),
                width="100%",
                align="center",
            ),
            rx.hstack(
                rx.form(
                    rx.text_area(
                        value=session.command_input,
                        on_change=AgentDashboardState.set_session_command(session.session_id),
                        enter_key_submit=True,
                        placeholder="Type a prompt for the active agent. Press Enter to send.",
                        rows="1",
                        resize="none",
                        disabled=session.is_busy,
                        width="100%",
                        min_height="56px",
                        padding="14px 16px",
                        background="rgba(0, 0, 0, 0.86)",
                        color=TEXT_PRIMARY,
                        border=f"1px solid {NEON_GREEN}",
                        border_radius="12px",
                        line_height="1.5",
                        _focus={
                            "border": f"1px solid {NEON_CYAN}",
                            "box_shadow": f"0 0 0 1px {NEON_CYAN}",
                        },
                    ),
                    on_submit=lambda _form_data: AgentDashboardState.process_session_command(session.session_id),
                    width="100%",
                ),
                rx.button(
                    "Run",
                    on_click=AgentDashboardState.process_session_command(session.session_id),
                    background="rgba(0, 255, 0, 0.08)",
                    color=NEON_GREEN,
                    border=f"1px solid {NEON_GREEN}",
                    min_width="96px",
                    height="56px",
                    _hover={"background": "rgba(0, 255, 0, 0.14)"},
                    is_disabled=session.is_busy,
                ),
                width="100%",
                align="stretch",
                spacing="3",
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
        width="100%",
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
                    "Attach an agent from the bottom command bar and the workspace will snap back into view.",
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

    return rx.cond(AgentDashboardState.session_count == 0, empty_state, main)


def index() -> rx.Component:
    return rx.box(
        rx.vstack(
            workspace_grid(),
            bottom_command_bar(),
            spacing="0",
            width="100%",
            height="100%",
            min_height="0",
            align="stretch",
        ),
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
                "https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&display=swap"
        ],
        head_components=[
                rx.el.style(_render_custom_css(custom_css)),
                rx.el.script(
                        """
                        (function() {
                            function ensureObserver(el) {
                                try {
                                    if (el.__hasAutoScroll) return;
                                    el.__hasAutoScroll = true;
                                    el.scrollTop = el.scrollHeight;
                                    const mo = new MutationObserver(function() {
                                        try { el.scrollTop = el.scrollHeight; } catch(e) {}
                                    });
                                    mo.observe(el, { childList: true, subtree: true });
                                } catch(e) {}
                            }

                            function attachExisting() {
                                document.querySelectorAll('.terminal-flicker').forEach(ensureObserver);
                            }

                            if (document.readyState === 'loading') {
                                document.addEventListener('DOMContentLoaded', attachExisting);
                            } else {
                                attachExisting();
                            }

                            const bodyObserver = new MutationObserver((mutations) => {
                                for (const m of mutations) {
                                    for (const n of m.addedNodes) {
                                        if (n.nodeType === 1) {
                                            if (n.classList && n.classList.contains('terminal-flicker')) ensureObserver(n);
                                            n.querySelectorAll && n.querySelectorAll('.terminal-flicker').forEach(ensureObserver);
                                        }
                                    }
                                }
                            });
                            bodyObserver.observe(document.body, { childList: true, subtree: true });
                        })();
                        """
                ),
        ],
)
app.add_page(index, route="/")
