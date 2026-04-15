import asyncio
import json
import os
import random
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field
import reflex as rx

from cai.main import execute_headless_action, terminate_action
from cai.parsers import parse_json_lenient
from cai.verification.policy_engine import PolicyEngine, PolicyReport


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
SESSION_TARGET_ALL = "ALL SESSIONS"
SESSION_CODENAMES = ["SENTINEL", "VECTOR", "RELAY", "FORGE"]
REPO_ROOT = Path(__file__).resolve().parents[1]
AUDIT_TIERS = [
    ("tier_1", "Tool Contract"),
    ("tier_2", "Workspace Bounds"),
    ("tier_3", "Loop Guard"),
    ("tier_4", "Risk Sweep"),
]
SESSION_SELECTOR_OPTIONS = [SESSION_TARGET_ALL] + [f"AGENT-{index + 1}" for index in range(MAX_SESSIONS)]


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


class AgentSession(BaseModel):
    session_id: str
    codename: str
    workspace: str
    workspace_id: str
    logs: list[dict[str, str]] = Field(default_factory=list)
    is_busy: bool = False
    termination_requested: bool = False
    approval_required: bool = False
    pending_action: dict[str, Any] | None = None
    policy_history: list[dict[str, Any]] = Field(default_factory=list)
    tier_status: dict[str, str] = Field(default_factory=_default_tier_status)
    last_command: str = ""
    status_line: str = "Awaiting operator input."


def _new_session(index: int) -> AgentSession:
    session_id = f"AGENT-{index + 1}"
    workspace_id = f"dashboard-agent-{index + 1}"
    workspace = f"./workspaces/{workspace_id}"
    codename = SESSION_CODENAMES[index]
    return AgentSession(
        session_id=session_id,
        codename=codename,
        workspace=workspace,
        workspace_id=workspace_id,
        logs=[
            _log_entry("System", f"{session_id} linked to live headless execution."),
            _log_entry("System", f"Workspace tether locked to {workspace}."),
        ],
    )


def _build_sessions() -> list[AgentSession]:
    return [_new_session(index) for index in range(MAX_SESSIONS)]


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


def _sidebar_component(*children: rx.Component, **props: Any) -> Any:
    sidebar = getattr(rx, "sidebar", None)
    if callable(sidebar):
        return sidebar(*children, **props)
    return rx.box(*children, **props)


def _stat_component(*children: rx.Component, **props: Any) -> Any:
    stat = getattr(rx, "stat", None)
    if callable(stat):
        return stat(*children, **props)
    return rx.box(*children, **props)


class AgentDashboardState(rx.State):
    agent_sessions: list[AgentSession] = _build_sessions()
    global_command: str = ""
    selected_session: str = SESSION_TARGET_ALL

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
    def command_scope_label(self) -> str:
        return "Global Commands" if self.selected_session == SESSION_TARGET_ALL else "Targeted Prompting"

    def set_global_command(self, value: str) -> None:
        self.global_command = value

    def set_selected_session(self, value: str) -> None:
        self.selected_session = value

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
        configured = os.getenv("CEREBRO_WORKSPACE_ROOT", "").strip()
        if configured:
            return str(Path(configured).expanduser().resolve())
        return str(REPO_ROOT.resolve())

    @staticmethod
    def _project_id_for_session(session: AgentSession) -> str:
        return session.workspace_id.strip() or "dashboard"

    @staticmethod
    def _system_state_for_session(session: AgentSession) -> dict[str, Any]:
        return {
            "workspace": session.workspace,
            "approval_required": session.approval_required,
            "status_line": session.status_line,
            "tier_status": dict(session.tier_status),
        }

    @staticmethod
    def _parse_prompt_to_action(prompt: str) -> dict[str, Any]:
        text = prompt.strip()
        parsed = parse_json_lenient(text, prefer_last=True) if text else None
        if isinstance(parsed, dict):
            action = dict(parsed)
            if "command" in action and "tool_name" not in action:
                action["tool_name"] = "execute_cli_command"
            if not isinstance(action.get("arguments"), dict):
                action["arguments"] = {}
            return action

        lowered = text.lower()
        if lowered.startswith("read "):
            return {"tool_name": "read_file", "arguments": {"file_path": text[5:].strip()}}
        if lowered.startswith("list "):
            return {"tool_name": "list_dir", "arguments": {"path": text[5:].strip()}}
        return {
            "tool_name": "execute_cli_command",
            "arguments": {"command": text},
            "command": text,
        }

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

    def _apply_report_state(
        self,
        index: int,
        report: PolicyReport,
        *,
        is_busy: bool,
        status_line: str,
        manual_approval_granted: bool = False,
    ) -> None:
        session = self._session_copy(index)
        session.is_busy = is_busy
        session.status_line = status_line
        session.tier_status = self._derive_tier_status(report, manual_approval_granted=manual_approval_granted)
        self._store_session(index, session)

    def _prime_session(self, index: int, command: str) -> None:
        session = self._session_copy(index)
        session.is_busy = True
        session.termination_requested = False
        session.approval_required = False
        session.pending_action = None
        session.last_command = command
        session.status_line = "Running policy verification."
        session.tier_status = {tier_key: "pending" for tier_key, _ in AUDIT_TIERS}
        session.logs = [
            *session.logs,
            _log_entry("User", command),
            _log_entry("Audit", "Policy engine verification started for live headless execution."),
        ][-MAX_LOG_ENTRIES:]
        self._store_session(index, session)

    async def _handle_runtime_event(self, index: int, event: dict[str, Any]) -> None:
        channel = str(event.get("channel", "stdout") or "stdout").strip().lower()
        message = str(event.get("message", "") or "").rstrip()
        if not message:
            return

        role = "Tool"
        if channel == "stderr":
            role = "Audit"
        elif channel == "status":
            role = "System"

        async with self:
            self._append_log(index, role, message)

    def _target_indexes(self) -> list[int]:
        if self.selected_session == SESSION_TARGET_ALL:
            return [
                index
                for index, session in enumerate(self.agent_sessions)
                if not session.is_busy and not session.approval_required
            ]
        return [
            index
            for index, session in enumerate(self.agent_sessions)
            if session.session_id == self.selected_session and not session.is_busy and not session.approval_required
        ]

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
                current_session.approval_required = False
                current_session.pending_action = None
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

    async def _run_session_command(self, index: int, command: str) -> None:
        async with self:
            if index >= len(self.agent_sessions):
                return
            session = self._session_copy(index)

        action = self._parse_prompt_to_action(command)
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
    async def stop_session(self, index: int) -> None:
        async with self:
            if index >= len(self.agent_sessions):
                return

            session = self._session_copy(index)
            if not session.is_busy:
                return

            session.is_busy = False
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
                session.status_line = "Action terminated by user."
                session.logs = [
                    *session.logs,
                    _log_entry("Audit", f"Stop signal sent to {found} registered process(es); kill fallback applied to {killed}."),
                ][-MAX_LOG_ENTRIES:]
            else:
                session.termination_requested = False
                session.status_line = "No active subprocess found for termination."
                session.logs = [
                    *session.logs,
                    _log_entry("Audit", "Emergency stop requested, but no active subprocess was registered."),
                ][-MAX_LOG_ENTRIES:]

            self._store_session(index, session)
            self._refresh_system_health()

    @rx.event(background=True)
    async def process_command(self) -> None:
        async with self:
            command = self.global_command.strip()
            if not command:
                return

            target_indexes = self._target_indexes()
            if not target_indexes:
                return

            for index in target_indexes:
                self._prime_session(index, command)
            self.global_command = ""
            self._refresh_system_health()

        await asyncio.gather(*(self._run_session_command(index, command) for index in target_indexes))

    @rx.event(background=True)
    async def approve_pending_action(self, index: int) -> None:
        async with self:
            if index >= len(self.agent_sessions):
                return

            session = self._session_copy(index)
            pending_action = session.pending_action
            if session.is_busy or not isinstance(pending_action, dict):
                return

            session.is_busy = True
            session.approval_required = False
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
    async def deny_pending_action(self, index: int) -> None:
        async with self:
            if index >= len(self.agent_sessions):
                return

            session = self._session_copy(index)
            if session.is_busy or not isinstance(session.pending_action, dict):
                return

            session.pending_action = None
            session.approval_required = False
            session.is_busy = False
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
    return rx.box(
        rx.text(
            status,
            text_transform="uppercase",
            font_size="0.66rem",
            font_weight="700",
            letter_spacing="0.08em",
            color=rx.cond(
                status == "cleared",
                NEON_CYAN,
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
                                status == "warning",
                                "#D9F99D",
                                rx.cond(status == "pending", "#D9F99D", MUTED_TEXT),
                            ),
                        ),
                    ),
                ),
            ),
        ),
        border=rx.cond(
            status == "cleared",
            f"1px solid {NEON_CYAN}",
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
                            status == "warning",
                            "1px solid #8AA800",
                            rx.cond(status == "pending", "1px solid #8AA800", "1px solid #305030"),
                        ),
                    ),
                ),
            ),
        ),
        background=rx.cond(
            status == "cleared",
            "rgba(0, 255, 255, 0.12)",
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
                            status == "warning",
                            "rgba(202, 255, 112, 0.12)",
                            rx.cond(status == "pending", "rgba(202, 255, 112, 0.12)", "rgba(8, 24, 8, 0.72)"),
                        ),
                    ),
                ),
            ),
        ),
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
    is_audit = entry["role"] == "Audit"
    is_system = entry["role"] == "System"
    label_color = rx.cond(is_audit, NEON_CYAN, rx.cond(is_system, MUTED_TEXT, NEON_GREEN))
    border_color = rx.cond(is_audit, NEON_CYAN, rx.cond(is_system, "#173817", NEON_GREEN))
    background = rx.cond(
        is_audit,
        "rgba(0, 28, 28, 0.68)",
        rx.cond(is_system, "rgba(9, 18, 9, 0.9)", "rgba(4, 14, 4, 0.92)"),
    )

    return rx.box(
        rx.text(
            f"[{entry['timestamp']}] {entry['role']}",
            color=label_color,
            font_size="0.69rem",
            font_weight="700",
            letter_spacing="0.08em",
        ),
        rx.text(entry["content"], color=TEXT_PRIMARY, font_size="0.79rem", white_space="pre-wrap"),
        class_name="terminal-log",
        border=f"1px solid {border_color}",
        background=background,
        border_radius="10px",
        padding="8px",
        width="100%",
    )


def audit_panel(session: AgentSession) -> rx.Component:
    return rx.box(
        rx.vstack(
            rx.hstack(
                rx.text("LOGIC AUDIT", color=NEON_CYAN, font_weight="700", font_size="0.76rem"),
                rx.spacer(),
                rx.text(session.workspace, color="#9ADADA", font_size="0.68rem"),
                width="100%",
                align="center",
            ),
            rx.cond(
                session.last_command != "",
                rx.text(
                    session.last_command,
                    color=TEXT_PRIMARY,
                    font_size="0.74rem",
                    white_space="nowrap",
                    overflow="hidden",
                    text_overflow="ellipsis",
                ),
                rx.text("No dispatch issued yet.", color=MUTED_TEXT, font_size="0.74rem"),
            ),
            rx.grid(
                *[
                    audit_tier_tile(f"T{tier_index}", tier_label, session.tier_status[tier_key])
                    for tier_index, (tier_key, tier_label) in enumerate(AUDIT_TIERS, start=1)
                ],
                template_columns="repeat(2, minmax(0, 1fr))",
                gap="10px",
                width="100%",
            ),
            spacing="2",
            width="100%",
            align="stretch",
        ),
        class_name="audit-panel",
        border_radius="12px",
        padding="12px",
        width="100%",
    )


def terminal_box(session: AgentSession, index: int) -> rx.Component:
    scroll_id = f"terminal-scroll-{index}"
    return rx.box(
        rx.scroll_area(
            rx.vstack(
                rx.foreach(session.logs, render_log_entry),
                width="100%",
                align="stretch",
                spacing="2",
            ),
            id=scroll_id,
            type="always",
            scrollbars="vertical",
            class_name="terminal-flicker",
            height="220px",
            width="100%",
            border=f"1px solid {NEON_GREEN}",
            background="#020602",
            border_radius="12px",
            padding="10px",
        ),
        rx.script(
            f"""
            setTimeout(function() {{
                const terminal = document.getElementById('{scroll_id}');
                if (terminal) {{
                    terminal.scrollTop = terminal.scrollHeight;
                }}
            }}, 20);
            """
        ),
        width="100%",
    )


def session_card(session: AgentSession, index: int) -> rx.Component:
    return neon_panel(
        rx.vstack(
            rx.hstack(
                rx.vstack(
                    rx.text(session.session_id, color=NEON_GREEN, font_weight="700", font_size="0.95rem"),
                    rx.text(session.codename, color=MUTED_TEXT, font_size="0.72rem", letter_spacing="0.14em"),
                    spacing="1",
                    align="start",
                ),
                rx.spacer(),
                rx.cond(
                    session.is_busy,
                    rx.hstack(
                        rx.badge(
                            "BUSY",
                            variant="solid",
                            background="rgba(0, 255, 255, 0.14)",
                            color=NEON_CYAN,
                            border=f"1px solid {NEON_CYAN}",
                        ),
                        rx.button(
                            "STOP",
                            on_click=AgentDashboardState.stop_session(index),  # pyright: ignore[reportCallIssue]
                            background="rgba(255, 107, 107, 0.14)",
                            color=AUDIT_VIOLATION,
                            border=f"1px solid {AUDIT_VIOLATION}",
                            min_width="92px",
                            height="32px",
                            _hover={"background": "rgba(255, 107, 107, 0.22)"},
                        ),
                        align="center",
                        spacing="2",
                    ),
                    rx.badge(
                        "READY",
                        variant="outline",
                        color=NEON_GREEN,
                        border=f"1px solid {NEON_GREEN}",
                    ),
                ),
                rx.cond(
                    session.approval_required,
                    rx.badge(
                        "APPROVAL REQUIRED",
                        variant="solid",
                        background="rgba(255, 209, 102, 0.14)",
                        color="#FFD166",
                        border="1px solid #FFD166",
                    ),
                ),
                width="100%",
                align="center",
            ),
            rx.text(session.status_line, color=TEXT_PRIMARY, font_size="0.77rem"),
            audit_panel(session),
            rx.cond(
                session.approval_required,
                rx.hstack(
                    rx.text(
                        "Tier 4 flagged a high-risk action. Manual approval is required before dispatch.",
                        color="#FFD166",
                        font_size="0.74rem",
                        width="100%",
                    ),
                    rx.button(
                        "Approve Risk",
                        on_click=AgentDashboardState.approve_pending_action(index),  # pyright: ignore[reportCallIssue]
                        background="rgba(255, 209, 102, 0.12)",
                        color="#FFD166",
                        border="1px solid #FFD166",
                        min_width="150px",
                        _hover={"background": "rgba(255, 209, 102, 0.2)"},
                        is_disabled=session.is_busy,
                    ),
                    rx.button(
                        "Deny Action",
                        on_click=AgentDashboardState.deny_pending_action(index),  # pyright: ignore[reportCallIssue]
                        background="rgba(255, 107, 107, 0.12)",
                        color="#FF6B6B",
                        border="1px solid #FF6B6B",
                        min_width="150px",
                        _hover={"background": "rgba(255, 107, 107, 0.2)"},
                        is_disabled=session.is_busy,
                    ),
                    width="100%",
                    align="center",
                    spacing="3",
                ),
            ),
            terminal_box(session, index),
            spacing="3",
            align="stretch",
            width="100%",
            height="100%",
        ),
        height="100%",
        min_height="0",
    )


def dashboard_header() -> rx.Component:
    return neon_panel(
        rx.hstack(
            rx.vstack(
                rx.text("CERBERUS AI | Command & Control.", color=NEON_GREEN, font_size="1.05rem", font_weight="700"),
                rx.text(
                    "Headless multi-agent security engine with programmatic policy enforcement, approvals, and workspace-scoped execution.",
                    color=MUTED_TEXT,
                    font_size="0.78rem",
                ),
                spacing="1",
                align="start",
            ),
            rx.spacer(),
            rx.vstack(
                rx.text(AgentDashboardState.command_scope_label, color=NEON_CYAN, font_size="0.8rem", font_weight="700"),
                rx.text(
                    "Each session executes verified actions inside its own isolated workspace under active policy control.",
                    color="#9ADADA",
                    font_size="0.72rem",
                    text_align="right",
                ),
                spacing="1",
                align="end",
            ),
            width="100%",
            align="center",
        ),
    )


def system_stat(label: str, value: str, detail: str) -> rx.Component:
    return _stat_component(
        rx.vstack(
            rx.text(label, color=MUTED_TEXT, font_size="0.7rem", font_weight="700", letter_spacing="0.08em"),
            rx.text(value, color=NEON_GREEN, font_size="1.2rem", font_weight="700"),
            rx.text(detail, color="#89B889", font_size="0.68rem"),
            spacing="1",
            align="start",
            width="100%",
        ),
        class_name="neon-panel",
        border_radius="12px",
        padding="12px",
        width="100%",
    )


def system_sidebar() -> rx.Component:
    return _sidebar_component(
        rx.vstack(
            rx.text("SYSTEM HEALTH", color=NEON_GREEN, font_size="0.98rem", font_weight="700"),
            rx.text("CPU / RAM / NETWORK", color=MUTED_TEXT, font_size="0.74rem"),
            system_stat("CPU", f"{AgentDashboardState.cpu_usage}%", "Audit-loop compute pressure"),
            system_stat("RAM", f"{AgentDashboardState.ram_usage}%", "Session cache residency"),
            system_stat("NETWORK", f"{AgentDashboardState.net_mbps} MB/s", "Synthetic control traffic"),
            rx.divider(border_color=NEON_GREEN),
            system_stat("BUSY NODES", f"{AgentDashboardState.busy_count}", "Sessions currently processing"),
            system_stat("CLEARED", f"{AgentDashboardState.cleared_count}", "Sessions with all tiers cleared"),
            system_stat("ALERTS", f"{AgentDashboardState.alert_count}", AgentDashboardState.sensor_health),
            rx.button(
                "Refresh Health",
                on_click=AgentDashboardState.trigger_refresh_system_health,
                width="100%",
                background="#021402",
                color=NEON_GREEN,
                border=f"1px solid {NEON_GREEN}",
                _hover={"background": "#042004"},
            ),
            spacing="3",
            width="100%",
            align="stretch",
        ),
        class_name="neon-panel",
        width="320px",
        min_width="320px",
        max_width="320px",
        height="100%",
        border_radius="16px",
        padding="16px",
    )


def workspace_grid() -> rx.Component:
    return rx.grid(
        rx.foreach(AgentDashboardState.agent_sessions, lambda session, index: session_card(session, index)),
        columns="2",
        rows="2",
        gap="18px",
        width="100%",
        flex="1",
        min_height="0",
    )


def command_bar() -> rx.Component:
    return rx.box(
        neon_panel(
            rx.hstack(
                rx.vstack(
                    rx.text("COMMAND BAR", color=NEON_GREEN, font_size="0.82rem", font_weight="700"),
                    rx.text(AgentDashboardState.command_scope_label, color=MUTED_TEXT, font_size="0.72rem"),
                    spacing="1",
                    align="start",
                    min_width="170px",
                ),
                rx.select(
                    SESSION_SELECTOR_OPTIONS,
                    value=AgentDashboardState.selected_session,
                    on_change=lambda value: AgentDashboardState.set_selected_session(value),  # pyright: ignore[reportCallIssue]
                    width="190px",
                    background="#020202",
                    color=TEXT_PRIMARY,
                    border=f"1px solid {NEON_GREEN}",
                ),
                rx.input(
                    value=AgentDashboardState.global_command,
                    on_change=lambda value: AgentDashboardState.set_global_command(value),  # pyright: ignore[reportCallIssue]
                    placeholder="Enter a global command or choose a session for targeted prompting...",
                    width="100%",
                    background="#010101",
                    color=TEXT_PRIMARY,
                    border=f"1px solid {NEON_GREEN}",
                    focus_border_color=NEON_CYAN,
                ),
                rx.button(
                    "Verify and Run",
                    on_click=AgentDashboardState.process_command,
                    is_disabled=AgentDashboardState.global_command == "",
                    background="#022202",
                    color=NEON_GREEN,
                    border=f"1px solid {NEON_GREEN}",
                    min_width="170px",
                    _hover={"background": "#033003"},
                ),
                width="100%",
                align="center",
                spacing="4",
            ),
            class_name="command-bar",
        ),
        position="fixed",
        left="0",
        right="0",
        bottom="0",
        padding="16px 20px 20px 20px",
        z_index="20",
    )


def index() -> rx.Component:
    return rx.box(
        rx.hstack(
            system_sidebar(),
            rx.vstack(
                dashboard_header(),
                workspace_grid(),
                spacing="4",
                align="stretch",
                width="100%",
                height="100%",
                min_height="0",
            ),
            spacing="4",
            align="stretch",
            width="100%",
            height="100%",
            min_height="0",
        ),
        command_bar(),
        class_name="dashboard-root",
        background=BG_BLACK,
        color=TEXT_PRIMARY,
        font_family='"JetBrains Mono", "Courier New", monospace',
        width="100vw",
        height="100vh",
        padding="20px 20px 120px 20px",
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
    head_components=[rx.el.style(_render_custom_css(custom_css))],
)
app.add_page(index, route="/")
