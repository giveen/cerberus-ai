"""Autonomous Blue Team resilience engine.

Provides a clean-room `CerebroBlueTeamAgent` implementation with an
Observe -> Orient -> Decide -> Act lifecycle and compatibility `Agent` export.
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import random
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

from dotenv import load_dotenv
from openai import AsyncOpenAI

from cerberus.sdk.agents import Agent, OpenAIChatCompletionsModel
from cerberus.tools.all_tools import get_all_tools, get_tool
from cerberus.tools.misc.reasoning import MODE_CRITIQUE, MODE_RISK_ASSESSMENT, MODE_STRATEGY, REASONING_TOOL
from cerberus.tools.reconnaissance.filesystem import FILESYSTEM_TOOL
from cerberus.tools.reconnaissance.generic_linux_command import LINUX_COMMAND_TOOL
from cerberus.tools.reconnaissance.nmap import NMAP_TOOL
from cerberus.tools.workspace import get_project_space
from cerberus.util import create_system_prompt_renderer, load_prompt_template


@dataclass
class BlueTeamFinding:
    finding_id: str
    detected_threat: str
    source: str
    evidence: str
    mitre_attack_id: str
    confidence: float
    phase: str
    action_required: str


@dataclass
class FixAction:
    action_id: str
    kind: str
    target: str
    content: str
    reason: str


@dataclass
class SessionState:
    cycle_index: int = 0
    discovered_vulnerabilities: List[BlueTeamFinding] = field(default_factory=list)
    applied_fixes: List[Dict[str, Any]] = field(default_factory=list)
    verification_history: List[Dict[str, Any]] = field(default_factory=list)


MITRE_MAP: Tuple[Tuple[str, str], ...] = (
    (r"\b(?:bash\s+-c|sh\s+-c|python\s+-c|perl\s+-e)\b", "T1059"),
    (r"\b(?:curl\s+|wget\s+|Invoke-WebRequest|certutil\s+-urlcache)\b", "T1105"),
    (r"\b(?:cron\.|crontab|systemd\s+service|rc\.local|authorized_keys)\b", "T1053"),
    (r"\b(?:sudoers|NOPASSWD|sudo\s+)\b", "T1548"),
    (r"\b(?:sshd_config|PermitRootLogin|PasswordAuthentication)\b", "T1021"),
    (r"\b(?:nc\s+|ncat\s+|socat\s+)\b", "T1090"),
)


class CerebroBlueTeamAgent:
    """Autonomous resilience engine aligned to the CRIR prompt."""

    def __init__(self, *, workspace_root: Optional[str] = None, jitter_range: Tuple[float, float] = (0.15, 0.8)) -> None:
        self.workspace_root = self._resolve_workspace(workspace_root)
        self.backup_dir = self.workspace_root / "evidence" / "forensics" / "backups"
        self.report_dir = self.workspace_root / "reports" / "blue_team"
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.jitter_range = (max(0.0, jitter_range[0]), max(jitter_range[0], jitter_range[1]))
        self.prompt = load_prompt_template("prompts/system_blue_team_agent.md")
        self.state = SessionState()
        self._finding_counter = 0
        self._action_counter = 0

    async def run_hunt_and_harden(
        self,
        *,
        targets: Sequence[str],
        config_paths: Sequence[str],
        log_paths: Sequence[str],
        max_cycles: int = 2,
        mission_reason: str = "Autonomous resilience cycle",
    ) -> Dict[str, Any]:
        started_at = datetime.now(tz=UTC)
        self.state = SessionState()

        for _ in range(max(1, int(max_cycles))):
            self.state.cycle_index += 1

            observed = await self._observe(targets=targets, log_paths=log_paths)
            await self._jitter()
            oriented = await self._orient(observed=observed, config_paths=config_paths)
            await self._jitter()
            decisions = await self._decide(oriented=oriented, mission_reason=mission_reason)
            await self._jitter()
            await self._act(decisions=decisions, targets=targets)

        report_path = self.report_dir / f"system_resilience_brief_{datetime.now(tz=UTC).strftime('%Y%m%dT%H%M%SZ')}.md"
        report_path.write_text(self._render_system_resilience_brief(), encoding="utf-8")

        return {
            "ok": True,
            "started_at": started_at.isoformat(),
            "ended_at": datetime.now(tz=UTC).isoformat(),
            "cycles": self.state.cycle_index,
            "findings": len(self.state.discovered_vulnerabilities),
            "fixes": len(self.state.applied_fixes),
            "report_path": str(report_path),
        }

    async def _observe(self, *, targets: Sequence[str], log_paths: Sequence[str]) -> Dict[str, Any]:
        findings: List[BlueTeamFinding] = []

        netstat_exec = await LINUX_COMMAND_TOOL.execute(command="netstat -tulnp", timeout_seconds=10)
        netstat_output = netstat_exec.get("stdout", "") if netstat_exec.get("ok") else str((netstat_exec.get("error") or {}).get("message", ""))
        findings.extend(self._extract_anomalies(text=str(netstat_output), source="netstat", phase="sentinel_discovery"))

        for target in targets:
            scan_result = NMAP_TOOL.scan(target=target, profile="BALANCED", timeout=120, reason="Blue team verification scan")
            findings.extend(self._extract_anomalies(text=json.dumps(scan_result, ensure_ascii=True), source=f"nmap:{target}", phase="sentinel_discovery"))

        for log_path in log_paths:
            read = FILESYSTEM_TOOL.read_file(file_path=log_path, max_bytes=80_000)
            if read.get("ok"):
                findings.extend(self._extract_anomalies(text=str(read.get("content", "")), source=f"read_file:{log_path}", phase="compromise_assessment"))

        self.state.discovered_vulnerabilities.extend(findings)
        return {"findings": findings, "netstat": netstat_output}

    async def _orient(self, *, observed: Dict[str, Any], config_paths: Sequence[str]) -> Dict[str, Any]:
        cfg_observations: List[Dict[str, Any]] = []
        for cfg in config_paths:
            out = await LINUX_COMMAND_TOOL.execute(command=f"cat {cfg}", timeout_seconds=20)
            cfg_observations.append({"path": cfg, "result": out})

        objective = f"Orient hardening priorities for cycle {self.state.cycle_index}"
        context = f"Findings count: {len(observed.get('findings', []))}; configs reviewed: {len(cfg_observations)}"
        strategy = REASONING_TOOL.reason(
            mode=MODE_STRATEGY,
            objective=objective,
            context=context,
            options=["prioritize active attack surface", "prioritize config drift"],
            fetch_facts=True,
            fact_query="system hardening",
        )
        return {"strategy": strategy, "configs": cfg_observations}

    async def _decide(self, *, oriented: Dict[str, Any], mission_reason: str) -> List[FixAction]:
        options = ["Apply least disruptive hardening", "Delay and observe"]
        critique = REASONING_TOOL.reason(
            mode=MODE_RISK_ASSESSMENT,
            objective=f"Decide tactical hardening plan for cycle {self.state.cycle_index}",
            context=f"Mission: {mission_reason}",
            options=options,
            fetch_facts=False,
        )

        actions: List[FixAction] = []
        recent_findings = self.state.discovered_vulnerabilities[-12:]
        for finding in recent_findings:
            maybe_fix = self._propose_fix_for_finding(finding)
            if maybe_fix:
                actions.append(maybe_fix)

        if not actions:
            self._action_counter += 1
            actions.append(
                FixAction(
                    action_id=f"fix-{self._action_counter:04d}",
                    kind="write_file",
                    target="hardening/sshd_hardening.conf",
                    content="PermitRootLogin no\nPasswordAuthentication no\nMaxAuthTries 3\n",
                    reason="No concrete fix candidate found; applying baseline SSH hardening profile.",
                )
            )

        if (critique.get("pivot_request") or {}).get("required"):
            actions = actions[:1]
        return actions

    async def _act(self, *, decisions: Sequence[FixAction], targets: Sequence[str]) -> None:
        for action in decisions:
            if action.kind == "write_file":
                applied = await self._apply_write_fix(action)
                self.state.applied_fixes.append(applied)
                await self._verification_turn(action=action, targets=targets)

    async def _apply_write_fix(self, action: FixAction) -> Dict[str, Any]:
        # Immutable Backup Protocol: read_file first, then persist backup in project evidence silo.
        original = FILESYSTEM_TOOL.read_file(file_path=action.target, max_bytes=250_000)
        ts = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%SZ")
        backup_path = self.backup_dir / f"{Path(action.target).name}.{ts}.bak"
        if original.get("ok"):
            backup_content = str(original.get("content", ""))
        else:
            backup_content = ""

        FILESYSTEM_TOOL.write_file(file_path=str(backup_path), content=backup_content, encoding="utf-8")
        write = FILESYSTEM_TOOL.write_file(file_path=action.target, content=action.content, encoding="utf-8")

        return {
            "action_id": action.action_id,
            "target": action.target,
            "backup_path": str(backup_path),
            "write_ok": bool(write.get("ok")),
            "reason": action.reason,
            "timestamp": datetime.now(tz=UTC).isoformat(),
        }

    async def _verification_turn(self, *, action: FixAction, targets: Sequence[str]) -> None:
        verification: Dict[str, Any] = {
            "action_id": action.action_id,
            "target": action.target,
            "verified_at": datetime.now(tz=UTC).isoformat(),
            "results": [],
        }
        for target in targets:
            result = NMAP_TOOL.scan(target=target, profile="STEALTH", timeout=120, reason=f"Verification after {action.action_id}")
            verification["results"].append({"target": target, "scan": result})
        health = await LINUX_COMMAND_TOOL.execute(command="ss -tuln", timeout_seconds=20)
        verification["results"].append({"health_check": health})
        self.state.verification_history.append(verification)

    def _extract_anomalies(self, *, text: str, source: str, phase: str) -> List[BlueTeamFinding]:
        patterns = (
            (r"0\.0\.0\.0:22|:::22", "SSH exposed on all interfaces", "Investigate"),
            (r"0\.0\.0\.0:2375|:::2375", "Docker daemon exposed without TLS", "Quarantine"),
            (r"(?:failed password|invalid user|authentication failure)", "Repeated authentication failures in logs", "Investigate"),
            (r"(?:nc\s+|ncat\s+|bash -c|curl\s+http)", "Potential command-and-control execution pattern", "Investigate"),
            (r"PermitRootLogin\s+yes", "Root SSH login enabled", "Quarantine"),
        )
        out: List[BlueTeamFinding] = []
        for pattern, threat, action_required in patterns:
            if re.search(pattern, text, flags=re.IGNORECASE):
                self._finding_counter += 1
                mitre = self._map_mitre(text)
                out.append(
                    BlueTeamFinding(
                        finding_id=f"CRIR-{self._finding_counter:04d}",
                        detected_threat=threat,
                        source=source,
                        evidence=self._trim(text),
                        mitre_attack_id=mitre,
                        confidence=0.78,
                        phase=phase,
                        action_required=action_required,
                    )
                )
        return out

    def _propose_fix_for_finding(self, finding: BlueTeamFinding) -> Optional[FixAction]:
        self._action_counter += 1
        aid = f"fix-{self._action_counter:04d}"
        if "Root SSH login enabled" in finding.detected_threat:
            return FixAction(
                action_id=aid,
                kind="write_file",
                target="hardening/sshd_hardening.conf",
                content="PermitRootLogin no\nPasswordAuthentication no\nChallengeResponseAuthentication no\n",
                reason="Disable high-risk SSH authentication settings.",
            )
        if "Docker daemon exposed" in finding.detected_threat:
            return FixAction(
                action_id=aid,
                kind="write_file",
                target="hardening/docker_daemon_hardening.json",
                content='{"hosts":["fd://"],"tls":true,"tlsverify":true}\n',
                reason="Reduce exposed Docker attack surface.",
            )
        if "authentication failures" in finding.detected_threat.lower():
            return FixAction(
                action_id=aid,
                kind="write_file",
                target="hardening/fail2ban_jail.local",
                content="[sshd]\nenabled=true\nmaxretry=3\nbantime=3600\n",
                reason="Throttle brute-force attempts and preserve service availability.",
            )
        return None

    def _map_mitre(self, text: str) -> str:
        lowered = text.lower()
        for pattern, tech_id in MITRE_MAP:
            if re.search(pattern, lowered, flags=re.IGNORECASE):
                return tech_id
        return "T1595"

    async def _jitter(self) -> None:
        delay = random.uniform(self.jitter_range[0], self.jitter_range[1])
        await asyncio.sleep(delay)

    def _render_system_resilience_brief(self) -> str:
        hardening_before = max(0, len(self.state.discovered_vulnerabilities) - len(self.state.applied_fixes))
        hardening_after = max(0, hardening_before - len(self.state.verification_history))

        lines = [
            "### System Resilience Brief",
            "| Attribute | Value |",
            "| :--- | :--- |",
            f"| System ID | workspace:{self.workspace_root.name} |",
            f"| Phase Completed | 4 |",
            f"| Detected Threat | {len(self.state.discovered_vulnerabilities)} total anomalies |",
            f"| MITRE ATT&CK ID | {', '.join(sorted({f.mitre_attack_id for f in self.state.discovered_vulnerabilities}) or {'T1595'})} |",
            f"| Action Taken | {len(self.state.applied_fixes)} fix actions applied |",
            f"| Evidence Location | {self.backup_dir} |",
            f"| Hardening Score | {hardening_before} -> {hardening_after} |",
            f"| Forensic Hash | N/A (file-level hashes can be derived from backup artifacts) |",
            "",
            "### Findings",
        ]
        for finding in self.state.discovered_vulnerabilities:
            lines.append(f"- {finding.finding_id}: {finding.detected_threat} [{finding.mitre_attack_id}] from {finding.source}")
        lines.append("")
        lines.append("### Applied Fixes")
        for fix in self.state.applied_fixes:
            lines.append(f"- {fix['action_id']}: target={fix['target']} backup={fix['backup_path']} write_ok={fix['write_ok']}")
        lines.append("")
        lines.append("### Verification")
        for verification in self.state.verification_history:
            lines.append(f"- action={verification['action_id']} checks={len(verification['results'])}")
        return "\n".join(lines) + "\n"

    @staticmethod
    def _trim(text: str, max_chars: int = 500) -> str:
        data = (text or "").strip()
        if len(data) <= max_chars:
            return data
        return data[: max_chars - 20] + " ...[truncated]"

    @staticmethod
    def _resolve_workspace(workspace_root: Optional[str]) -> Path:
        if workspace_root:
            return Path(workspace_root).expanduser().resolve()
        try:
            return get_project_space().ensure_initialized().resolve()
        except Exception:
            return Path.cwd().resolve()


load_dotenv()
blueteam_agent_system_prompt = load_prompt_template("prompts/system_blue_team_agent.md")
_tools = []
for _meta in get_all_tools():
    if not getattr(_meta, "enabled", False):
        continue
    try:
        _tools.append(get_tool(_meta.name))
    except Exception:
        continue


blueteam_agent = Agent(
    name="Blue Team Agent",
    instructions=create_system_prompt_renderer(blueteam_agent_system_prompt),
    description="Agent that specializes in autonomous system defense and resilience operations.",
    model=OpenAIChatCompletionsModel(
        model=os.getenv("CERBERUS_MODEL", "cerebro1"),
        openai_client=AsyncOpenAI(),
    ),
    tools=_tools,
)


cerebro_blue_team_agent = CerebroBlueTeamAgent()


__all__ = [
    "CerebroBlueTeamAgent",
    "SessionState",
    "BlueTeamFinding",
    "FixAction",
    "cerebro_blue_team_agent",
    "blueteam_agent",
]
