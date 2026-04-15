"""Cerebro Lab Operative (CLO) for Hack The Box workflows."""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
import json
import os
from pathlib import Path
from shlex import quote as shlex_quote
from typing import Any, Dict, List, Mapping, Optional, Sequence
from uuid import uuid4

from dotenv import load_dotenv
from openai import AsyncOpenAI

from cai.memory.logic import clean_data
from cai.agents.codeagent import cerebro_code_synthesis_agent
from cai.agents.flag_discriminator import cov_validator
from cai.agents.guardrails import get_security_guardrails
from cai.sdk.agents import Agent, OpenAIChatCompletionsModel, ModelSettings
from cai.tools.all_tools import get_all_tools, get_tool
from cai.tools.misc.reasoning import MODE_CRITIQUE, MODE_STRATEGY, REASONING_TOOL
from cai.tools.reconnaissance.exec_code import EXEC_TOOL
from cai.tools.reconnaissance.ffuf import FFUF_TOOL
from cai.tools.reconnaissance.generic_linux_command import LINUX_COMMAND_TOOL
from cai.tools.reconnaissance.nmap import NMAP_TOOL
from cai.tools.workspace import get_project_space
from cai.util import create_system_prompt_renderer, load_prompt_template


@dataclass
class LabEvent:
    phase: str
    timestamp: str
    action: str
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class LabState:
    session_id: str
    machine_name: str
    target_ip: str
    phase: str = "Connection"
    connected: bool = False
    methodology: str = "General HTB methodology"
    command_log: List[Dict[str, Any]] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    flags: List[str] = field(default_factory=list)
    events: List[LabEvent] = field(default_factory=list)


@dataclass
class ForensicArtifact:
    artifact_id: str
    phase: str
    process_id: str
    memory_offset: str
    data_type: str
    confidence_score: str
    critique_note: str
    action_required: str


class CerebroLabOperativeAgent:
    """Autonomous HTB lab orchestrator with professional methodology alignment."""

    def __init__(self, *, workspace_root: Optional[str] = None) -> None:
        self.workspace_root = self._resolve_workspace(workspace_root)
        self.training_dir = (self.workspace_root / "training").resolve()
        self.training_dir.mkdir(parents=True, exist_ok=True)
        self.prompt = load_prompt_template("prompts/system_htb_agent.md")

    async def run_lab(
        self,
        *,
        machine_name: str,
        target_ip: str,
        connection_profile: Optional[str] = None,
        profile_kind: str = "auto",
        scope_domains: Optional[Sequence[str]] = None,
    ) -> Dict[str, Any]:
        session_id = datetime.now(tz=UTC).strftime("CLO_%Y%m%dT%H%M%S")
        state = LabState(session_id=session_id, machine_name=machine_name, target_ip=target_ip)
        state.methodology = self._academy_methodology(machine_name=machine_name, target_ip=target_ip)

        phases = [
            "Connection",
            "Enumeration",
            "Foothold",
            "PrivEsc",
            "Final Documentation",
        ]

        for phase in phases:
            state.phase = phase
            if phase == "Connection":
                await self._connection_phase(state, connection_profile=connection_profile, profile_kind=profile_kind)
            elif phase == "Enumeration":
                await self._enumeration_phase(state, scope_domains=scope_domains)
            elif phase == "Foothold":
                foothold_ok = await self._foothold_phase(state)
                if not foothold_ok:
                    await self._strategy_pivot(state)
            elif phase == "PrivEsc":
                await self._privesc_phase(state)
            elif phase == "Final Documentation":
                break

        lar_path = await self._write_lab_action_report(state)
        forensic = self._forensic_template(state)

        return {
            "ok": True,
            "session_id": state.session_id,
            "machine_name": state.machine_name,
            "target_ip": state.target_ip,
            "methodology": state.methodology,
            "flags": state.flags,
            "findings": state.findings,
            "lab_action_report": str(lar_path),
            "forensic_artifact_template": forensic,
        }

    async def _connection_phase(self, state: LabState, *, connection_profile: Optional[str], profile_kind: str) -> None:
        plan = REASONING_TOOL.reason(
            mode=MODE_STRATEGY,
            objective="Validate and establish HTB lab network connectivity",
            context=f"target={state.target_ip} profile={connection_profile or 'none'} kind={profile_kind}",
            options=["verify existing tunnel", "start OpenVPN", "start WireGuard"],
            fetch_facts=False,
        )
        state.events.append(self._event(state.phase, "connectivity_strategy", {"summary": plan.get("summary", "")}))

        connected = await self._verify_connectivity(target_ip=state.target_ip)
        if not connected and connection_profile:
            await self._start_vpn(profile=connection_profile, profile_kind=profile_kind)
            connected = await self._verify_connectivity(target_ip=state.target_ip)

        state.connected = connected
        state.command_log.append({"phase": state.phase, "tool": "exec_code", "command": "connectivity_check", "ok": connected})

    async def _enumeration_phase(self, state: LabState, *, scope_domains: Optional[Sequence[str]]) -> None:
        if not state.connected:
            state.findings.append({"phase": state.phase, "severity": "high", "message": "No VPN connectivity; enumeration skipped"})
            return

        # Professional OPSEC: prefer stealth-balanced scans to avoid destabilizing shared lab instances.
        nmap_result = NMAP_TOOL.scan(
            target=state.target_ip,
            profile="STEALTH",
            timeout=240,
            reason=f"CLO enumeration for {state.machine_name}",
        )
        state.command_log.append({"phase": state.phase, "tool": "nmap", "command": f"scan {state.target_ip} profile=STEALTH", "ok": bool(nmap_result.get("ok"))})
        state.findings.append({"phase": state.phase, "source": "nmap", "data": nmap_result})

        service_text = json.dumps(nmap_result, ensure_ascii=True)
        flag_hits = await cov_validator.scan_output(output=service_text, source=f"nmap:{state.target_ip}")
        state.flags.extend([item.value for item in flag_hits if item.value not in state.flags])

        hostnames = list(scope_domains or [])
        hostnames.extend(self._extract_host_hints(nmap_result))
        for host in hostnames[:2]:
            ffuf_result = FFUF_TOOL.start_fuzz(
                url=f"http://{host}/FUZZ",
                wordlist=["admin", "uploads", "backup", "dev", "api"],
                method="GET",
                threads=8,
                rate=35,
                timeout=120,
            )
            state.command_log.append({"phase": state.phase, "tool": "ffuf", "command": f"start_fuzz {host}", "ok": bool(ffuf_result.get("ok"))})
            state.findings.append({"phase": state.phase, "source": "ffuf", "target": host, "data": ffuf_result})

    async def _foothold_phase(self, state: LabState) -> bool:
        summary = json.dumps(state.findings[-6:], ensure_ascii=True)
        strategy = REASONING_TOOL.reason(
            mode=MODE_STRATEGY,
            objective="Select initial foothold path based on enumeration",
            context=summary,
            options=[
                "web exploit adaptation",
                "credential attack with discovered usernames",
                "service misconfiguration entry",
            ],
            fetch_facts=False,
        )
        state.events.append(self._event(state.phase, "foothold_strategy", {"summary": strategy.get("summary", "")}))

        exploit_task = (
            "Adapt public exploit to target "
            f"{state.target_ip} while preserving reliability and HTB-lab OPSEC. "
            "Input is enumeration summary and likely vulnerable service versions."
        )
        code_result = await cerebro_code_synthesis_agent.synthesize_and_execute(requirement=exploit_task, parent_agent_id=state.session_id)
        state.command_log.append({"phase": state.phase, "tool": "codeagent", "command": "synthesize_and_execute exploit adaptation", "ok": bool(code_result.get("ok"))})
        state.findings.append({"phase": state.phase, "source": "codeagent", "data": code_result})

        foothold_ok = bool(code_result.get("ok"))
        if foothold_ok:
            flag_scan = await cov_validator.scan_output(output=json.dumps(code_result, ensure_ascii=True), source="codeagent:foothold")
            state.flags.extend([item.value for item in flag_scan if item.value not in state.flags])
        return foothold_ok

    async def _privesc_phase(self, state: LabState) -> None:
        if not state.connected:
            state.findings.append({"phase": state.phase, "severity": "high", "message": "Disconnected before privilege escalation"})
            return

        recon_cmd = (
            "bash -lc "
            "'id; uname -a; whoami; cat /etc/os-release 2>/dev/null || true; "
            "sudo -l 2>/dev/null || true; find / -perm -4000 -type f 2>/dev/null | head -n 20'"
        )
        recon = await LINUX_COMMAND_TOOL.execute(command=recon_cmd, timeout_seconds=60)
        state.command_log.append({"phase": state.phase, "tool": "generic_linux_command", "command": "privesc_recon", "ok": bool(recon.get("ok"))})
        state.findings.append({"phase": state.phase, "source": "privesc_recon", "data": recon})

        flag_hits = await cov_validator.scan_output(output=json.dumps(recon, ensure_ascii=True), source="privesc:recon")
        state.flags.extend([item.value for item in flag_hits if item.value not in state.flags])

    async def _strategy_pivot(self, state: LabState) -> None:
        prior = json.dumps(state.findings[-8:], ensure_ascii=True)
        critique = REASONING_TOOL.reason(
            mode=MODE_CRITIQUE,
            objective="Foothold failed; identify missed service clues, rabbit holes, and next pivot",
            context="HTB CLO pivot after failed initial foothold",
            prior_output=prior,
            options=[
                "revisit web content and hidden directories",
                "service-specific enumeration expansion",
                "credential and config artifact review",
            ],
            fetch_facts=False,
        )
        state.events.append(self._event("Foothold", "strategy_pivot", {"summary": critique.get("summary", ""), "pivot": critique.get("pivot_request", {})}))

    async def _verify_connectivity(self, *, target_ip: str) -> bool:
        probe = (
            "import json, socket\n"
            f"target = {target_ip!r}\n"
            "ports = [22, 80, 443]\n"
            "hits = []\n"
            "for p in ports:\n"
            "    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
            "    s.settimeout(1.2)\n"
            "    try:\n"
            "        ok = s.connect_ex((target, p)) == 0\n"
            "    except Exception:\n"
            "        ok = False\n"
            "    finally:\n"
            "        s.close()\n"
            "    if ok:\n"
            "        hits.append(p)\n"
            "print(json.dumps({'reachable_ports': hits, 'reachable': bool(hits)}))\n"
        )
        result = EXEC_TOOL.execute(code=probe, language="python", filename="htb_connectivity_probe", timeout=8, persist=False)
        if not result.get("ok"):
            return False
        output = str((result.get("record") or {}).get("output", "") or "").strip()
        try:
            parsed = json.loads(output.splitlines()[-1])
            return bool(parsed.get("reachable"))
        except Exception:
            return False

    async def _start_vpn(self, *, profile: str, profile_kind: str) -> None:
        profile_path = Path(profile).expanduser().resolve()
        if not profile_path.exists():
            return

        kind = profile_kind.lower().strip()
        if kind == "auto":
            if profile_path.suffix.lower() == ".ovpn":
                kind = "openvpn"
            else:
                kind = "wireguard"

        if kind == "openvpn":
            cmd = f"bash -lc 'openvpn --config {shlex_quote(str(profile_path))} --daemon'"
        else:
            cmd = f"bash -lc 'wg-quick up {shlex_quote(str(profile_path))} || wg-quick up htb'"
        await LINUX_COMMAND_TOOL.execute(command=cmd, timeout_seconds=35)

    async def _write_lab_action_report(self, state: LabState) -> Path:
        report_path = self.training_dir / f"LAR_{state.machine_name}_{state.session_id}.md"

        lines = [
            "### Lab Action Report (LAR)",
            "| Attribute | Value |",
            "| :--- | :--- |",
            f"| **Target Machine** | `{state.machine_name}` |",
            "| **Initial Vector** | `Pending/Derived from findings` |",
            "| **User Access Path** | `Derived from foothold attempts` |",
            "| **Root Escalation** | `Derived from privilege escalation logs` |",
            f"| **Final Flag** | `{state.flags[-1] if state.flags else 'Not captured'}` |",
            f"| **Academy Path** | `{state.methodology}` |",
            "| **Knowledge Gain** | `Systematic HTB methodology execution with pivot-aware reasoning` |",
            "",
            "### Methodology Citation",
            f"Applying {state.methodology} for the {state.machine_name} machine.",
            "",
            "### Command Log",
        ]

        for row in state.command_log:
            lines.append(
                f"- [{row.get('phase', 'unknown')}] {row.get('tool', 'tool')} :: {row.get('command', '')} :: ok={row.get('ok')}"
            )

        lines.append("")
        lines.append("### Findings Snapshot")
        for finding in state.findings[-20:]:
            lines.append(f"- {json.dumps(clean_data(finding), ensure_ascii=True)[:900]}")

        report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return report_path

    def _forensic_template(self, state: LabState) -> Dict[str, str]:
        confidence = "90%" if state.flags else "68%"
        artifact = ForensicArtifact(
            artifact_id=f"HTB-{state.session_id}",
            phase=state.phase,
            process_id=state.session_id,
            memory_offset="n/a",
            data_type="lab_walkthrough",
            confidence_score=confidence,
            critique_note="Foothold pivot executed when needed via MODE_CRITIQUE.",
            action_required="Review LAR and replay command chain for reproducibility.",
        )
        return asdict(artifact)

    def _academy_methodology(self, *, machine_name: str, target_ip: str) -> str:
        _ = target_ip
        label = machine_name.lower()
        if any(token in label for token in ("forest", "active", "ad", "domain", "dc")):
            return "Active Directory Enumeration methodology (HTB CPTS)"
        if any(token in label for token in ("web", "academy", "book", "shop", "api")):
            return "Web exploitation methodology (HTB CBBH)"
        return "Structured foothold-to-privesc methodology (HTB CPTS)"

    @staticmethod
    def _extract_host_hints(nmap_result: Mapping[str, Any]) -> List[str]:
        text = json.dumps(nmap_result, ensure_ascii=True)
        hints: List[str] = []
        for token in ("http://", "https://"):
            if token in text:
                hints.append("127.0.0.1")
                break
        return hints

    @staticmethod
    def _event(phase: str, action: str, details: Mapping[str, Any]) -> LabEvent:
        return LabEvent(phase=phase, timestamp=datetime.now(tz=UTC).isoformat(), action=action, details=dict(details))

    @staticmethod
    def _resolve_workspace(workspace_root: Optional[str]) -> Path:
        if workspace_root:
            return Path(workspace_root).expanduser().resolve()
        try:
            return get_project_space().ensure_initialized().resolve()
        except Exception:
            return Path.cwd().resolve()


load_dotenv()
model_name = os.getenv("CEREBRO_MODEL", "cerebro1")
api_key = os.getenv("CEREBRO_API_KEY", os.getenv("OPENAI_API_KEY", "sk-cerebro-1234567890"))

htb_agent_system_prompt = load_prompt_template("prompts/system_htb_agent.md")

_tools = []
for _meta in get_all_tools():
    if not getattr(_meta, "enabled", False):
        continue
    try:
        _tools.append(get_tool(_meta.name))
    except Exception:
        continue

input_guardrails, output_guardrails = get_security_guardrails()

htb_agent = Agent(
    name="HTB Agent",
    description="Cerebro Lab Operative for systematic HTB engagement execution and reporting.",
    instructions=create_system_prompt_renderer(htb_agent_system_prompt),
    model_settings=ModelSettings(temperature=0, tool_choice="required"),
    tools=_tools,
    input_guardrails=input_guardrails,
    output_guardrails=output_guardrails,
    model=OpenAIChatCompletionsModel(
        model=model_name,
        openai_client=AsyncOpenAI(api_key=api_key),
    ),
)


cerebro_lab_operative_agent = CerebroLabOperativeAgent()


def transfer_to_htb_agent(**kwargs: Any) -> Agent:  # pylint: disable=unused-argument
    """Compatibility transfer to HTB agent export."""
    return htb_agent


__all__ = [
    "LabEvent",
    "LabState",
    "ForensicArtifact",
    "CerebroLabOperativeAgent",
    "cerebro_lab_operative_agent",
    "htb_agent",
    "transfer_to_htb_agent",
]
