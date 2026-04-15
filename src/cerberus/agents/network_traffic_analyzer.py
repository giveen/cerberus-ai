"""Cerebro Protocol Intelligence Engine (CPIE).

Autonomous network traffic analyst with a stateful DPI loop:
Capture -> Stream Reassembly -> Protocol Decoding -> Anomaly Detection.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import re
from shlex import quote as shlex_quote
from typing import Any, Dict, List, Mapping, Optional, Sequence
from uuid import uuid4

from dotenv import load_dotenv
from openai import AsyncOpenAI

from cerberus.agents.dfir import cerebro_dfir_orchestrator
from cerberus.memory.logic import clean_data
from cerberus.sdk.agents import Agent, OpenAIChatCompletionsModel
from cerberus.tools.all_tools import get_all_tools, get_tool
from cerberus.tools.misc.reasoning import MODE_CRITIQUE, MODE_STRATEGY, REASONING_TOOL
from cerberus.tools.reconnaissance.exec_code import EXEC_TOOL
from cerberus.tools.reconnaissance.filesystem import FILESYSTEM_TOOL
from cerberus.tools.reconnaissance.generic_linux_command import LINUX_COMMAND_TOOL
from cerberus.tools.workspace import get_project_space
from cerberus.util import create_system_prompt_renderer, load_prompt_template


@dataclass
class ReassembledStream:
    stream_id: str
    protocol: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    packet_count: int
    total_bytes: int
    first_ts: float
    last_ts: float
    payload_sample: str
    payload_path: str = ""
    payload_sha256: str = ""


@dataclass
class AnomalyFinding:
    finding_id: str
    category: str
    confidence: int
    src_ip: str
    dst_ip: str
    protocol: str
    stream_id: str
    explanation: str
    critique_note: str
    action_required: str
    evidence_path: str
    evidence_sha256: str


@dataclass
class AnalysisState:
    session_id: str
    phase: str = "Capture"
    capture_path: str = ""
    reassembled_streams: List[ReassembledStream] = field(default_factory=list)
    protocol_rows: List[Dict[str, Any]] = field(default_factory=list)
    signature_hits: List[Dict[str, Any]] = field(default_factory=list)
    anomalies: List[AnomalyFinding] = field(default_factory=list)
    timeline: List[Dict[str, Any]] = field(default_factory=list)


class CerebroProtocolIntelligenceAgent:
    """Commercial-grade autonomous protocol intelligence engine."""

    def __init__(self, *, workspace_root: Optional[str] = None) -> None:
        self.workspace_root = self._resolve_workspace(workspace_root)
        self.evidence_root = (self.workspace_root / "evidence" / "network_traffic").resolve()
        self.report_root = (self.workspace_root / "reports" / "forensics").resolve()
        self.evidence_root.mkdir(parents=True, exist_ok=True)
        self.report_root.mkdir(parents=True, exist_ok=True)
        self.prompt = self._load_prompt()

    async def analyze_network_traffic(
        self,
        *,
        capture_file: Optional[str] = None,
        interface: Optional[str] = None,
        packet_limit: int = 5000,
        capture_seconds: int = 30,
    ) -> Dict[str, Any]:
        state = AnalysisState(session_id=datetime.now(tz=UTC).strftime("CPIE_%Y%m%dT%H%M%S"))

        phase_order = [
            "Capture",
            "Stream Reassembly",
            "Protocol Decoding",
            "Anomaly Detection",
        ]

        for phase in phase_order:
            state.phase = phase
            if phase == "Capture":
                result = await self._phase_capture(
                    state=state,
                    capture_file=capture_file,
                    interface=interface,
                    packet_limit=packet_limit,
                    capture_seconds=capture_seconds,
                )
            elif phase == "Stream Reassembly":
                result = self._phase_stream_reassembly(state=state)
            elif phase == "Protocol Decoding":
                result = await self._phase_protocol_decoding(state=state)
            else:
                result = await self._phase_anomaly_detection(state=state)

            if not result.get("ok"):
                return clean_data(result)

        timeline_path = self.report_root / f"network_timeline_{state.session_id}.json"
        timeline_path.write_text(json.dumps(state.timeline, ensure_ascii=True, indent=2), encoding="utf-8")

        report = self._render_forensic_artifact_template(state)
        report_path = self.report_root / f"network_forensic_artifacts_{state.session_id}.md"
        report_path.write_text(report, encoding="utf-8")

        return clean_data(
            {
                "ok": True,
                "session_id": state.session_id,
                "capture_path": state.capture_path,
                "stream_count": len(state.reassembled_streams),
                "signature_hits": len(state.signature_hits),
                "malicious_findings": len(state.anomalies),
                "timeline_path": str(timeline_path),
                "report_path": str(report_path),
                "forensic_artifact_template": report,
            }
        )

    async def _phase_capture(
        self,
        *,
        state: AnalysisState,
        capture_file: Optional[str],
        interface: Optional[str],
        packet_limit: int,
        capture_seconds: int,
    ) -> Dict[str, Any]:
        REASONING_TOOL.reason(
            mode=MODE_STRATEGY,
            objective="Initialize packet acquisition plan",
            context=f"capture_file={capture_file or 'none'} interface={interface or 'none'}",
            options=["offline-pcap", "live-capture", "hybrid"],
            fetch_facts=False,
        )

        if capture_file:
            digest = FILESYSTEM_TOOL.get_file_hash(file_path=capture_file, algorithm="sha256")
            if not digest.get("ok"):
                return digest
            state.capture_path = capture_file
            state.timeline.append(
                {
                    "timestamp": datetime.now(tz=UTC).isoformat(),
                    "phase": state.phase,
                    "event": f"using supplied pcap sha256={digest.get('sha256', '')}",
                }
            )
            return {"ok": True}

        if not interface:
            return {"ok": False, "error": {"message": "capture_file or interface is required"}}

        out_path = self.evidence_root / f"capture_{state.session_id}.pcap"
        safe_iface = shlex_quote(interface)
        safe_out = shlex_quote(str(out_path))
        cmd = (
            f"timeout {max(5, int(capture_seconds))} "
            f"tcpdump -ni {safe_iface} -w {safe_out} -c {max(100, int(packet_limit))}"
        )
        capture = await LINUX_COMMAND_TOOL.execute(command=cmd, timeout_seconds=max(15, int(capture_seconds) + 20))
        if not capture.get("ok"):
            return capture

        state.capture_path = str(out_path)
        state.timeline.append(
            {
                "timestamp": datetime.now(tz=UTC).isoformat(),
                "phase": state.phase,
                "event": f"captured traffic on interface={interface}",
            }
        )
        return {"ok": True}

    def _phase_stream_reassembly(self, *, state: AnalysisState) -> Dict[str, Any]:
        strategy = REASONING_TOOL.reason(
            mode=MODE_STRATEGY,
            objective="Reassemble stateful TCP/UDP streams from packet capture",
            context=state.capture_path,
            options=["scapy-stream-ordering", "pyshark-conversation-merge"],
            fetch_facts=False,
        )
        state.timeline.append(
            {
                "timestamp": datetime.now(tz=UTC).isoformat(),
                "phase": state.phase,
                "event": strategy.get("summary", "stream reassembly strategy selected"),
            }
        )

        script = self._stream_reassembly_script(state.capture_path)
        parsed = EXEC_TOOL.execute(
            code=script,
            language="python",
            filename="cpie_stream_reassembly",
            timeout=35,
            persist=False,
        )
        if not parsed.get("ok"):
            return parsed

        raw = str((parsed.get("record") or {}).get("output", "") or "")
        payload = self._parse_json_tail(raw)
        if payload is None:
            return {"ok": False, "error": {"message": "stream reassembly produced invalid output"}}

        for row in list(payload.get("streams") or [])[:500]:
            stream = ReassembledStream(
                stream_id=str(row.get("stream_id", "unknown")),
                protocol=str(row.get("protocol", "unknown")),
                src_ip=str(row.get("src_ip", "")),
                src_port=int(row.get("src_port", 0) or 0),
                dst_ip=str(row.get("dst_ip", "")),
                dst_port=int(row.get("dst_port", 0) or 0),
                packet_count=int(row.get("packet_count", 0) or 0),
                total_bytes=int(row.get("total_bytes", 0) or 0),
                first_ts=float(row.get("first_ts", 0.0) or 0.0),
                last_ts=float(row.get("last_ts", 0.0) or 0.0),
                payload_sample=str(row.get("payload_sample", "")),
            )

            payload_path, payload_sha = self._silo_stream_payload(state=state, stream=stream)
            stream.payload_path = payload_path
            stream.payload_sha256 = payload_sha
            state.reassembled_streams.append(stream)

        return {"ok": True}

    async def _phase_protocol_decoding(self, *, state: AnalysisState) -> Dict[str, Any]:
        signature_hits = self._signature_first_detection(state.reassembled_streams)
        state.signature_hits.extend(signature_hits)

        safe_path = shlex_quote(state.capture_path)
        tshark_cmd = (
            "tshark -r "
            f"{safe_path} "
            "-T fields -E separator='|' "
            "-e frame.time_epoch -e ip.src -e ip.dst -e tcp.dstport -e udp.dstport "
            "-e _ws.col.Protocol -e dns.qry.name -e http.host -e http.request.uri"
        )
        tshark = await LINUX_COMMAND_TOOL.execute(command=tshark_cmd, timeout_seconds=30)
        if tshark.get("ok"):
            rows = str(tshark.get("stdout", "")).splitlines()
            state.protocol_rows = self._decode_tshark_rows(rows)

        script = self._protocol_decode_script(state.capture_path)
        decoded = EXEC_TOOL.execute(
            code=script,
            language="python",
            filename="cpie_protocol_decode",
            timeout=30,
            persist=False,
        )
        if decoded.get("ok"):
            raw = str((decoded.get("record") or {}).get("output", "") or "")
            obj = self._parse_json_tail(raw)
            if obj and isinstance(obj.get("rows"), list):
                for row in obj["rows"][:1500]:
                    state.protocol_rows.append(dict(row))

        state.timeline.append(
            {
                "timestamp": datetime.now(tz=UTC).isoformat(),
                "phase": state.phase,
                "event": f"protocol rows decoded={len(state.protocol_rows)} signature_hits={len(state.signature_hits)}",
            }
        )
        return {"ok": True}

    async def _phase_anomaly_detection(self, *, state: AnalysisState) -> Dict[str, Any]:
        heuristic_findings = self._detect_c2_beaconing(state)
        heuristic_findings.extend(self._detect_data_exfiltration(state))
        heuristic_findings.extend(self._detect_protocol_skew(state))

        confirmed: List[AnomalyFinding] = []
        for candidate in heuristic_findings:
            # Signature-confirmed findings bypass heavy critique only when confidence is already very high.
            if candidate.get("signature_confirmed") and int(candidate.get("confidence", 0)) >= 90:
                verdict = "malicious"
                critique_note = "Signature-first high-confidence detection accepted."
            else:
                verdict, critique_note = self._critique_candidate(state=state, candidate=candidate)

            if verdict != "malicious":
                continue

            evidence_path, evidence_sha = self._silo_suspicious_slice(state=state, candidate=candidate)
            finding = AnomalyFinding(
                finding_id=f"NET-{uuid4().hex[:12].upper()}",
                category=str(candidate.get("category", "network_anomaly")),
                confidence=int(candidate.get("confidence", 0) or 0),
                src_ip=str(candidate.get("src_ip", "")),
                dst_ip=str(candidate.get("dst_ip", "")),
                protocol=str(candidate.get("protocol", "unknown")),
                stream_id=str(candidate.get("stream_id", "unknown")),
                explanation=str(candidate.get("explanation", "")),
                critique_note=critique_note,
                action_required="Investigate",
                evidence_path=evidence_path,
                evidence_sha256=evidence_sha,
            )
            state.anomalies.append(finding)
            confirmed.append(finding)

        await self._run_snort_signature_sweep(state)
        await self._handoff_exfiltration_streams(state, confirmed)

        state.timeline.append(
            {
                "timestamp": datetime.now(tz=UTC).isoformat(),
                "phase": state.phase,
                "event": f"malicious findings confirmed={len(state.anomalies)}",
            }
        )
        return {"ok": True}

    def _signature_first_detection(self, streams: Sequence[ReassembledStream]) -> List[Dict[str, Any]]:
        signatures = [
            ("c2_indicator", re.compile(r"(?i)(/beacon|/heartbeat|cmd=ping|x-c2|powershell\\s+-enc)")),
            ("exfil_pattern", re.compile(r"(?i)(/upload|/sync|multipart/form-data|dns\\s*txt|base64)")),
            ("known_malware_string", re.compile(r"(?i)(cobaltstrike|metasploit|mimikatz|sliver)")),
        ]
        hits: List[Dict[str, Any]] = []
        for stream in streams:
            sample = stream.payload_sample[:20000]
            for sig_name, pattern in signatures:
                if pattern.search(sample):
                    hits.append(
                        {
                            "signature": sig_name,
                            "stream_id": stream.stream_id,
                            "src_ip": stream.src_ip,
                            "dst_ip": stream.dst_ip,
                            "protocol": stream.protocol,
                            "confidence": 92,
                        }
                    )
        return hits

    def _detect_c2_beaconing(self, state: AnalysisState) -> List[Dict[str, Any]]:
        grouped: Dict[tuple[str, str, str], List[ReassembledStream]] = {}
        for stream in state.reassembled_streams:
            key = (stream.src_ip, stream.dst_ip, stream.protocol)
            grouped.setdefault(key, []).append(stream)

        findings: List[Dict[str, Any]] = []
        for (src_ip, dst_ip, protocol), streams in grouped.items():
            if len(streams) < 4:
                continue
            streams_sorted = sorted(streams, key=lambda item: item.first_ts)
            intervals: List[float] = []
            for idx in range(1, len(streams_sorted)):
                intervals.append(max(0.0, streams_sorted[idx].first_ts - streams_sorted[idx - 1].first_ts))
            if not intervals:
                continue
            mean = sum(intervals) / len(intervals)
            variance = sum((x - mean) ** 2 for x in intervals) / max(1, len(intervals))
            jitter = variance**0.5
            low_volume = all(item.total_bytes < 2500 for item in streams_sorted[: min(12, len(streams_sorted))])
            if low_volume and mean > 5 and jitter < (mean * 0.25):
                seed_stream = streams_sorted[0]
                findings.append(
                    {
                        "category": "c2_beaconing",
                        "confidence": 84,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "protocol": protocol,
                        "stream_id": seed_stream.stream_id,
                        "signature_confirmed": self._stream_has_signature(state, seed_stream.stream_id),
                        "explanation": f"Periodic low-volume traffic with mean interval {mean:.2f}s and low jitter.",
                    }
                )
        return findings

    def _detect_data_exfiltration(self, state: AnalysisState) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        if not state.reassembled_streams:
            return findings

        outbound_by_src: Dict[str, int] = {}
        for stream in state.reassembled_streams:
            outbound_by_src[stream.src_ip] = outbound_by_src.get(stream.src_ip, 0) + stream.total_bytes

        baseline = sum(outbound_by_src.values()) / max(1, len(outbound_by_src))
        for stream in state.reassembled_streams:
            non_standard = stream.dst_port not in {53, 80, 443, 22, 123}
            dns_tunnel_hint = "=" in stream.payload_sample and stream.dst_port == 53 and len(stream.payload_sample) > 900
            burst = stream.total_bytes > max(200_000, int(baseline * 2.5))
            if burst and (non_standard or dns_tunnel_hint):
                confidence = 88 if non_standard else 80
                findings.append(
                    {
                        "category": "data_exfiltration",
                        "confidence": confidence,
                        "src_ip": stream.src_ip,
                        "dst_ip": stream.dst_ip,
                        "protocol": stream.protocol,
                        "stream_id": stream.stream_id,
                        "signature_confirmed": self._stream_has_signature(state, stream.stream_id),
                        "explanation": "Outbound volume spike over non-standard channel or DNS-encapsulated payload.",
                    }
                )
        return findings

    def _detect_protocol_skew(self, state: AnalysisState) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for stream in state.reassembled_streams:
            sample = stream.payload_sample.lower()
            if "ssh-" in sample and stream.dst_port not in {22, 2222}:
                findings.append(
                    {
                        "category": "protocol_skew",
                        "confidence": 78,
                        "src_ip": stream.src_ip,
                        "dst_ip": stream.dst_ip,
                        "protocol": stream.protocol,
                        "stream_id": stream.stream_id,
                        "signature_confirmed": False,
                        "explanation": f"SSH protocol markers observed on unauthorized port {stream.dst_port}.",
                    }
                )
            if any(tok in sample for tok in ("http/1.1", "host:", "user-agent:")) and stream.dst_port not in {80, 443, 8080, 8443}:
                findings.append(
                    {
                        "category": "protocol_skew",
                        "confidence": 74,
                        "src_ip": stream.src_ip,
                        "dst_ip": stream.dst_ip,
                        "protocol": stream.protocol,
                        "stream_id": stream.stream_id,
                        "signature_confirmed": False,
                        "explanation": f"HTTP semantics observed over atypical destination port {stream.dst_port}.",
                    }
                )
        return findings

    def _critique_candidate(self, *, state: AnalysisState, candidate: Mapping[str, Any]) -> tuple[str, str]:
        context = json.dumps(clean_data(candidate), ensure_ascii=True)
        critique = REASONING_TOOL.reason(
            mode=MODE_CRITIQUE,
            objective="Validate suspected malicious connection and exclude legitimate high-volume services",
            context=context,
            prior_output=json.dumps([asdict(a) for a in state.anomalies[-20:]], ensure_ascii=True),
            options=[
                "cloud backup service",
                "software update distribution",
                "content delivery synchronization",
                "malicious traffic",
            ],
            fetch_facts=False,
        )

        summary = str(critique.get("summary", "")).lower()
        if any(term in summary for term in ("backup", "update", "content delivery")):
            return "benign", "Critique indicates likely legitimate high-volume service."

        pivot = critique.get("pivot_request") or {}
        if pivot.get("required"):
            return "benign", "Critique requested deterministic pivot; malicious claim withheld."

        return "malicious", "MODE_CRITIQUE did not identify benign high-volume service explanation."

    async def _run_snort_signature_sweep(self, state: AnalysisState) -> None:
        safe_path = shlex_quote(state.capture_path)
        snort_cmd = f"snort -r {safe_path} -A console -q"
        result = await LINUX_COMMAND_TOOL.execute(command=snort_cmd, timeout_seconds=25)
        if result.get("ok"):
            stdout = str(result.get("stdout", "") or "")
            if stdout.strip():
                state.timeline.append(
                    {
                        "timestamp": datetime.now(tz=UTC).isoformat(),
                        "phase": "Anomaly Detection",
                        "event": "snort signature sweep produced alerts",
                    }
                )

    async def _handoff_exfiltration_streams(self, state: AnalysisState, findings: Sequence[AnomalyFinding]) -> None:
        exfil_paths = [item.evidence_path for item in findings if item.category == "data_exfiltration"]
        if not exfil_paths:
            return
        try:
            handoff = await cerebro_dfir_orchestrator.investigate(
                triage_paths=exfil_paths,
                log_paths=[state.capture_path],
                scan_root=".",
            )
            state.timeline.append(
                {
                    "timestamp": datetime.now(tz=UTC).isoformat(),
                    "phase": "Anomaly Detection",
                    "event": f"dfir_handoff={handoff.get('session_id', 'unknown')}",
                }
            )
        except Exception as exc:
            state.timeline.append(
                {
                    "timestamp": datetime.now(tz=UTC).isoformat(),
                    "phase": "Anomaly Detection",
                    "event": f"dfir_handoff_failed={type(exc).__name__}",
                }
            )

    def _silo_stream_payload(self, *, state: AnalysisState, stream: ReassembledStream) -> tuple[str, str]:
        payload_path = self.evidence_root / f"stream_{state.session_id}_{stream.stream_id}.txt"
        metadata = {
            "session_id": state.session_id,
            "stream_id": stream.stream_id,
            "src_ip": stream.src_ip,
            "src_port": stream.src_port,
            "dst_ip": stream.dst_ip,
            "dst_port": stream.dst_port,
            "protocol": stream.protocol,
            "packet_count": stream.packet_count,
            "total_bytes": stream.total_bytes,
            "payload_sample": stream.payload_sample,
        }
        payload_path.write_text(json.dumps(clean_data(metadata), ensure_ascii=True, indent=2), encoding="utf-8")
        sha = hashlib.sha256(payload_path.read_bytes()).hexdigest()
        return str(payload_path), sha

    def _silo_suspicious_slice(self, *, state: AnalysisState, candidate: Mapping[str, Any]) -> tuple[str, str]:
        item_id = str(candidate.get("stream_id", uuid4().hex[:8]))
        ev_path = self.evidence_root / f"slice_{state.session_id}_{item_id}.json"
        row = {
            "captured_at": datetime.now(tz=UTC).isoformat(),
            "source_capture": state.capture_path,
            "category": candidate.get("category"),
            "confidence": candidate.get("confidence"),
            "src_ip": candidate.get("src_ip"),
            "dst_ip": candidate.get("dst_ip"),
            "protocol": candidate.get("protocol"),
            "stream_id": candidate.get("stream_id"),
            "explanation": candidate.get("explanation"),
        }
        ev_path.write_text(json.dumps(clean_data(row), ensure_ascii=True, indent=2), encoding="utf-8")
        sha = hashlib.sha256(ev_path.read_bytes()).hexdigest()
        return str(ev_path), sha

    def _decode_tshark_rows(self, rows: Sequence[str]) -> List[Dict[str, Any]]:
        decoded: List[Dict[str, Any]] = []
        for line in rows[:3000]:
            parts = line.split("|")
            if len(parts) < 9:
                continue
            decoded.append(
                {
                    "time_epoch": parts[0],
                    "src_ip": parts[1],
                    "dst_ip": parts[2],
                    "tcp_dst_port": parts[3],
                    "udp_dst_port": parts[4],
                    "protocol": parts[5],
                    "dns_query": parts[6],
                    "http_host": parts[7],
                    "http_uri": parts[8],
                }
            )
        return decoded

    def _stream_has_signature(self, state: AnalysisState, stream_id: str) -> bool:
        return any(item.get("stream_id") == stream_id for item in state.signature_hits)

    @staticmethod
    def _parse_json_tail(output: str) -> Optional[Dict[str, Any]]:
        lines = [line for line in output.splitlines() if line.strip()]
        for line in reversed(lines):
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    return obj
            except json.JSONDecodeError:
                continue
        return None

    def _render_forensic_artifact_template(self, state: AnalysisState) -> str:
        primary = state.anomalies[0] if state.anomalies else None
        confidence = primary.confidence if primary else 0
        critique = primary.critique_note if primary else "No malicious finding confirmed after critique gate."
        action = "Investigate" if primary else "Ignore"
        category = primary.category if primary else "network_observation"

        lines = [
            "### Forensic Artifact Report",
            "| Attribute | Value |",
            "| :--- | :--- |",
            f"| **Artifact ID** | `{state.session_id}` |",
            "| **Phase** | `4` |",
            "| **Process ID (PID)** | `N/A` |",
            "| **Memory Offset** | `N/A` |",
            f"| **Data Type** | `{category}` |",
            f"| **Confidence Score** | `{confidence}%` |",
            f"| **Critique Note** | `{critique.replace('|', '/')}` |",
            f"| **Action Required** | `{action}` |",
            "",
            "### Network Findings",
        ]
        if not state.anomalies:
            lines.append("- No malicious connection was confirmed after MODE_CRITIQUE checks.")
        else:
            for finding in state.anomalies[:120]:
                lines.append(
                    "- "
                    f"{finding.finding_id} | {finding.category} | {finding.src_ip}:{finding.protocol} -> {finding.dst_ip} "
                    f"| confidence={finding.confidence}% | evidence={finding.evidence_path} | sha256={finding.evidence_sha256}"
                )

        lines.append("")
        lines.append("### Timeline")
        for event in state.timeline[:120]:
            lines.append(
                f"- [{event.get('timestamp', '')}] phase={event.get('phase', '')} :: {event.get('event', '')}"
            )
        return "\n".join(lines) + "\n"

    @staticmethod
    def _stream_reassembly_script(capture_path: str) -> str:
        return (
            "import json\n"
            "from collections import defaultdict\n"
            f"pcap_path={capture_path!r}\n"
            "streams=defaultdict(lambda:{'frames':[]})\n"
            "def push(proto,src,sport,dst,dport,ts,payload,seq):\n"
            "    sid=f'{proto}:{src}:{sport}->{dst}:{dport}'\n"
            "    streams[sid]['proto']=proto\n"
            "    streams[sid]['src']=src\n"
            "    streams[sid]['sport']=int(sport or 0)\n"
            "    streams[sid]['dst']=dst\n"
            "    streams[sid]['dport']=int(dport or 0)\n"
            "    streams[sid]['frames'].append({'ts':float(ts or 0.0),'seq':int(seq or 0),'payload':bytes(payload or b'')})\n"
            "try:\n"
            "    from scapy.all import rdpcap, IP, TCP, UDP, Raw\n"
            "    packets=rdpcap(pcap_path)\n"
            "    for pkt in packets:\n"
            "        if IP not in pkt:\n"
            "            continue\n"
            "        ts=float(getattr(pkt,'time',0.0) or 0.0)\n"
            "        ip=pkt[IP]\n"
            "        if TCP in pkt:\n"
            "            tcp=pkt[TCP]\n"
            "            payload=bytes(pkt[Raw]) if Raw in pkt else b''\n"
            "            push('TCP', ip.src, tcp.sport, ip.dst, tcp.dport, ts, payload, int(getattr(tcp,'seq',0) or 0))\n"
            "        elif UDP in pkt:\n"
            "            udp=pkt[UDP]\n"
            "            payload=bytes(pkt[Raw]) if Raw in pkt else b''\n"
            "            push('UDP', ip.src, udp.sport, ip.dst, udp.dport, ts, payload, 0)\n"
            "except Exception:\n"
            "    import pyshark\n"
            "    cap=pyshark.FileCapture(pcap_path, keep_packets=False, use_json=True, include_raw=False)\n"
            "    for pkt in cap:\n"
            "        try:\n"
            "            proto='TCP' if hasattr(pkt,'tcp') else ('UDP' if hasattr(pkt,'udp') else None)\n"
            "            if not proto:\n"
            "                continue\n"
            "            src=str(pkt.ip.src)\n"
            "            dst=str(pkt.ip.dst)\n"
            "            sport=int(pkt[pkt.transport_layer].srcport)\n"
            "            dport=int(pkt[pkt.transport_layer].dstport)\n"
            "            ts=float(pkt.sniff_timestamp)\n"
            "            payload=b''\n"
            "            push(proto,src,sport,dst,dport,ts,payload,0)\n"
            "        except Exception:\n"
            "            continue\n"
            "result=[]\n"
            "for sid,data in streams.items():\n"
            "    frames=sorted(data['frames'], key=lambda x: (x['seq'], x['ts'])) if data['proto']=='TCP' else sorted(data['frames'], key=lambda x: x['ts'])\n"
            "    payload=b''.join(f['payload'] for f in frames)\n"
            "    result.append({\n"
            "        'stream_id': sid.replace(':','_').replace('>','').replace('/','_')[:140],\n"
            "        'protocol': data['proto'],\n"
            "        'src_ip': data['src'],\n"
            "        'src_port': data['sport'],\n"
            "        'dst_ip': data['dst'],\n"
            "        'dst_port': data['dport'],\n"
            "        'packet_count': len(frames),\n"
            "        'total_bytes': len(payload),\n"
            "        'first_ts': frames[0]['ts'] if frames else 0.0,\n"
            "        'last_ts': frames[-1]['ts'] if frames else 0.0,\n"
            "        'payload_sample': payload[:16384].decode('utf-8', errors='replace')\n"
            "    })\n"
            "print(json.dumps({'streams': result[:1000]}, ensure_ascii=True))\n"
        )

    @staticmethod
    def _protocol_decode_script(capture_path: str) -> str:
        return (
            "import json\n"
            f"pcap_path={capture_path!r}\n"
            "rows=[]\n"
            "try:\n"
            "    from scapy.all import rdpcap, DNSQR, HTTPRequest, IP, TCP, UDP\n"
            "    packets=rdpcap(pcap_path)\n"
            "    for pkt in packets:\n"
            "        if IP not in pkt:\n"
            "            continue\n"
            "        row={'src_ip':pkt[IP].src,'dst_ip':pkt[IP].dst,'protocol':'TCP' if TCP in pkt else ('UDP' if UDP in pkt else 'OTHER')}\n"
            "        if DNSQR in pkt:\n"
            "            row['dns_query']=bytes(pkt[DNSQR].qname).decode('utf-8', errors='replace').strip('.')\n"
            "        if HTTPRequest in pkt:\n"
            "            host=getattr(pkt[HTTPRequest], 'Host', b'')\n"
            "            path=getattr(pkt[HTTPRequest], 'Path', b'')\n"
            "            row['http_host']=host.decode('utf-8', errors='replace') if isinstance(host,(bytes,bytearray)) else str(host)\n"
            "            row['http_uri']=path.decode('utf-8', errors='replace') if isinstance(path,(bytes,bytearray)) else str(path)\n"
            "        rows.append(row)\n"
            "except Exception:\n"
            "    pass\n"
            "print(json.dumps({'rows': rows[:3000]}, ensure_ascii=True))\n"
        )

    def _load_prompt(self) -> str:
        try:
            return load_prompt_template("prompts/system_network_analyzer.md")
        except FileNotFoundError:
            return "You are Cerebro Protocol Intelligence Engine."

    @staticmethod
    def _resolve_workspace(workspace_root: Optional[str]) -> Path:
        if workspace_root:
            return Path(workspace_root).expanduser().resolve()
        try:
            return get_project_space().ensure_initialized().resolve()
        except Exception:
            return Path.cwd().resolve()


load_dotenv()
network_security_analyzer_prompt = load_prompt_template("prompts/system_network_analyzer.md")

_tools = []
for _meta in get_all_tools():
    if not getattr(_meta, "enabled", False):
        continue
    try:
        _tools.append(get_tool(_meta.name))
    except Exception:
        continue


network_security_analyzer_agent = Agent(
    name="Network Analyst (CPIE)",
    instructions=create_system_prompt_renderer(network_security_analyzer_prompt),
    description="High-speed protocol analysis and service fingerprinting specialist for transparent network auditing.",
    model=OpenAIChatCompletionsModel(
        model=os.getenv("CERBERUS_MODEL", "cerebro1"),
        openai_client=AsyncOpenAI(),
    ),
    tools=_tools,
)


cerebro_protocol_intelligence_agent = CerebroProtocolIntelligenceAgent()


__all__ = [
    "ReassembledStream",
    "AnomalyFinding",
    "AnalysisState",
    "CerebroProtocolIntelligenceAgent",
    "cerebro_protocol_intelligence_agent",
    "network_security_analyzer_agent",
]
