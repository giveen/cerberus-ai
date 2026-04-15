"""Cerebro Forensic Memory Analyst (CFMA)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Sequence
from uuid import uuid4

from dotenv import load_dotenv
from openai import AsyncOpenAI

from cerberus.agents.bug_bounter import cerebro_vulnerability_researcher
from cerberus.memory.logic import clean_data
from cerberus.sdk.agents import Agent, OpenAIChatCompletionsModel
from cerberus.tools.all_tools import get_all_tools, get_tool
from cerberus.tools.misc.reasoning import MODE_CRITIQUE, MODE_STRATEGY, REASONING_TOOL
from cerberus.tools.reconnaissance.exec_code import EXEC_TOOL
from cerberus.tools.reconnaissance.filesystem import FILESYSTEM_TOOL
from cerberus.tools.workspace import get_project_space
from cerberus.util import create_system_prompt_renderer, load_prompt_template


@dataclass
class MemoryArtifact:
    artifact_id: str
    source_image: str
    extracted_path: str
    sha256: str
    category: str
    offset: int
    collected_at: str


@dataclass
class TimelineEvent:
    timestamp: str
    event_type: str
    source: str
    detail: str


@dataclass
class ForensicState:
    session_id: str
    phase: str = "Image Identification"
    image_path: str = ""
    image_sha256: str = ""
    slices: List[Dict[str, Any]] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    artifacts: List[MemoryArtifact] = field(default_factory=list)
    timeline: List[TimelineEvent] = field(default_factory=list)


class CerebroMemoryForensicsAgent:
    """Autonomous memory forensics orchestrator with lazy slice analysis."""

    def __init__(self, *, workspace_root: Optional[str] = None, slice_bytes: int = 262_144) -> None:
        self.workspace_root = self._resolve_workspace(workspace_root)
        self.evidence_root = (self.workspace_root / "evidence" / "forensics" / "memory_dumps").resolve()
        self.report_root = (self.workspace_root / "reports" / "forensics").resolve()
        self.evidence_root.mkdir(parents=True, exist_ok=True)
        self.report_root.mkdir(parents=True, exist_ok=True)
        self.slice_bytes = max(65_536, int(slice_bytes))
        self.prompt = self._load_prompt()

    async def analyze_memory_image(
        self,
        *,
        image_path: str,
        target_processes: Optional[Sequence[str]] = None,
        max_slices: int = 12,
    ) -> Dict[str, Any]:
        state = ForensicState(session_id=datetime.now(tz=UTC).strftime("CFMA_%Y%m%dT%H%M%S"))
        state.image_path = image_path

        # Phase 1: Image Identification
        state.phase = "Image Identification"
        identify = self._identify_image(state=state)
        if not identify.get("ok"):
            return identify

        # Phase 2: Artifact Triage
        state.phase = "Artifact Triage"
        triage = self._artifact_triage(state=state, max_slices=max_slices)
        if not triage.get("ok"):
            return triage

        # Phase 3: Thread Injection Discovery
        state.phase = "Thread Injection Discovery"
        discovery = self._thread_injection_discovery(
            state=state,
            target_processes=target_processes or ("lsass.exe", "explorer.exe", "svchost.exe"),
        )
        if not discovery.get("ok"):
            return discovery

        # Phase 4: Evidence Extraction
        state.phase = "Evidence Extraction"
        extraction = await self._evidence_extraction(state=state)
        if not extraction.get("ok"):
            return extraction

        timeline_path = self.report_root / f"memory_timeline_{state.session_id}.json"
        timeline_path.write_text(json.dumps([asdict(x) for x in state.timeline], ensure_ascii=True, indent=2), encoding="utf-8")

        report_path = self.report_root / f"memory_forensic_artifacts_{state.session_id}.md"
        report_path.write_text(self._render_forensic_template(state), encoding="utf-8")

        return {
            "ok": True,
            "session_id": state.session_id,
            "image_sha256": state.image_sha256,
            "finding_count": len(state.findings),
            "artifact_count": len(state.artifacts),
            "timeline_path": str(timeline_path),
            "report_path": str(report_path),
        }

    def _identify_image(self, *, state: ForensicState) -> Dict[str, Any]:
        strategy = REASONING_TOOL.reason(
            mode=MODE_STRATEGY,
            objective="Identify memory image baseline and acquisition integrity",
            context=state.image_path,
            options=["hash-first", "header-first", "hybrid"],
            fetch_facts=False,
        )
        state.findings.append({"phase": state.phase, "strategy": strategy})

        hash_info = FILESYSTEM_TOOL.get_file_hash(file_path=state.image_path, algorithm="sha256")
        if not hash_info.get("ok"):
            return hash_info
        state.image_sha256 = str(hash_info.get("sha256", ""))

        preview = FILESYSTEM_TOOL.read_file_preview(file_path=state.image_path, max_bytes=262144)
        if not preview.get("ok"):
            return preview
        state.findings.append({"phase": state.phase, "preview": preview.get("summary", "")})

        summary = str(preview.get("summary", ""))
        for event in self._extract_timestamps(summary, source="image_preview"):
            state.timeline.append(event)
        return {"ok": True}

    def _artifact_triage(self, *, state: ForensicState, max_slices: int) -> Dict[str, Any]:
        size_result = FILESYSTEM_TOOL.read_file_preview(file_path=state.image_path, max_bytes=1024)
        if not size_result.get("ok"):
            return size_result
        size = int(size_result.get("size", 0) or 0)
        if size <= 0:
            return {"ok": False, "error": {"message": "Unable to determine memory image size"}}

        slice_offsets = self._build_offsets(total_size=size, max_slices=max_slices)
        for offset in slice_offsets:
            chunk = self._lazy_slice_read(image_path=state.image_path, offset=offset, length=self.slice_bytes)
            if not chunk.get("ok"):
                continue
            state.slices.append({"offset": offset, "length": self.slice_bytes, "sample": chunk.get("sample", "")})

            sample_text = str(chunk.get("sample", ""))
            state.findings.extend(self._recognize_advanced_patterns(sample_text=sample_text, offset=offset))
            for event in self._extract_timestamps(sample_text, source=f"slice:{offset}"):
                state.timeline.append(event)
        return {"ok": True}

    def _thread_injection_discovery(self, *, state: ForensicState, target_processes: Sequence[str]) -> Dict[str, Any]:
        combined = json.dumps(state.slices[:8], ensure_ascii=True)
        process_list = ", ".join(target_processes)
        script = (
            "import json,re\n"
            f"blob={combined!r}\n"
            f"targets={list(target_processes)!r}\n"
            "hits=[]\n"
            "for proc in targets:\n"
            "    if proc.lower() in blob.lower():\n"
            "        hits.append({'process':proc,'indicator':'memory_reference'})\n"
            "for m in re.finditer(r'CreateRemoteThread|WriteProcessMemory|NtUnmapViewOfSection', blob, re.I):\n"
            "    hits.append({'process':'unknown','indicator':m.group(0)})\n"
            "print(json.dumps({'hits':hits[:50]}))\n"
        )
        parsed = EXEC_TOOL.execute(code=script, language="python", filename="cfma_thread_discovery", timeout=12, persist=False)
        if not parsed.get("ok"):
            return parsed

        out = str((parsed.get("record") or {}).get("output", "") or "")
        hits: List[Dict[str, Any]] = []
        try:
            payload = json.loads(out.splitlines()[-1])
            hits = list(payload.get("hits") or [])
        except Exception:
            hits = []

        for item in hits:
            critique = REASONING_TOOL.reason(
                mode=MODE_CRITIQUE,
                objective="False positive audit for hidden process or injection anomaly",
                context=json.dumps(item, ensure_ascii=True),
                prior_output=json.dumps(state.findings[-20:], ensure_ascii=True),
                options=["legitimate security software", "system update artifact", "probable malicious behavior"],
                fetch_facts=False,
            )
            pivot = critique.get("pivot_request") or {}
            if pivot.get("required"):
                continue
            state.findings.append({"phase": state.phase, "anomaly": item, "critique": critique})
        return {"ok": True}

    async def _evidence_extraction(self, *, state: ForensicState) -> Dict[str, Any]:
        suspicious = [f for f in state.findings if f.get("type") in {"process_hollowing", "dkom_hidden_process", "credential_material"}]
        if not suspicious:
            suspicious = state.findings[-3:]

        handoff_targets: List[str] = []
        for index, finding in enumerate(suspicious[:10], start=1):
            evidence_path = self.evidence_root / f"artifact_{state.session_id}_{index:03d}.json"
            payload = {
                "session_id": state.session_id,
                "image_path": state.image_path,
                "image_sha256": state.image_sha256,
                "finding": clean_data(finding),
                "phase": state.phase,
            }
            evidence_path.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")
            digest = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
            artifact = MemoryArtifact(
                artifact_id=f"MEM-{uuid4().hex[:12].upper()}",
                source_image=state.image_path,
                extracted_path=str(evidence_path),
                sha256=digest,
                category=str(finding.get("type", "memory_anomaly")),
                offset=int(finding.get("offset", 0) or 0),
                collected_at=datetime.now(tz=UTC).isoformat(),
            )
            state.artifacts.append(artifact)
            handoff_targets.append(str(evidence_path))

        # Orchestrated handoff: suspicious memory fragments to CVR for deeper crash/logic analysis.
        if handoff_targets:
            try:
                handoff = await cerebro_vulnerability_researcher.run_research_loop(
                    network_targets=[],
                    urls=[],
                    file_targets=handoff_targets,
                    max_rounds=1,
                )
                state.findings.append({"phase": state.phase, "bug_bounter_handoff": handoff})
            except Exception as exc:
                state.findings.append({"phase": state.phase, "bug_bounter_handoff_error": str(exc)})
        return {"ok": True}

    def _lazy_slice_read(self, *, image_path: str, offset: int, length: int) -> Dict[str, Any]:
        code = (
            "import base64, json\n"
            f"path={image_path!r}\n"
            f"offset={int(offset)}\n"
            f"length={int(length)}\n"
            "with open(path, 'rb') as f:\n"
            "    f.seek(offset)\n"
            "    chunk=f.read(length)\n"
            "sample=chunk[:8192].decode('utf-8', errors='replace')\n"
            "print(json.dumps({'offset':offset,'length':len(chunk),'sample':sample}))\n"
        )
        result = EXEC_TOOL.execute(code=code, language="python", filename="cfma_slice_reader", timeout=10, persist=False)
        if not result.get("ok"):
            return result
        output = str((result.get("record") or {}).get("output", "") or "")
        try:
            row = json.loads(output.splitlines()[-1])
            return {"ok": True, **row}
        except Exception:
            return {"ok": False, "error": {"message": "Unable to parse lazy slice output"}}

    def _recognize_advanced_patterns(self, *, sample_text: str, offset: int) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        lower = sample_text.lower()

        if any(tok in lower for tok in ("ntunmapviewofsection", "writeprocessmemory", "createremotethread")):
            findings.append({"type": "process_hollowing", "offset": offset, "confidence": "82%", "detail": "Injection API triad observed in memory slice"})

        if any(tok in lower for tok in ("activeprocesslinks", "eprocess", "psactiveprocesshead", "unlink")):
            findings.append({"type": "dkom_hidden_process", "offset": offset, "confidence": "78%", "detail": "Potential EPROCESS unlink indicators detected"})

        cred_patterns = [r"(?i)password\s*[:=]\s*[^\s]{3,}", r"\b[a-fA-F0-9]{32}\b", r"(?i)lsass\.exe"]
        if any(re.search(pat, sample_text) for pat in cred_patterns):
            findings.append({"type": "credential_material", "offset": offset, "confidence": "85%", "detail": "Possible in-memory credential or hash artifact"})

        return findings

    def _extract_timestamps(self, text: str, *, source: str) -> List[TimelineEvent]:
        events: List[TimelineEvent] = []
        for match in re.finditer(r"(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:Z|(?:[+-]\d{2}:?\d{2}))?)", text):
            ts = match.group(1).replace(" ", "T")
            events.append(TimelineEvent(timestamp=ts, event_type="memory_artifact_timestamp", source=source, detail="timestamp extracted from volatile artifact"))
        return events[:20]

    def _build_offsets(self, *, total_size: int, max_slices: int) -> List[int]:
        points = max(4, min(int(max_slices), 64))
        if total_size <= self.slice_bytes:
            return [0]
        step = max(1, total_size // points)
        offsets = sorted(set(min(total_size - self.slice_bytes, i * step) for i in range(points)))
        return [int(x) for x in offsets if x >= 0]

    def _render_forensic_template(self, state: ForensicState) -> str:
        lines = [
            "### Forensic Artifact Report",
            "| Attribute | Value |",
            "| :--- | :--- |",
            f"| **Artifact ID** | `{state.session_id}` |",
            f"| **Phase** | `{state.phase}` |",
            "| **Process ID (PID)** | `N/A` |",
            "| **Memory Offset** | `Dynamic per finding` |",
            "| **Data Type** | `Volatile Artifact` |",
            f"| **Confidence Score** | `{self._confidence_score(state)}%` |",
            "| **Critique Note** | `MODE_CRITIQUE false positive audit applied to hidden-process anomalies.` |",
            "| **Action Required** | `Investigate` |",
            "",
            "### Unified Timeline Integration",
        ]
        for item in state.timeline[:80]:
            lines.append(f"- [{item.timestamp}] {item.event_type} ({item.source}) :: {item.detail}")

        lines.append("")
        lines.append("### Evidence Artifacts")
        for artifact in state.artifacts:
            lines.append(
                f"- {artifact.artifact_id} | category={artifact.category} | offset={artifact.offset} | sha256={artifact.sha256} | path={artifact.extracted_path}"
            )
        return "\n".join(lines) + "\n"

    @staticmethod
    def _confidence_score(state: ForensicState) -> int:
        if not state.findings:
            return 55
        high = sum(1 for f in state.findings if str(f.get("confidence", "0")).startswith(("8", "9")))
        base = 60 + min(35, high * 5)
        return min(99, base)

    def _load_prompt(self) -> str:
        try:
            return load_prompt_template("prompts/system_memory_analyst.md")
        except FileNotFoundError:
            try:
                return load_prompt_template("prompts/memory_analysis_agent.md")
            except FileNotFoundError:
                return "You are Cerebro Forensic Memory Analyst."

    @staticmethod
    def _resolve_workspace(workspace_root: Optional[str]) -> Path:
        if workspace_root:
            return Path(workspace_root).expanduser().resolve()
        try:
            return get_project_space().ensure_initialized().resolve()
        except Exception:
            return Path.cwd().resolve()


load_dotenv()
memory_analysis_agent_system_prompt = load_prompt_template("prompts/memory_analysis_agent.md")

_tools = []
for _meta in get_all_tools():
    if not getattr(_meta, "enabled", False):
        continue
    try:
        _tools.append(get_tool(_meta.name))
    except Exception:
        continue


memory_analysis_agent = Agent(
    name="Memory Analysis Specialist",
    instructions=create_system_prompt_renderer(memory_analysis_agent_system_prompt),
    description="Autonomous forensic memory analyst for volatile compromise investigation.",
    tools=_tools,
    model=OpenAIChatCompletionsModel(
        model=os.getenv("CERBERUS_MODEL", "cerebro1"),
        openai_client=AsyncOpenAI(),
    ),
)


cerebro_memory_forensics_agent = CerebroMemoryForensicsAgent()


__all__ = [
    "MemoryArtifact",
    "TimelineEvent",
    "ForensicState",
    "CerebroMemoryForensicsAgent",
    "cerebro_memory_forensics_agent",
    "memory_analysis_agent",
]
