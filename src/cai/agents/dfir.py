"""Cerebro Digital Forensics & Incident Response (CDFIR) orchestrator.

Clean-room DFIR implementation focused on chain of custody, timeline
reconstruction, and defensible forensic reporting.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence

from dotenv import load_dotenv
from openai import AsyncOpenAI

from cai.sdk.agents import Agent, OpenAIChatCompletionsModel
from cai.tools.all_tools import get_all_tools, get_tool
from cai.tools.misc.reasoning import MODE_CRITIQUE, MODE_STRATEGY, REASONING_TOOL
from cai.tools.reconnaissance.exec_code import EXEC_TOOL
from cai.tools.reconnaissance.filesystem import FILESYSTEM_TOOL
from cai.tools.reconnaissance.generic_linux_command import LINUX_COMMAND_TOOL
from cai.tools.workspace import get_project_space
from cai.util import create_system_prompt_renderer, load_prompt_template


DFIR_PROMPT_FALLBACK = """# CDFIR Prompt

You are the Cerebro DFIR Orchestrator.
Lifecycle phases:
1. Initial Triage
2. Evidence Preservation
3. Analysis
4. Remediation Recommendations

Prioritize legally-defensible chain of custody and timeline reconstruction.
"""


@dataclass
class EvidenceArtifact:
    artifact_id: str
    source_path: str
    collected_at: str
    agent_id: str
    collection_method: str
    sha256: str
    stored_path: str
    note: str = ""


@dataclass
class TimelineEvent:
    timestamp: str
    source: str
    event: str
    confidence: str
    actor: str


@dataclass
class InvestigationState:
    session_id: str
    phase: str = "Initial Triage"
    artifacts: List[EvidenceArtifact] = field(default_factory=list)
    timeline: List[TimelineEvent] = field(default_factory=list)
    suspicious_findings: List[Dict[str, Any]] = field(default_factory=list)
    forensic_warnings: List[str] = field(default_factory=list)


class CerebroDFIROrchestrator:
    """Autonomous DFIR orchestrator with strict chain-of-custody controls."""

    def __init__(self, *, workspace_root: Optional[str] = None) -> None:
        self.workspace_root = self._resolve_workspace(workspace_root)
        self.prompt = self._load_prompt()

    async def investigate(
        self,
        *,
        triage_paths: Sequence[str],
        log_paths: Sequence[str],
        scan_root: str = ".",
        agent_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        session_id = datetime.now(tz=UTC).strftime("CDFIR_%Y%m%dT%H%M%SZ")
        state = InvestigationState(session_id=session_id)
        active_agent_id = (agent_id or os.getenv("CEREBRO_AGENT_ID") or "unknown-agent").strip()

        evidence_dir = (self.workspace_root / "evidence" / "forensics" / session_id).resolve()
        evidence_dir.mkdir(parents=True, exist_ok=True)
        custody_log = evidence_dir / "chain_of_custody.jsonl"

        # Phase 1: Initial Triage
        state.phase = "Initial Triage"
        strategy = REASONING_TOOL.reason(
            mode=MODE_STRATEGY,
            objective="Plan DFIR initial triage",
            context=f"triage_paths={len(triage_paths)} log_paths={len(log_paths)} scan_root={scan_root}",
            options=["network-first", "logs-first", "filesystem-first"],
            fetch_facts=True,
            fact_query="forensic triage",
        )
        state.suspicious_findings.append({"phase": state.phase, "strategy": strategy})

        netstat_result = await LINUX_COMMAND_TOOL.execute(command="netstat -tulnp", timeout_seconds=20)
        self._append_event(state, source="netstat", event=self._summarize_netstat(netstat_result), confidence="Medium", actor="system")

        # Phase 2: Evidence Preservation
        state.phase = "Evidence Preservation"
        collect_targets = list(triage_paths) + list(log_paths)
        for src in collect_targets:
            art = self._collect_artifact(
                source_path=src,
                evidence_dir=evidence_dir,
                agent_id=active_agent_id,
                collection_method="read_file",
            )
            if art:
                state.artifacts.append(art)
                self._append_custody(custody_log, art)

        # Filesystem mapping for hidden directories and modified timestamps.
        fs_map = FILESYSTEM_TOOL.list_directory(path=scan_root, max_depth=3, include_hidden=True, interesting_only=False)
        fs_dump = evidence_dir / "filesystem_map.json"
        fs_dump.write_text(json.dumps(fs_map, ensure_ascii=True, indent=2), encoding="utf-8")
        fs_artifact = self._register_stored_artifact(
            stored_file=fs_dump,
            source_path=scan_root,
            agent_id=active_agent_id,
            collection_method="filesystem",
            note="filesystem map with hidden entries and timestamps",
        )
        state.artifacts.append(fs_artifact)
        self._append_custody(custody_log, fs_artifact)

        # Phase 3: Analysis
        state.phase = "Analysis"
        timeline_rows = self._reconstruct_timeline(state)
        state.timeline.extend(timeline_rows)
        timeline_path = evidence_dir / "unified_timeline.json"
        timeline_path.write_text(json.dumps([asdict(row) for row in state.timeline], ensure_ascii=True, indent=2), encoding="utf-8")

        # Optional parsing helpers via exec_code in read-only mode.
        forensic_parse = EXEC_TOOL.execute(
            code=self._timeline_parser_code(str(timeline_path)),
            language="python",
            filename="timeline_parser",
            timeout=12,
            persist=True,
        )
        parse_path = evidence_dir / "timeline_parser_output.json"
        parse_path.write_text(json.dumps(forensic_parse, ensure_ascii=True, indent=2), encoding="utf-8")
        parse_art = self._register_stored_artifact(
            stored_file=parse_path,
            source_path=str(timeline_path),
            agent_id=active_agent_id,
            collection_method="exec_code",
            note="parsed timeline indicators",
        )
        state.artifacts.append(parse_art)
        self._append_custody(custody_log, parse_art)

        # MODE_CRITIQUE: intrusion vs admin activity.
        critique = REASONING_TOOL.reason(
            mode=MODE_CRITIQUE,
            objective="Classify anomalies as genuine intrusion vs administrative activity",
            context=json.dumps([asdict(e) for e in state.timeline[:60]], ensure_ascii=True),
            prior_output=json.dumps(state.suspicious_findings, ensure_ascii=True),
            options=["genuine intrusion", "administrative activity"],
            fetch_facts=False,
        )

        # Phase 4: Remediation Recommendations
        state.phase = "Remediation Recommendations"
        recommendations = self._recommend_remediation(state, critique)

        brief_path = self.workspace_root / "reports" / "forensics" / f"forensic_investigation_brief_{session_id}.md"
        brief_path.parent.mkdir(parents=True, exist_ok=True)
        brief_path.write_text(self._render_brief(state, critique, recommendations), encoding="utf-8")

        return {
            "ok": True,
            "session_id": session_id,
            "evidence_dir": str(evidence_dir),
            "artifact_count": len(state.artifacts),
            "timeline_events": len(state.timeline),
            "brief_path": str(brief_path),
        }

    def _collect_artifact(
        self,
        *,
        source_path: str,
        evidence_dir: Path,
        agent_id: str,
        collection_method: str,
    ) -> Optional[EvidenceArtifact]:
        result = FILESYSTEM_TOOL.read_file(file_path=source_path, max_bytes=250000)
        if not result.get("ok"):
            return None
        content = str(result.get("content", ""))
        artifact_id = self._artifact_id(source_path)
        stored = evidence_dir / f"{artifact_id}.txt"
        stored.write_text(content, encoding="utf-8", errors="replace")
        digest = hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()
        return EvidenceArtifact(
            artifact_id=artifact_id,
            source_path=source_path,
            collected_at=datetime.now(tz=UTC).isoformat(),
            agent_id=agent_id,
            collection_method=collection_method,
            sha256=digest,
            stored_path=str(stored),
        )

    def _register_stored_artifact(
        self,
        *,
        stored_file: Path,
        source_path: str,
        agent_id: str,
        collection_method: str,
        note: str,
    ) -> EvidenceArtifact:
        payload = stored_file.read_bytes()
        return EvidenceArtifact(
            artifact_id=self._artifact_id(source_path + stored_file.name),
            source_path=source_path,
            collected_at=datetime.now(tz=UTC).isoformat(),
            agent_id=agent_id,
            collection_method=collection_method,
            sha256=hashlib.sha256(payload).hexdigest(),
            stored_path=str(stored_file),
            note=note,
        )

    def _append_custody(self, custody_log: Path, artifact: EvidenceArtifact) -> None:
        with custody_log.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(asdict(artifact), ensure_ascii=True) + "\n")

    @staticmethod
    def _append_event(
        state: InvestigationState,
        *,
        source: str,
        event: str,
        confidence: str,
        actor: str,
    ) -> None:
        state.timeline.append(
            TimelineEvent(
                timestamp=datetime.now(tz=UTC).isoformat(),
                source=source,
                event=event,
                confidence=confidence,
                actor=actor,
            )
        )

    def _reconstruct_timeline(self, state: InvestigationState) -> List[TimelineEvent]:
        rows: List[TimelineEvent] = []
        for artifact in state.artifacts:
            content = Path(artifact.stored_path).read_text(encoding="utf-8", errors="replace") if Path(artifact.stored_path).exists() else ""
            for line in content.splitlines()[:1500]:
                timestamp = self._extract_timestamp(line) or artifact.collected_at
                actor = self._extract_actor(line)
                event = self._normalize_event(line)
                if not event:
                    continue
                rows.append(
                    TimelineEvent(
                        timestamp=timestamp,
                        source=artifact.source_path,
                        event=event,
                        confidence="Medium",
                        actor=actor,
                    )
                )

        rows.sort(key=lambda item: item.timestamp)
        if rows:
            rows[0].event = f"PATIENT_ZERO_CANDIDATE: {rows[0].event}"
        return rows

    def _recommend_remediation(self, state: InvestigationState, critique: Dict[str, Any]) -> List[str]:
        pivot = critique.get("pivot_request") or {}
        recs = [
            "Isolate suspicious hosts from lateral movement corridors until containment is verified.",
            "Rotate potentially exposed credentials and invalidate stale sessions.",
            "Enable stricter audit logging on authentication and privileged command paths.",
        ]
        if pivot.get("required"):
            recs.append("Conduct administrator interview and change-window validation before escalation.")
        return recs

    def _render_brief(self, state: InvestigationState, critique: Dict[str, Any], recommendations: Sequence[str]) -> str:
        lines = [
            "### Forensic Investigation Brief",
            "",
            "| Attribute | Value |",
            "| :--- | :--- |",
            f"| Session ID | {state.session_id} |",
            f"| Investigation Phase | {state.phase} |",
            f"| Artifacts Collected | {len(state.artifacts)} |",
            f"| Timeline Events | {len(state.timeline)} |",
            f"| Critique Summary | {str(critique.get('summary', 'n/a')).replace('|', '/')} |",
            "",
            "#### Unified Forensic Timeline",
        ]
        for event in state.timeline[:60]:
            lines.append(f"- [{event.timestamp}] ({event.source}) {event.event} | actor={event.actor} | confidence={event.confidence}")

        lines.append("")
        lines.append("#### Chain of Custody Snapshot")
        for art in state.artifacts[:40]:
            lines.append(
                f"- Artifact {art.artifact_id}: {art.source_path} -> {art.stored_path} | SHA-256={art.sha256} | method={art.collection_method} | agent={art.agent_id}"
            )

        lines.append("")
        lines.append("#### Remediation Recommendations")
        for rec in recommendations:
            lines.append(f"- {rec}")
        return "\n".join(lines) + "\n"

    @staticmethod
    def _extract_timestamp(line: str) -> str:
        match = re.search(r"(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:Z|(?:[+-]\d{2}:?\d{2}))?)", line)
        if match:
            return match.group(1).replace(" ", "T")
        return ""

    @staticmethod
    def _extract_actor(line: str) -> str:
        m = re.search(r"\b(user|uid|account|login)[:=\s]+([A-Za-z0-9._\\-]+)", line, flags=re.IGNORECASE)
        return m.group(2) if m else "unknown"

    @staticmethod
    def _normalize_event(line: str) -> str:
        text = line.strip()
        if not text:
            return ""
        keep = any(token in text.lower() for token in ("failed", "accepted", "sudo", "ssh", "connect", "login", "exec", "copy", "delete", "moved", "session"))
        return text[:320] if keep else ""

    @staticmethod
    def _summarize_netstat(result: Dict[str, Any]) -> str:
        if not result.get("ok"):
            return f"netstat collection failed: {(result.get('error') or {}).get('message', 'unknown')}"
        out = str(result.get("stdout", ""))
        suspicious = []
        for line in out.splitlines():
            if any(tok in line for tok in (":4444", ":1337", "ESTABLISHED")):
                suspicious.append(line.strip())
        if suspicious:
            return "Potential suspicious connections observed: " + " | ".join(suspicious[:6])
        return "Network triage completed; no obvious suspicious persistent connection markers."

    @staticmethod
    def _timeline_parser_code(timeline_path: str) -> str:
        return (
            "import json\n"
            f"p = {timeline_path!r}\n"
            "rows = json.load(open(p, 'r', encoding='utf-8'))\n"
            "alerts = [r for r in rows if 'PATIENT_ZERO_CANDIDATE' in r.get('event', '') or 'sudo' in r.get('event', '').lower() or 'failed' in r.get('event', '').lower()]\n"
            "print(json.dumps({'alerts': alerts[:50], 'count': len(alerts)}))\n"
        )

    @staticmethod
    def _artifact_id(seed: str) -> str:
        base = hashlib.sha256((seed + datetime.now(tz=UTC).isoformat()).encode("utf-8")).hexdigest()
        return "ART-" + base[:12].upper()

    def _load_prompt(self) -> str:
        try:
            return load_prompt_template("prompts/dfir_agent.md")
        except FileNotFoundError:
            return DFIR_PROMPT_FALLBACK

    @staticmethod
    def _resolve_workspace(workspace_root: Optional[str]) -> Path:
        if workspace_root:
            return Path(workspace_root).expanduser().resolve()
        try:
            return get_project_space().ensure_initialized().resolve()
        except Exception:
            return Path.cwd().resolve()


load_dotenv()
dfir_agent_system_prompt = load_prompt_template("prompts/system_dfir_agent.md")
_tools = []
for _meta in get_all_tools():
    if not getattr(_meta, "enabled", False):
        continue
    try:
        _tools.append(get_tool(_meta.name))
    except Exception:
        continue


dfir_agent = Agent(
    name="OS Auditor (COSA)",
    instructions=create_system_prompt_renderer(dfir_agent_system_prompt),
    description="Configuration integrity, privilege analysis, and internal state mapping specialist.",
    model=OpenAIChatCompletionsModel(
        model=os.getenv("CEREBRO_MODEL", "cerebro1"),
        openai_client=AsyncOpenAI(),
    ),
    tools=_tools,
)


cerebro_dfir_orchestrator = CerebroDFIROrchestrator()


__all__ = [
    "CerebroDFIROrchestrator",
    "InvestigationState",
    "EvidenceArtifact",
    "TimelineEvent",
    "cerebro_dfir_orchestrator",
    "dfir_agent",
]