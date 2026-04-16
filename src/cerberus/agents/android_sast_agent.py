"""Autonomous Android SAST agent with CASA phase orchestration.

This file provides two layers:
1. `CerebroAndroidSASTAgent`: an autonomous forensic auditor implementation.
2. Compatibility `Agent` exports (`app_logic_mapper`, `android_sast`) for runtime discovery.
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from dotenv import load_dotenv
from openai import AsyncOpenAI

from cerberus.agents import Agent, OpenAIChatCompletionsModel
from cerberus.tools.all_tools import get_all_tools, get_tool
from cerberus.tools.misc.reasoning import MODE_CRITIQUE, MODE_STRATEGY, REASONING_TOOL
from cerberus.tools.reconnaissance.exec_code import EXEC_TOOL
from cerberus.tools.reconnaissance.filesystem import FILESYSTEM_TOOL
from cerberus.tools.workspace import get_project_space
from cerberus.util import create_system_prompt_renderer, load_prompt_template


android_sast_system_prompt = load_prompt_template("prompts/system_android_sast.md")
app_logic_mapper_system_prompt = load_prompt_template("prompts/system_android_app_logic_mapper.md")


@dataclass(frozen=True)
class AuditPhase:
    key: str
    title: str
    keywords: Tuple[str, ...]


@dataclass
class Finding:
    finding_id: str
    category: str
    cwe_id: str
    owasp_top10: str
    severity: str
    impact_score: float
    exploit_probability: float
    risk_vector: float
    evidence_path: str
    snippet: str
    rationale: str
    critique_validation: str
    phase: str


PHASES: Tuple[AuditPhase, ...] = (
    AuditPhase("config_review", "Security Configuration Review", ("AndroidManifest.xml", "network_security_config", "uses-permission", "debuggable", "cleartext")),
    AuditPhase("crypto_check", "Cryptographic Integrity Check", ("javax.crypto", "MessageDigest", "MD5", "SHA1", "SecretKeySpec", "BEGIN RSA PRIVATE KEY")),
    AuditPhase("data_flow", "Data Flow & Sink Analysis", ("SharedPreferences", "Log.", "WebView", "Intent", "putExtra", "getExternalStorageDirectory", "token", "password")),
    AuditPhase("permission_audit", "Permission Over-Privilege Check", ("uses-permission", "android.permission", "READ_SMS", "READ_CONTACTS", "WRITE_EXTERNAL_STORAGE", "RECORD_AUDIO")),
)


class CerebroAndroidSASTAgent:
    """Autonomous forensic Android SAST engine driven by reasoning.py."""

    def __init__(self, *, workspace_root: Optional[str] = None, max_workers: int = 6) -> None:
        self.workspace_root = self._resolve_workspace(workspace_root)
        self.reports_dir = self.workspace_root / "reports" / "android_sast"
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.max_workers = max(1, int(max_workers))
        self.system_prompt = android_sast_system_prompt
        self._finding_counter = 0
        self._lock = asyncio.Lock()

    async def run_audit(self, source_root: str) -> Dict[str, Any]:
        """Run full CASA audit with phase state-machine and stream findings to artifacts."""
        target_root = Path(source_root).expanduser().resolve()
        if not target_root.exists() or not target_root.is_dir():
            return {"ok": False, "error": {"code": "invalid_target", "message": f"Path does not exist: {source_root}"}}

        started_at = datetime.now(tz=UTC)
        findings: List[Finding] = []
        phase_results: List[Dict[str, Any]] = []

        for phase in PHASES:
            strategy = REASONING_TOOL.reason(
                mode=MODE_STRATEGY,
                objective=f"CASA phase execution for {phase.title}",
                context=f"Target path: {target_root}",
                options=["Focused keyword peeking", "Broader package sweep"],
                fetch_facts=True,
                fact_query=phase.title,
            )
            phase_findings = await self._execute_phase(phase=phase, target_root=target_root, strategy=strategy)
            findings.extend(phase_findings)
            phase_results.append(
                {
                    "phase": phase.key,
                    "title": phase.title,
                    "findings": len(phase_findings),
                    "strategy_summary": strategy.get("summary", ""),
                }
            )

        ended_at = datetime.now(tz=UTC)
        brief_path = self.reports_dir / "binary_intelligence_brief.md"
        brief_path.write_text(self._render_binary_intelligence_brief(target_root=target_root, findings=findings, phase_results=phase_results), encoding="utf-8")

        return {
            "ok": True,
            "target_root": str(target_root),
            "started_at": started_at.isoformat(),
            "ended_at": ended_at.isoformat(),
            "phases": phase_results,
            "total_findings": len(findings),
            "reports_dir": str(self.reports_dir),
            "brief_path": str(brief_path),
        }

    async def _execute_phase(self, *, phase: AuditPhase, target_root: Path, strategy: Dict[str, Any]) -> List[Finding]:
        actions = self._decide_actions(phase=phase, strategy=strategy)
        candidates: List[Path] = []

        if actions["filesystem"]:
            candidates = self._peek_candidate_files(target_root=target_root, keywords=phase.keywords)

        if not candidates:
            return []

        worker_inputs = self._shard_candidates(candidates)
        semaphore = asyncio.Semaphore(self.max_workers)
        tasks = [self._worker_scan(phase=phase, files=chunk, semaphore=semaphore, use_exec=actions["exec_code"]) for chunk in worker_inputs]
        worker_results = await asyncio.gather(*tasks)

        flattened = [item for chunk in worker_results for item in chunk]
        accepted: List[Finding] = []
        for finding in flattened:
            critique = REASONING_TOOL.reason(
                mode=MODE_CRITIQUE,
                objective=f"Validate potential false positive for {finding.cwe_id}",
                context=finding.rationale,
                prior_output=f"file={finding.evidence_path}; severity={finding.severity}; snippet={finding.snippet[:220]}",
                options=["retain finding", "discard finding"],
                fetch_facts=False,
            )
            if self._discard_after_critique(finding=finding, critique=critique):
                continue
            finding.critique_validation = critique.get("summary", "")
            await self._append_finding_artifact(finding)
            accepted.append(finding)
        return accepted

    def _decide_actions(self, *, phase: AuditPhase, strategy: Dict[str, Any]) -> Dict[str, bool]:
        weights = strategy.get("weights") or []
        top_utility = 0.0
        if weights:
            top_utility = max(float(item.get("utility_score", 0.0)) for item in weights)
        return {
            "filesystem": True,
            "read_file": True,
            "exec_code": phase.key in {"crypto_check", "data_flow"} or top_utility < 0.25,
        }

    def _peek_candidate_files(self, *, target_root: Path, keywords: Sequence[str]) -> List[Path]:
        candidates: List[Path] = []
        seen: set[str] = set()
        limit = 600
        for path in target_root.rglob("*"):
            if len(candidates) >= limit:
                break
            if not path.is_file():
                continue
            if path.suffix.lower() not in {".java", ".kt", ".xml", ".smali", ".txt", ".cfg", ".properties"} and path.name != "AndroidManifest.xml":
                continue
            rel = str(path.relative_to(target_root))
            lowered = rel.lower()
            if not any(keyword.lower() in lowered for keyword in keywords):
                preview = self._stream_read(path)
                if not any(keyword.lower() in preview.lower() for keyword in keywords):
                    continue
            if rel in seen:
                continue
            seen.add(rel)
            candidates.append(path)
        return candidates

    def _stream_read(self, path: Path, *, max_bytes: int = 4096) -> str:
        data = FILESYSTEM_TOOL.read_file(file_path=str(path), max_bytes=max_bytes)
        if data.get("ok"):
            return str(data.get("content", ""))
        try:
            return path.read_text(encoding="utf-8", errors="replace")[:max_bytes]
        except OSError:
            return ""

    def _shard_candidates(self, candidates: Sequence[Path]) -> List[List[Path]]:
        if not candidates:
            return []
        shard_size = max(1, len(candidates) // self.max_workers)
        out: List[List[Path]] = []
        current: List[Path] = []
        for item in candidates:
            current.append(item)
            if len(current) >= shard_size:
                out.append(current)
                current = []
        if current:
            out.append(current)
        return out

    async def _worker_scan(self, *, phase: AuditPhase, files: Sequence[Path], semaphore: asyncio.Semaphore, use_exec: bool) -> List[Finding]:
        async with semaphore:
            findings: List[Finding] = []
            for file_path in files:
                text = self._stream_read(file_path)
                if not text:
                    continue
                findings.extend(self._extract_findings(phase=phase, file_path=file_path, text=text, use_exec=use_exec))
            return findings

    def _extract_findings(self, *, phase: AuditPhase, file_path: Path, text: str, use_exec: bool) -> List[Finding]:
        out: List[Finding] = []
        rel_path = str(file_path.relative_to(self.workspace_root)) if self._is_under_workspace(file_path) else str(file_path)
        for rule in self._phase_rules(phase):
            match = re.search(rule["pattern"], text, flags=re.IGNORECASE | re.MULTILINE)
            if not match:
                continue
            probability = self._exploit_probability(path=rel_path, snippet=match.group(0), phase=phase)
            impact = float(rule["impact"])
            risk_vector = round(min(100.0, impact * probability * 10.0), 2)
            rationale = f"Matched rule '{rule['name']}' in phase {phase.key}."
            if use_exec and phase.key == "crypto_check":
                entropy = self._calculate_entropy(match.group(0))
                rationale += f" Entropy={entropy:.2f}."
            self._finding_counter += 1
            out.append(
                Finding(
                    finding_id=f"CASA-{self._finding_counter:04d}",
                    category=rule["category"],
                    cwe_id=rule["cwe"],
                    owasp_top10=rule["owasp"],
                    severity=self._severity_from_risk(risk_vector),
                    impact_score=impact,
                    exploit_probability=probability,
                    risk_vector=risk_vector,
                    evidence_path=rel_path,
                    snippet=match.group(0)[:260],
                    rationale=rationale,
                    critique_validation="",
                    phase=phase.key,
                )
            )
        return out

    def _phase_rules(self, phase: AuditPhase) -> List[Dict[str, Any]]:
        rules: Dict[str, List[Dict[str, Any]]] = {
            "config_review": [
                {"name": "Cleartext Allowed", "pattern": r"cleartextTrafficPermitted\s*=\s*\"?true\"?", "cwe": "CWE-319", "owasp": "M3: Insecure Communication", "impact": 8.0, "category": "Config"},
                {"name": "Debuggable Build", "pattern": r"android:debuggable\s*=\s*\"true\"", "cwe": "CWE-489", "owasp": "M8: Security Misconfiguration", "impact": 7.0, "category": "Config"},
            ],
            "crypto_check": [
                {"name": "Weak Hash", "pattern": r"MessageDigest\.getInstance\(\s*\"(?:MD5|SHA1?)\"\s*\)", "cwe": "CWE-327", "owasp": "M5: Insufficient Cryptography", "impact": 8.0, "category": "Crypto"},
                {"name": "Hardcoded Key", "pattern": r"(?:secret|api|token|key)[a-zA-Z0-9_\-]*\s*=\s*\"[A-Za-z0-9_\-+/=]{12,}\"", "cwe": "CWE-321", "owasp": "M5: Insufficient Cryptography", "impact": 9.0, "category": "Crypto"},
            ],
            "data_flow": [
                {"name": "Sensitive Logging", "pattern": r"Log\.(?:d|i|w|e)\([^\)]*(?:password|token|secret|session)", "cwe": "CWE-532", "owasp": "M2: Insecure Data Storage", "impact": 7.0, "category": "Flow"},
                {"name": "External Storage Sensitive", "pattern": r"getExternalStorageDirectory\(\)|MODE_WORLD_READABLE", "cwe": "CWE-312", "owasp": "M2: Insecure Data Storage", "impact": 8.0, "category": "Flow"},
            ],
            "permission_audit": [
                {"name": "High-Risk Permission", "pattern": r"android\.permission\.(?:READ_SMS|READ_CONTACTS|RECORD_AUDIO|READ_CALL_LOG)", "cwe": "CWE-250", "owasp": "M6: Insecure Authorization", "impact": 6.0, "category": "Permission"},
                {"name": "Broad Storage Access", "pattern": r"android\.permission\.(?:MANAGE_EXTERNAL_STORAGE|WRITE_EXTERNAL_STORAGE)", "cwe": "CWE-284", "owasp": "M8: Security Misconfiguration", "impact": 6.5, "category": "Permission"},
            ],
        }
        return rules.get(phase.key, [])

    def _exploit_probability(self, *, path: str, snippet: str, phase: AuditPhase) -> float:
        base = 0.55
        lowered_path = path.lower()
        lowered_snippet = snippet.lower()
        if any(marker in lowered_path for marker in ("/test/", "/androidtest/", "mock", "fixture")):
            base -= 0.35
        if any(marker in lowered_snippet for marker in ("todo", "sample", "placeholder", "dummy")):
            base -= 0.2
        if phase.key in {"crypto_check", "data_flow"}:
            base += 0.15
        return round(max(0.05, min(0.98, base)), 3)

    def _severity_from_risk(self, risk_vector: float) -> str:
        if risk_vector >= 75:
            return "Critical"
        if risk_vector >= 55:
            return "High"
        if risk_vector >= 35:
            return "Medium"
        return "Low"

    def _calculate_entropy(self, value: str) -> float:
        code = (
            "from collections import Counter\n"
            "from math import log2\n"
            f"data={value!r}\n"
            "count=Counter(data)\n"
            "length=max(len(data),1)\n"
            "entropy=-sum((v/length)*log2(v/length) for v in count.values())\n"
            "print(round(entropy,4))\n"
        )
        result = EXEC_TOOL.execute(code=code, language="python", filename="entropy_check", timeout=3, persist=False)
        if not result.get("ok"):
            return 0.0
        record = result.get("record") or {}
        output = str(record.get("output", "")).strip()
        try:
            return float(output.splitlines()[-1])
        except (ValueError, IndexError):
            return 0.0

    def _discard_after_critique(self, *, finding: Finding, critique: Dict[str, Any]) -> bool:
        if "test" in finding.evidence_path.lower():
            return True
        pivot = critique.get("pivot_request") or {}
        if pivot.get("required") and finding.exploit_probability < 0.4:
            return True
        return False

    async def _append_finding_artifact(self, finding: Finding) -> None:
        async with self._lock:
            jsonl_path = self.reports_dir / "findings.jsonl"
            with jsonl_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(asdict(finding), ensure_ascii=True) + "\n")

            md_path = self.reports_dir / "forensic_artifacts.md"
            with md_path.open("a", encoding="utf-8") as handle:
                handle.write(
                    "\n### Forensic Artifact Template\n"
                    f"- Artifact ID: {finding.finding_id}\n"
                    f"- Phase: {finding.phase}\n"
                    f"- Category: {finding.category}\n"
                    f"- CWE: {finding.cwe_id}\n"
                    f"- OWASP: {finding.owasp_top10}\n"
                    f"- Severity: {finding.severity}\n"
                    f"- Risk Vector: {finding.risk_vector}\n"
                    f"- Evidence Path: {finding.evidence_path}\n"
                    f"- Critique Validation: {finding.critique_validation}\n"
                )

    def _render_binary_intelligence_brief(self, *, target_root: Path, findings: Sequence[Finding], phase_results: Sequence[Dict[str, Any]]) -> str:
        lines = [
            "### Binary Intelligence Brief",
            "",
            "| Attribute | Value |",
            "| :--- | :--- |",
            f"| Target Application | {target_root.name} |",
            f"| Report Time (UTC) | {datetime.now(tz=UTC).isoformat()} |",
            f"| Total Findings | {len(findings)} |",
            "| Output Format | Security Audit Report + Forensic Artifacts |",
            "",
            "### Phase Summary",
        ]
        for phase in phase_results:
            lines.append(f"- {phase['title']}: {phase['findings']} finding(s)")

        lines.append("")
        lines.append("### Security Audit Report")
        lines.append("| Attribute | Value |")
        lines.append("| :--- | :--- |")
        for finding in findings:
            lines.append(f"| Finding ID | {finding.finding_id} |")
            lines.append(f"| Category | {finding.category} |")
            lines.append(f"| OWASP Top 10 | {finding.owasp_top10} |")
            lines.append(f"| CWE ID | {finding.cwe_id} |")
            lines.append(f"| Severity | {finding.severity} |")
            lines.append(f"| Evidence Path | {finding.evidence_path} |")
            lines.append(f"| Critique Validation | {finding.critique_validation or 'N/A'} |")
            lines.append(f"| Remediation | Investigate and patch in source component owning {finding.evidence_path}. |")
            lines.append("")
        if not findings:
            lines.append("No high-confidence findings identified after MODE_CRITIQUE filtering.")
        return "\n".join(lines) + "\n"

    @staticmethod
    def _resolve_workspace(workspace_root: Optional[str]) -> Path:
        if workspace_root:
            return Path(workspace_root).expanduser().resolve()
        try:
            return get_project_space().ensure_initialized().resolve()
        except Exception:
            return Path.cwd().resolve()

    def _is_under_workspace(self, path: Path) -> bool:
        try:
            path.resolve().relative_to(self.workspace_root)
            return True
        except ValueError:
            return False


load_dotenv()
model_name = os.getenv("CERBERUS_MODEL", "cerebro1")
tools = []
for _meta in get_all_tools():
    if not getattr(_meta, "enabled", False):
        continue
    try:
        tools.append(get_tool(_meta.name))
    except Exception:
        continue

app_logic_mapper = Agent(
    name="AppLogicMapper",
    description="Agent specializing in application analysis to understand the logic of operation and return a complete map of it.",
    instructions=create_system_prompt_renderer(app_logic_mapper_system_prompt),
    tools=tools,
    model=OpenAIChatCompletionsModel(
        model=model_name,
        openai_client=AsyncOpenAI(),
    ),
)

android_sast = Agent(
    name="AndroidSAST",
    description="Agent specializing in static application security testing and vulnerability discovery for Android applications.",
    instructions=create_system_prompt_renderer(android_sast_system_prompt),
    tools=[
        app_logic_mapper.as_tool(
            tool_name="app_mapper",
            tool_description="Application analysis for logic mapping and attack-surface understanding.",
        ),
        *tools,
    ],
    model=OpenAIChatCompletionsModel(
        model=model_name,
        openai_client=AsyncOpenAI(),
    ),
)


cerebro_android_sast_agent = CerebroAndroidSASTAgent()


__all__ = [
    "CerebroAndroidSASTAgent",
    "cerebro_android_sast_agent",
    "app_logic_mapper",
    "android_sast",
]

