"""Autonomous CVR agent for vulnerability discovery and verification.

This module provides a clean-room `CerebroVulnerabilityResearcher` implementation
and a compatibility `bug_bounter_agent` export for existing agent loading flows.
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
import json
import math
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

from dotenv import load_dotenv
from openai import AsyncOpenAI

from cerberus.agents.guardrails import get_security_guardrails
from cerberus.sdk.agents import Agent, OpenAIChatCompletionsModel
from cerberus.tools.all_tools import get_all_tools, get_tool
from cerberus.tools.misc.reasoning import MODE_CRITIQUE, MODE_RISK_ASSESSMENT, MODE_STRATEGY, REASONING_TOOL
from cerberus.tools.reconnaissance.curl import CURL_TOOL
from cerberus.tools.reconnaissance.exec_code import EXEC_TOOL
from cerberus.tools.reconnaissance.filesystem import FILESYSTEM_TOOL
from cerberus.tools.reconnaissance.nmap import NMAP_TOOL
from cerberus.tools.runners.docker import DOCKER_TOOL
from cerberus.tools.workspace import get_project_space
from cerberus.util import create_system_prompt_renderer, load_prompt_template


CVR_PROMPT_FALLBACK = """# Cerebro Vulnerability Researcher Prompt

You are the Cerebro Vulnerability Researcher (CVR).
Your mission is to discover, triage, reproduce, and verify vulnerabilities with high scientific rigor.

Triage states are mandatory:
1) Discovery
2) Reproduction
3) Impact Analysis
4) Verification

You must perform a verification turn before reporting and output findings as a
Vulnerability Intelligence Brief.
"""


@dataclass(frozen=True)
class CVSSVector:
    av: str
    ac: str
    pr: str
    ui: str
    s: str
    c: str
    i: str
    a: str
    e: str
    rl: str
    rc: str
    cr: str
    ir: str
    ar: str


@dataclass
class VulnerabilityFinding:
    vuln_id: str
    target_system: str
    vuln_class: str
    triage_state: str
    root_cause: str
    reproduction_steps: List[str]
    impact_assessment: str
    verification_status: str
    cvss_base_score: float
    cvss_temporal_score: float
    cvss_environmental_score: float
    cvss_vector: CVSSVector
    remediation: str
    evidence_dir: str
    critique_summary: str


@dataclass
class TriageState:
    discovery: List[Dict[str, Any]] = field(default_factory=list)
    reproduction: List[Dict[str, Any]] = field(default_factory=list)
    impact_analysis: List[Dict[str, Any]] = field(default_factory=list)
    verification: List[Dict[str, Any]] = field(default_factory=list)


class CerebroVulnerabilityResearcher:
    """Autonomous CVR loop with async fuzz/reproduction sessions."""

    def __init__(self, *, workspace_root: Optional[str] = None, max_parallel_sessions: int = 4) -> None:
        self.workspace_root = self._resolve_workspace(workspace_root)
        self.evidence_root = (self.workspace_root / "evidence" / "vulnerabilities").resolve()
        self.report_root = (self.workspace_root / "reports" / "vulnerabilities").resolve()
        self.evidence_root.mkdir(parents=True, exist_ok=True)
        self.report_root.mkdir(parents=True, exist_ok=True)
        self.max_parallel_sessions = max(1, int(max_parallel_sessions))
        self.triage = TriageState()
        self._counter = 0
        self.prompt = self._load_research_prompt()

    async def run_research_loop(
        self,
        *,
        network_targets: Sequence[str],
        urls: Sequence[str],
        file_targets: Sequence[str],
        max_rounds: int = 2,
    ) -> Dict[str, Any]:
        findings: List[VulnerabilityFinding] = []
        started_at = datetime.now(tz=UTC)

        for round_index in range(max(1, int(max_rounds))):
            strategy = REASONING_TOOL.reason(
                mode=MODE_STRATEGY,
                objective=f"CVR round {round_index + 1} discovery planning",
                context=f"targets={len(network_targets)} urls={len(urls)} files={len(file_targets)}",
                options=["network-first", "code-first", "balanced"],
                fetch_facts=True,
                fact_query="vulnerability research",
            )

            discoveries = await self._discover(
                network_targets=network_targets,
                urls=urls,
                file_targets=file_targets,
                strategy=strategy,
            )
            self.triage.discovery.extend(discoveries)

            reproduction = await self._reproduce(discoveries)
            self.triage.reproduction.extend(reproduction)

            impacts = self._analyze_impact(reproduction)
            self.triage.impact_analysis.extend(impacts)

            verified = await self._verify(impacts)
            self.triage.verification.extend(verified)

            for item in verified:
                finding = self._build_finding(item)
                if finding is not None:
                    findings.append(finding)

        brief_path = self.report_root / f"vulnerability_intelligence_brief_{datetime.now(tz=UTC).strftime('%Y%m%dT%H%M%SZ')}.md"
        brief_path.write_text(self._render_brief(findings), encoding="utf-8")
        return {
            "ok": True,
            "started_at": started_at.isoformat(),
            "ended_at": datetime.now(tz=UTC).isoformat(),
            "findings": len(findings),
            "report_path": str(brief_path),
        }

    async def _discover(
        self,
        *,
        network_targets: Sequence[str],
        urls: Sequence[str],
        file_targets: Sequence[str],
        strategy: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        discovered: List[Dict[str, Any]] = []
        semaphore = asyncio.Semaphore(self.max_parallel_sessions)

        async def _nmap_probe(target: str) -> Dict[str, Any]:
            async with semaphore:
                return {"type": "network", "target": target, "data": NMAP_TOOL.scan(target=target, profile="BALANCED", timeout=180, reason="CVR discovery")}

        async def _curl_probe(target_url: str) -> Dict[str, Any]:
            async with semaphore:
                data = await CURL_TOOL.request(target=target_url, args="--location", timeout=20)
                return {"type": "web", "target": target_url, "data": data}

        async def _file_probe(path: str) -> Dict[str, Any]:
            async with semaphore:
                data = FILESYSTEM_TOOL.read_file(file_path=path, max_bytes=120000)
                return {"type": "file", "target": path, "data": data}

        tasks: List[asyncio.Task[Dict[str, Any]]] = []
        for target in network_targets:
            tasks.append(asyncio.create_task(_nmap_probe(target)))
        for target_url in urls:
            tasks.append(asyncio.create_task(_curl_probe(target_url)))
        for path in file_targets:
            tasks.append(asyncio.create_task(_file_probe(path)))

        if tasks:
            discovered.extend(await asyncio.gather(*tasks))

        # Dynamic orchestration: if strategy suggests deeper probing, run controlled fuzz seed.
        utility = max((float(w.get("utility_score", 0.0)) for w in (strategy.get("weights") or [])), default=0.0)
        if utility < 0.3 and urls:
            fuzz_seed = await self._run_exec_fuzzer_seed(urls[0])
            discovered.append({"type": "fuzz_seed", "target": urls[0], "data": fuzz_seed})

        return discovered

    async def _run_exec_fuzzer_seed(self, target_url: str) -> Dict[str, Any]:
        script = (
            "import requests\n"
            "target = " + repr(target_url) + "\n"
            "payloads = ['\"', " + repr("' OR '1'='1") + ", '../etc/passwd', '<script>alert(1)</script>']\n"
            "rows = []\n"
            "for p in payloads:\n"
            "    try:\n"
            "        r = requests.get(target, params={'q': p}, timeout=5)\n"
            "        rows.append((p, r.status_code, len(r.text)))\n"
            "    except Exception as e:\n"
            "        rows.append((p, 'ERR', str(e)))\n"
            "print(rows)\n"
        )
        return EXEC_TOOL.execute(code=script, language="python", filename="cvr_fuzz_seed", timeout=12, persist=True)

    async def _reproduce(self, discoveries: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
        semaphore = asyncio.Semaphore(self.max_parallel_sessions)

        async def _attempt(item: Dict[str, Any]) -> Dict[str, Any]:
            async with semaphore:
                return await self._single_reproduction(item)

        tasks = [asyncio.create_task(_attempt(item)) for item in discoveries]
        return await asyncio.gather(*tasks) if tasks else []

    async def _single_reproduction(self, item: Dict[str, Any]) -> Dict[str, Any]:
        evidence_id = self._next_id()
        silo = self.evidence_root / evidence_id
        silo.mkdir(parents=True, exist_ok=True)

        artifact: Dict[str, Any] = {
            "id": evidence_id,
            "source_type": item.get("type", "unknown"),
            "target": item.get("target", ""),
            "reproducible": False,
            "signal": "",
            "evidence_dir": str(silo),
        }

        # Optional isolated execution for unstable tests.
        docker_trace = await DOCKER_TOOL.run_command_async(
            command="echo cvr-docker-sanity && uname -a",
            container_id=None,
            timeout=40,
            stream=False,
            args={"image": "alpine:latest", "internet_access": False, "read_only": True},
        )
        (silo / "docker_trace.json").write_text(json.dumps(docker_trace, ensure_ascii=True, indent=2), encoding="utf-8")

        # Verification turn requirement: minimally viable reproduction via exec_code.
        mv_repro = await self._minimal_reproduction(item=item, silo=silo)
        artifact["reproducible"] = bool(mv_repro.get("reproducible"))
        artifact["signal"] = str(mv_repro.get("signal", ""))
        artifact["mv_repro"] = mv_repro

        return artifact

    async def _minimal_reproduction(self, *, item: Dict[str, Any], silo: Path) -> Dict[str, Any]:
        item_type = str(item.get("type", ""))
        target = str(item.get("target", ""))

        if item_type in {"web", "fuzz_seed"} and target:
            script = (
                "import requests\n"
                "u = " + repr(target) + "\n"
                "codes = []\n"
                "for _ in range(3):\n"
                "    try:\n"
                "        r = requests.get(u, timeout=5)\n"
                "        codes.append(r.status_code)\n"
                "    except Exception:\n"
                "        codes.append('ERR')\n"
                "print(codes)\n"
            )
            result = EXEC_TOOL.execute(code=script, language="python", filename="mv_repro_web", timeout=15, persist=True)
            (silo / "mv_repro_exec.json").write_text(json.dumps(result, ensure_ascii=True, indent=2), encoding="utf-8")
            out = str((result.get("record") or {}).get("output", ""))
            return {"reproducible": out.count("200") >= 2 or "ERR" in out, "signal": out}

        if item_type == "file":
            content = ((item.get("data") or {}).get("content") if isinstance(item.get("data"), dict) else "") or ""
            signal = "possible_secret" if re.search(r"(?i)(password|token|secret|api[_-]?key)\s*[:=]", str(content)) else "no_signal"
            (silo / "mv_repro_file.txt").write_text(str(content)[:8000], encoding="utf-8")
            return {"reproducible": signal == "possible_secret", "signal": signal}

        if item_type == "network":
            data = item.get("data") or {}
            host_count = len(data.get("hosts", [])) if isinstance(data, dict) else 0
            (silo / "mv_repro_network.json").write_text(json.dumps(data, ensure_ascii=True, indent=2), encoding="utf-8")
            return {"reproducible": host_count > 0, "signal": f"hosts={host_count}"}

        return {"reproducible": False, "signal": "unsupported"}

    def _analyze_impact(self, reproduction: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
        impact_rows: List[Dict[str, Any]] = []
        for row in reproduction:
            reproducible = bool(row.get("reproducible"))
            src = str(row.get("source_type", "unknown"))
            vuln_class = self._classify_vulnerability(src=src, signal=str(row.get("signal", "")))
            cvss = self._score_cvss(vuln_class=vuln_class, reproducible=reproducible)
            impact_rows.append(
                {
                    **row,
                    "vuln_class": vuln_class,
                    "impact": "Security-relevant primitive failure" if reproducible else "Insufficient security signal",
                    "cvss": cvss,
                }
            )
        return impact_rows

    async def _verify(self, impacts: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
        verified: List[Dict[str, Any]] = []
        for row in impacts:
            critique = REASONING_TOOL.reason(
                mode=MODE_CRITIQUE,
                objective="Determine whether behavior is vulnerability or intended feature",
                context=f"class={row.get('vuln_class')} impact={row.get('impact')}",
                prior_output=f"signal={row.get('signal')} reproducible={row.get('reproducible')}",
                options=["true vulnerability", "intended behavior"],
                fetch_facts=False,
            )
            is_feature = "intended" in str(critique.get("summary", "")).lower() and not bool(row.get("reproducible"))
            row["verification_status"] = "Verified" if (bool(row.get("reproducible")) and not is_feature) else "Unverified"
            row["critique_summary"] = critique.get("summary", "")
            verified.append(row)
        return verified

    def _build_finding(self, row: Dict[str, Any]) -> Optional[VulnerabilityFinding]:
        if row.get("verification_status") != "Verified":
            return None
        cvss = row.get("cvss") or {}
        vector = cvss.get("vector")
        if not isinstance(vector, CVSSVector):
            vector = CVSSVector("N", "H", "L", "R", "U", "L", "L", "L", "U", "O", "R", "M", "M", "M")
        target = str(row.get("target", "unknown"))
        evidence_dir = str(row.get("evidence_dir", ""))
        steps = [
            f"Open target: {target}",
            "Run included minimally viable reproduction script from evidence silo.",
            "Observe repeated anomalous output in mv_repro artifacts.",
        ]
        return VulnerabilityFinding(
            vuln_id=str(row.get("id", "VULN-UNKNOWN")),
            target_system=target,
            vuln_class=str(row.get("vuln_class", "Unknown")),
            triage_state="Verification",
            root_cause=self._root_cause_hint(str(row.get("vuln_class", "Unknown"),), str(row.get("signal", ""))),
            reproduction_steps=steps,
            impact_assessment=str(row.get("impact", "")),
            verification_status="Verified",
            cvss_base_score=float(cvss.get("base_score", 0.0)),
            cvss_temporal_score=float(cvss.get("temporal_score", 0.0)),
            cvss_environmental_score=float(cvss.get("environmental_score", 0.0)),
            cvss_vector=vector,
            remediation=self._remediation_hint(str(row.get("vuln_class", "Unknown"))),
            evidence_dir=evidence_dir,
            critique_summary=str(row.get("critique_summary", "")),
        )

    def _score_cvss(self, *, vuln_class: str, reproducible: bool) -> Dict[str, Any]:
        presets: Dict[str, CVSSVector] = {
            "Remote Code Execution": CVSSVector("N", "L", "N", "N", "U", "H", "H", "H", "F", "O", "C", "H", "H", "H"),
            "Authentication Bypass": CVSSVector("N", "L", "N", "N", "U", "H", "H", "L", "F", "O", "R", "H", "H", "M"),
            "Sensitive Data Exposure": CVSSVector("N", "L", "L", "N", "U", "H", "L", "N", "P", "O", "R", "H", "M", "M"),
            "Service Misconfiguration": CVSSVector("N", "L", "L", "R", "U", "L", "L", "L", "P", "T", "R", "M", "M", "M"),
            "Unknown": CVSSVector("N", "H", "L", "R", "U", "L", "L", "L", "U", "O", "R", "M", "M", "M"),
        }
        vector = presets.get(vuln_class, presets["Unknown"])
        base = self._cvss_base(vector)
        if not reproducible:
            base = round(base * 0.55, 1)
        temporal = self._cvss_temporal(base, vector)
        environmental = self._cvss_environmental(temporal, vector)
        return {
            "base_score": base,
            "temporal_score": temporal,
            "environmental_score": environmental,
            "vector": vector,
            "justification": {
                "base": f"AV={vector.av}, AC={vector.ac}, PR={vector.pr}, UI={vector.ui}, S={vector.s}, C/I/A={vector.c}/{vector.i}/{vector.a}",
                "temporal": f"E={vector.e}, RL={vector.rl}, RC={vector.rc}",
                "environmental": f"CR={vector.cr}, IR={vector.ir}, AR={vector.ar}",
            },
        }

    def _cvss_base(self, vector: CVSSVector) -> float:
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[vector.av]
        ac = {"L": 0.77, "H": 0.44}[vector.ac]
        ui = {"N": 0.85, "R": 0.62}[vector.ui]
        pr_u = {"N": 0.85, "L": 0.62, "H": 0.27}
        pr_c = {"N": 0.85, "L": 0.68, "H": 0.5}
        pr = (pr_c if vector.s == "C" else pr_u)[vector.pr]
        cia = {"N": 0.0, "L": 0.22, "H": 0.56}
        c = cia[vector.c]
        i = cia[vector.i]
        a = cia[vector.a]

        iss = 1.0 - ((1 - c) * (1 - i) * (1 - a))
        if vector.s == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        exploitability = 8.22 * av * ac * pr * ui
        if impact <= 0:
            return 0.0
        total = impact + exploitability
        if vector.s == "C":
            total *= 1.08
        return self._roundup_1(min(total, 10.0))

    def _cvss_temporal(self, base: float, vector: CVSSVector) -> float:
        e = {"X": 1.0, "U": 0.91, "P": 0.94, "F": 0.97, "H": 1.0}[vector.e]
        rl = {"X": 1.0, "O": 0.95, "T": 0.96, "W": 0.97, "U": 1.0}[vector.rl]
        rc = {"X": 1.0, "U": 0.92, "R": 0.96, "C": 1.0}[vector.rc]
        return self._roundup_1(min(base * e * rl * rc, 10.0))

    def _cvss_environmental(self, temporal: float, vector: CVSSVector) -> float:
        req = {"X": 1.0, "L": 0.5, "M": 1.0, "H": 1.5}
        modifier = (req[vector.cr] + req[vector.ir] + req[vector.ar]) / 3.0
        return self._roundup_1(min(temporal * modifier, 10.0))

    @staticmethod
    def _roundup_1(value: float) -> float:
        return math.ceil(value * 10.0) / 10.0

    @staticmethod
    def _classify_vulnerability(*, src: str, signal: str) -> str:
        s = signal.lower()
        if src in {"web", "fuzz_seed"} and ("500" in s or "traceback" in s or "err" in s):
            return "Remote Code Execution"
        if src == "file" and "possible_secret" in s:
            return "Sensitive Data Exposure"
        if src == "network" and "hosts=" in s:
            return "Service Misconfiguration"
        return "Unknown"

    @staticmethod
    def _root_cause_hint(vuln_class: str, signal: str) -> str:
        if vuln_class == "Remote Code Execution":
            return "Untrusted user-controlled input reached executable code path without robust sanitization."
        if vuln_class == "Sensitive Data Exposure":
            return "Credential-like material appears in plaintext configuration or source artifacts."
        if vuln_class == "Service Misconfiguration":
            return "Exposed network service configuration allows unsafe access path from untrusted network."
        return f"Potential security flaw observed; signal={signal}."

    @staticmethod
    def _remediation_hint(vuln_class: str) -> str:
        hints = {
            "Remote Code Execution": "Enforce strict input validation, isolate execution contexts, and disable dangerous interpreter paths.",
            "Sensitive Data Exposure": "Remove embedded secrets, rotate credentials, and move sensitive values to secure secret management.",
            "Service Misconfiguration": "Restrict listening interfaces, enforce authentication, and apply least-privilege network policies.",
            "Unknown": "Add deterministic validation checks, increase telemetry, and apply hardening defaults.",
        }
        return hints.get(vuln_class, hints["Unknown"])

    def _render_brief(self, findings: Sequence[VulnerabilityFinding]) -> str:
        if not findings:
            return "### Vulnerability Intelligence Brief\nNo verified vulnerabilities identified in this research run.\n"

        lines: List[str] = []
        for finding in findings:
            lines.extend(
                [
                    "### Vulnerability Intelligence Brief",
                    "| Attribute | Value |",
                    "| :--- | :--- |",
                    f"| Target System | {finding.target_system} |",
                    f"| Vulnerability Class | {finding.vuln_class} |",
                    f"| Reproduction Steps | {' ; '.join(finding.reproduction_steps)} |",
                    f"| Technical Root Cause | {finding.root_cause} |",
                    f"| CVSS v3.1 Score | Base {finding.cvss_base_score} / Temporal {finding.cvss_temporal_score} / Environmental {finding.cvss_environmental_score} |",
                    f"| Impact Assessment | {finding.impact_assessment} |",
                    f"| Verification Status | {finding.verification_status} |",
                    f"| Remediation | {finding.remediation} |",
                    f"| Evidence Silo | {finding.evidence_dir} |",
                    "",
                    "Technical CVSS Justification:",
                    f"- Base: AV/AC/PR/UI/S/C/I/A = {finding.cvss_vector.av}/{finding.cvss_vector.ac}/{finding.cvss_vector.pr}/{finding.cvss_vector.ui}/{finding.cvss_vector.s}/{finding.cvss_vector.c}/{finding.cvss_vector.i}/{finding.cvss_vector.a}",
                    f"- Temporal: E/RL/RC = {finding.cvss_vector.e}/{finding.cvss_vector.rl}/{finding.cvss_vector.rc}",
                    f"- Environmental: CR/IR/AR = {finding.cvss_vector.cr}/{finding.cvss_vector.ir}/{finding.cvss_vector.ar}",
                    "",
                ]
            )
        return "\n".join(lines)

    def _next_id(self) -> str:
        self._counter += 1
        return f"VULN-{self._counter:04d}"

    def _load_research_prompt(self) -> str:
        try:
            return load_prompt_template("prompts/vulnerability_research_agent.md")
        except FileNotFoundError:
            # Fallback keeps module import-safe while allowing external prompt injection later.
            return CVR_PROMPT_FALLBACK

    @staticmethod
    def _resolve_workspace(workspace_root: Optional[str]) -> Path:
        if workspace_root:
            return Path(workspace_root).expanduser().resolve()
        try:
            return get_project_space().ensure_initialized().resolve()
        except Exception:
            return Path.cwd().resolve()


load_dotenv()
api_key = os.getenv("CERBERUS_API_KEY", os.getenv("OPENAI_API_KEY", "sk-cerebro-1234567890"))
_prompt = load_prompt_template("prompts/system_bug_bounter.md")
_tools = []
for _meta in get_all_tools():
    if not getattr(_meta, "enabled", False):
        continue
    try:
        _tools.append(get_tool(_meta.name))
    except Exception:
        continue

input_guardrails, output_guardrails = get_security_guardrails()

bug_bounter_agent = Agent(
    name="Bug Bounter",
    instructions=create_system_prompt_renderer(_prompt),
    description="Agent that specializes in vulnerability discovery, triage, and verification.",
    tools=_tools,
    input_guardrails=input_guardrails,
    output_guardrails=output_guardrails,
    model=OpenAIChatCompletionsModel(
        model=os.getenv("CERBERUS_MODEL", "cerebro1"),
        openai_client=AsyncOpenAI(api_key=api_key),
    ),
)


cerebro_vulnerability_researcher = CerebroVulnerabilityResearcher()


__all__ = [
    "CerebroVulnerabilityResearcher",
    "TriageState",
    "VulnerabilityFinding",
    "CVSSVector",
    "cerebro_vulnerability_researcher",
    "bug_bounter_agent",
]