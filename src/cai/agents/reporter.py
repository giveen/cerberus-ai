"""Cerebro Executive Intelligence Reporter (CEIR).

Autonomous reporting engine that inventories artifacts, maps findings to
OWASP/MITRE/CVSS, performs redaction audit, and exports structured reports.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
import hashlib
import html
import json
import math
import os
from pathlib import Path
import re
from typing import Any, Dict, Iterable, List, Literal, Mapping, Optional, Sequence, Tuple

from dotenv import load_dotenv
from openai import AsyncOpenAI

from cai.sdk.agents import Agent, OpenAIChatCompletionsModel
from cai.tools.all_tools import get_all_tools, get_tool
from cai.tools.misc.reasoning import MODE_CRITIQUE, MODE_STRATEGY, REASONING_TOOL
from cai.tools.reconnaissance.filesystem import PathGuard as FilesystemPathGuard
from cai.tools.workspace import get_project_space
from cai.util import create_system_prompt_renderer, load_prompt_template


@dataclass
class ArtifactRecord:
    artifact_id: str
    path: str
    category: Literal["flag", "hash", "log", "generic"]
    size_bytes: int
    sha256: str
    preview: str
    discovered_at: str


@dataclass
class ComplianceMapping:
    owasp_top10: str
    mitre_attack: str
    cvss_version: Literal["3.1", "4.0"]
    cvss_vector: str
    cvss_base_score: float


@dataclass
class VulnerabilityEntry:
    finding_id: str
    title: str
    severity: str
    impact: str
    technical_details: str
    reproduction_steps: List[str]
    remediation: List[str]
    objective_validator_data: Dict[str, Any]
    compliance: ComplianceMapping
    artifact_path: str
    artifact_sha256: str
    chain_of_custody_link: str


@dataclass
class RedactionAuditResult:
    safe: bool
    issues: List[str] = field(default_factory=list)
    redacted_tokens: int = 0
    output_preview: str = ""


class CerebroFileWriter:
    """PathGuard-backed report exporter for workspace-safe writes."""

    def __init__(self, workspace_root: Path) -> None:
        self.workspace_root = workspace_root.resolve()
        self._guard = FilesystemPathGuard(self.workspace_root, self._audit)

    def write_text(self, relative_path: str, content: str, *, encoding: str = "utf-8") -> Dict[str, Any]:
        resolved = self._guard.validate_path(relative_path, action="ceir_write_report", mode="write")
        resolved.parent.mkdir(parents=True, exist_ok=True)
        resolved.write_text(content, encoding=encoding)
        return {
            "ok": True,
            "path": str(resolved),
            "bytes_written": len(content.encode(encoding, errors="ignore")),
        }

    @staticmethod
    def _audit(_event: str, _payload: Dict[str, Any]) -> None:
        return


class CerebroReportingAgent:
    """Professional-grade CEIR synthesis and reporting engine (zero inheritance)."""

    FLAG_PATTERNS: Tuple[re.Pattern[str], ...] = (
        re.compile(r"FLAG\{[^\n\r\}]{1,200}\}", re.IGNORECASE),
        re.compile(r"CTF\{[^\n\r\}]{1,200}\}", re.IGNORECASE),
    )
    HASH_PATTERNS: Tuple[re.Pattern[str], ...] = (
        re.compile(r"\b[a-fA-F0-9]{64}\b"),
        re.compile(r"\b[a-fA-F0-9]{40}\b"),
        re.compile(r"\b[a-fA-F0-9]{32}\b"),
    )
    LOG_EXTS = {".log", ".jsonl", ".pcap", ".txt", ".md", ".json", ".csv", ".xml", ".yaml", ".yml"}

    PII_RE = re.compile(
        r"(?:\b[\w.%-]+@[\w.-]+\.[A-Za-z]{2,}\b|\b\d{3}-\d{2}-\d{4}\b|\b(?:AKIA|ASIA)[A-Z0-9]{16}\b)",
        re.IGNORECASE,
    )
    TOKEN_RE = re.compile(r"\b(?:sess|session|token|jwt|bearer)[_\-:=\s]+[A-Za-z0-9_\-\.]{12,}\b", re.IGNORECASE)

    def __init__(self, *, workspace_root: Optional[str] = None, max_read_bytes: int = 2_000_000) -> None:
        self.workspace_root = self._resolve_workspace(workspace_root)
        self.report_root = (self.workspace_root / "reports" / "ceir").resolve()
        self.report_root.mkdir(parents=True, exist_ok=True)
        self.writer = CerebroFileWriter(self.workspace_root)
        self.max_read_bytes = max(65_536, int(max_read_bytes))

        self._tool_names = {meta.name for meta in get_all_tools() if getattr(meta, "enabled", False)}

    def synthesize_intelligence_report(
        self,
        *,
        objective_validator_impact: Optional[Sequence[Dict[str, Any]]] = None,
        target_scope: str = "unknown",
        export_formats: Sequence[Literal["markdown", "html"]] = ("markdown", "html"),
        prepared_for: str = "Security Leadership",
    ) -> Dict[str, Any]:
        artifacts = self._inventory_artifacts()
        csem_context = self._cross_reference_csem(artifacts)
        findings = self._build_vulnerability_entries(
            artifacts=artifacts,
            objective_validator_impact=objective_validator_impact or [],
            csem_context=csem_context,
        )

        markdown_report = self._render_markdown(
            findings=findings,
            artifacts=artifacts,
            csem_context=csem_context,
            target_scope=target_scope,
            prepared_for=prepared_for,
        )

        audit = self._redaction_audit(markdown_report)
        if not audit.safe:
            markdown_report = self._apply_redactions(markdown_report)
            audit = self._redaction_audit(markdown_report)

        report_stamp = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%SZ")
        out_paths: Dict[str, str] = {}

        if "markdown" in export_formats:
            rel_md = f"reports/ceir/ceir_report_{report_stamp}.md"
            self.writer.write_text(rel_md, markdown_report)
            out_paths["markdown"] = str((self.workspace_root / rel_md).resolve())

        if "html" in export_formats:
            html_report = self._render_html(markdown_report)
            rel_html = f"reports/ceir/ceir_report_{report_stamp}.html"
            self.writer.write_text(rel_html, html_report)
            out_paths["html"] = str((self.workspace_root / rel_html).resolve())

        return {
            "ok": True,
            "artifact_count": len(artifacts),
            "finding_count": len(findings),
            "redaction_audit": asdict(audit),
            "report_paths": out_paths,
        }

    def _inventory_artifacts(self) -> List[ArtifactRecord]:
        roots = [Path("/workspace/loot"), Path("/workspace/evidence")]
        if not roots[0].exists() and not roots[1].exists():
            roots = [self.workspace_root / "loot", self.workspace_root / "evidence"]

        rows: List[ArtifactRecord] = []
        seen: set[str] = set()

        for root in roots:
            if not root.exists():
                continue
            for path in root.rglob("*"):
                if not path.is_file():
                    continue
                resolved = path.resolve()
                key = str(resolved)
                if key in seen:
                    continue
                seen.add(key)

                try:
                    blob = path.read_bytes()
                except Exception:
                    continue
                size = len(blob)
                head = blob[: min(size, self.max_read_bytes)]
                preview = head.decode("utf-8", errors="replace")

                category = self._categorize_artifact(path=path, preview=preview)
                sha = hashlib.sha256(blob).hexdigest()

                rows.append(
                    ArtifactRecord(
                        artifact_id=f"ART-{len(rows)+1:05d}",
                        path=str(resolved),
                        category=category,
                        size_bytes=size,
                        sha256=sha,
                        preview=self._trim(preview, 600),
                        discovered_at=datetime.now(tz=UTC).isoformat(),
                    )
                )

        # Resource management: keep a dense in-memory index for high-speed cross-reference.
        self._artifact_memory_index: Dict[str, List[str]] = {}
        for art in rows:
            token_key = f"{art.category}:{Path(art.path).suffix}:{len(art.preview)}"
            self._artifact_memory_index.setdefault(token_key, []).append(art.artifact_id)

        return rows

    def _cross_reference_csem(self, artifacts: Sequence[ArtifactRecord]) -> Dict[str, Any]:
        if "query_memory" not in self._tool_names:
            return {"available": False, "methodologies": []}

        query_tool = get_tool("query_memory")
        seed_terms = self._derive_memory_terms(artifacts)
        methodologies: List[str] = []
        for term in seed_terms[:8]:
            try:
                response = str(query_tool(query=f"successful methodology for {term}", top_k=3, kb="all"))
            except Exception:
                continue
            if response and "No documents found" not in response:
                methodologies.append(response)

        if "read_key_findings" in self._tool_names:
            try:
                key_findings = str(get_tool("read_key_findings")())
                if key_findings.strip():
                    methodologies.append(key_findings)
            except Exception:
                pass

        return {
            "available": True,
            "methodologies": methodologies,
            "summary": self._trim("\n".join(methodologies), 1800),
        }

    def _build_vulnerability_entries(
        self,
        *,
        artifacts: Sequence[ArtifactRecord],
        objective_validator_impact: Sequence[Dict[str, Any]],
        csem_context: Dict[str, Any],
    ) -> List[VulnerabilityEntry]:
        entries: List[VulnerabilityEntry] = []
        impact_rows = list(objective_validator_impact)

        for idx, art in enumerate(artifacts[:2000]):
            impact = impact_rows[idx % len(impact_rows)] if impact_rows else {}
            title = self._derive_finding_title(art, impact)
            severity = self._derive_severity(art, impact)
            details = self._derive_technical_details(art, csem_context)

            compliance = self._map_compliance(artifact=art, impact=impact, severity=severity)

            entries.append(
                VulnerabilityEntry(
                    finding_id=f"CEIR-{idx+1:04d}",
                    title=title,
                    severity=severity,
                    impact=str(impact.get("impact", "Impact not provided by Objective Validator.")),
                    technical_details=details,
                    reproduction_steps=self._derive_repro_steps(art),
                    remediation=self._derive_remediation(art, compliance),
                    objective_validator_data=dict(impact),
                    compliance=compliance,
                    artifact_path=art.path,
                    artifact_sha256=art.sha256,
                    chain_of_custody_link=f"sha256:{art.sha256}",
                )
            )

        return entries

    def _map_compliance(self, *, artifact: ArtifactRecord, impact: Dict[str, Any], severity: str) -> ComplianceMapping:
        owasp = self._map_owasp(artifact.preview, artifact.path)
        mitre = self._map_mitre(artifact.preview, artifact.path)
        cvss_version, vector, score = self._score_cvss(artifact=artifact, impact=impact, severity=severity)
        return ComplianceMapping(
            owasp_top10=owasp,
            mitre_attack=mitre,
            cvss_version=cvss_version,
            cvss_vector=vector,
            cvss_base_score=score,
        )

    def _map_owasp(self, preview: str, path: str) -> str:
        text = f"{preview}\n{path}".lower()
        mapping: List[Tuple[str, str]] = [
            (r"sql|sqli|union select|database error", "A03:2021 - Injection"),
            (r"auth|session|jwt|token|cookie", "A07:2021 - Identification and Authentication Failures"),
            (r"access denied|forbidden|idor|insecure direct object", "A01:2021 - Broken Access Control"),
            (r"xss|script>|onerror=|onclick=", "A03:2021 - Injection"),
            (r"secret|credential|api[_\- ]?key|private key", "A02:2021 - Cryptographic Failures"),
            (r"log4j|struts|outdated|version", "A06:2021 - Vulnerable and Outdated Components"),
            (r"misconfig|directory listing|debug=true|trace", "A05:2021 - Security Misconfiguration"),
            (r"integrity|checksum|signature", "A08:2021 - Software and Data Integrity Failures"),
            (r"logging|monitor|alert", "A09:2021 - Security Logging and Monitoring Failures"),
        ]
        for patt, tag in mapping:
            if re.search(patt, text, flags=re.IGNORECASE):
                return tag
        return "A04:2021 - Insecure Design"

    def _map_mitre(self, preview: str, path: str) -> str:
        text = f"{preview}\n{path}".lower()
        mapping: List[Tuple[str, str]] = [
            (r"ssh|remote command|run_ssh", "T1021 - Remote Services"),
            (r"powershell|bash -c|python -c|cmd.exe", "T1059 - Command and Scripting Interpreter"),
            (r"cron|scheduled task|systemd", "T1053 - Scheduled Task/Job"),
            (r"exfil|upload|smb|http post", "T1041 - Exfiltration Over C2 Channel"),
            (r"credential|password|hashdump|token", "T1003 - OS Credential Dumping"),
            (r"scan|nmap|enumeration|service discovery", "T1046 - Network Service Discovery"),
        ]
        for patt, tag in mapping:
            if re.search(patt, text, flags=re.IGNORECASE):
                return tag
        return "T1595 - Active Scanning"

    def _score_cvss(self, *, artifact: ArtifactRecord, impact: Dict[str, Any], severity: str) -> Tuple[Literal["3.1", "4.0"], str, float]:
        req_version = str(impact.get("cvss_version", "3.1")).strip()
        version: Literal["3.1", "4.0"] = "4.0" if req_version == "4.0" else "3.1"

        impact_conf = str(impact.get("confidentiality", "L")).upper()[:1] or "L"
        impact_integ = str(impact.get("integrity", "L")).upper()[:1] or "L"
        impact_avail = str(impact.get("availability", "L")).upper()[:1] or "L"

        av = "N" if artifact.category in {"log", "flag", "hash"} else "L"
        ac = "L"
        pr = "N" if severity in {"Critical", "High"} else "L"
        ui = "N"
        scope = "C" if "cross" in str(impact.get("scope", "")).lower() else "U"

        cia = {"N": 0.0, "L": 0.22, "H": 0.56}
        av_map = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
        ac_map = {"L": 0.77, "H": 0.44}
        pr_u = {"N": 0.85, "L": 0.62, "H": 0.27}
        pr_c = {"N": 0.85, "L": 0.68, "H": 0.5}
        ui_map = {"N": 0.85, "R": 0.62}

        c = cia.get(impact_conf, 0.22)
        i = cia.get(impact_integ, 0.22)
        a = cia.get(impact_avail, 0.22)

        iss = 1.0 - ((1 - c) * (1 - i) * (1 - a))
        if scope == "U":
            impact_sub = 6.42 * iss
        else:
            impact_sub = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        pr_weight = (pr_c if scope == "C" else pr_u).get(pr, 0.62)
        exploitability = 8.22 * av_map[av] * ac_map[ac] * pr_weight * ui_map[ui]

        if impact_sub <= 0:
            base = 0.0
        else:
            total = impact_sub + exploitability
            if scope == "C":
                total *= 1.08
            base = self._roundup_1(min(total, 10.0))

        if version == "4.0":
            # Lightweight v4 approximation for consistent CEIR output.
            base = self._roundup_1(min(base * 1.03, 10.0))
            vector = f"CVSS:4.0/AV:{av}/AC:{ac}/AT:N/PR:{pr}/UI:{ui}/VC:{impact_conf}/VI:{impact_integ}/VA:{impact_avail}"
        else:
            vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{scope}/C:{impact_conf}/I:{impact_integ}/A:{impact_avail}"

        return version, vector, base

    def _render_markdown(
        self,
        *,
        findings: Sequence[VulnerabilityEntry],
        artifacts: Sequence[ArtifactRecord],
        csem_context: Dict[str, Any],
        target_scope: str,
        prepared_for: str,
    ) -> str:
        high = sum(1 for f in findings if f.severity in {"Critical", "High"})
        medium = sum(1 for f in findings if f.severity == "Medium")
        low = max(0, len(findings) - high - medium)

        lines: List[str] = [
            "# Cerebro Executive Intelligence Report",
            "",
            "## Report Header",
            f"- Report Title: CEIR Vulnerability Intelligence Report",
            f"- Date Generated: {datetime.now(tz=UTC).isoformat()}",
            f"- Prepared For: {prepared_for}",
            f"- Scope: {target_scope}",
            "- Classification: Internal Security Assessment",
            "",
            "## Executive Summary",
            f"- Risk Overview: {high} high-impact findings identified across {len(artifacts)} artifacts.",
            f"- Key Findings Scorecard: Critical/High={high}, Medium={medium}, Low={low}",
            "- Critical Action Items: Prioritize remediation of findings with CVSS base score >= 8.0.",
            "",
            "## Technical Details",
        ]

        for finding in findings[:120]:
            lines.extend(
                [
                    f"### {finding.finding_id} - {finding.title}",
                    f"- Severity: {finding.severity}",
                    f"- Impact: {finding.impact}",
                    f"- OWASP Top 10: {finding.compliance.owasp_top10}",
                    f"- MITRE ATT&CK: {finding.compliance.mitre_attack}",
                    f"- CVSS v{finding.compliance.cvss_version}: {finding.compliance.cvss_base_score} ({finding.compliance.cvss_vector})",
                    f"- Evidence Path: {finding.artifact_path}",
                    f"- Chain of Custody: {finding.chain_of_custody_link}",
                    "- Reproduction Steps:",
                ]
            )
            for step in finding.reproduction_steps:
                lines.append(f"  - {step}")
            lines.extend(
                [
                    "- Remediation Plan:",
                ]
            )
            for rec in finding.remediation:
                lines.append(f"  - {rec}")
            lines.append("")

        lines.extend(
            [
                "## Remediation Plan",
                "- Patch vulnerable components and rotate credentials exposed in logs/configs.",
                "- Enforce strong authentication/session controls and minimize token lifetime.",
                "- Apply network hardening to reduce attack surface and unauthorized reachability.",
                "- Establish continuous telemetry review mapped to MITRE ATT&CK detections.",
                "",
                "## CSEM Cross-Reference",
                f"- Memory Available: {csem_context.get('available', False)}",
                "- Methodology Highlights:",
            ]
        )
        for line in (csem_context.get("methodologies") or [])[:10]:
            lines.append(f"  - {self._trim(str(line), 400)}")

        return "\n".join(lines) + "\n"

    def _render_html(self, markdown_report: str) -> str:
        esc = html.escape(markdown_report)
        return (
            "<!DOCTYPE html>\n"
            "<html lang='en'>\n"
            "<head>\n"
            "  <meta charset='UTF-8'/>\n"
            "  <meta name='viewport' content='width=device-width, initial-scale=1.0'/>\n"
            "  <title>Cerebro Executive Intelligence Report</title>\n"
            "  <style>\n"
            "    :root { --ink:#0f172a; --muted:#475569; --bg:#f8fafc; --accent:#0b7285; --panel:#ffffff; }\n"
            "    body { margin:0; padding:0; background:linear-gradient(180deg,#e2e8f0 0%, #f8fafc 100%); color:var(--ink); font-family: 'IBM Plex Sans', 'Segoe UI', sans-serif; }\n"
            "    .wrap { max-width:1100px; margin:24px auto; background:var(--panel); border-radius:12px; box-shadow:0 12px 24px rgba(15,23,42,.12); overflow:hidden; }\n"
            "    .brand { padding:20px 28px; background:var(--accent); color:#fff; font-weight:700; letter-spacing:.03em; }\n"
            "    .content { padding:24px 28px; }\n"
            "    pre { white-space:pre-wrap; word-wrap:break-word; margin:0; font-family:'IBM Plex Mono','Consolas',monospace; font-size:13px; color:#0f172a; }\n"
            "  </style>\n"
            "</head>\n"
            "<body>\n"
            "  <div class='wrap'>\n"
            "    <div class='brand'>CERBERUS AI | CEIR Report</div>\n"
            "    <div class='content'><pre>" + esc + "</pre></div>\n"
            "  </div>\n"
            "</body>\n"
            "</html>\n"
        )

    def _redaction_audit(self, text: str) -> RedactionAuditResult:
        findings: List[str] = []
        pii_hits = self.PII_RE.findall(text)
        token_hits = self.TOKEN_RE.findall(text)
        if pii_hits:
            findings.append(f"PII patterns detected: {len(pii_hits)}")
        if token_hits:
            findings.append(f"Session/token patterns detected: {len(token_hits)}")

        critique = REASONING_TOOL.reason(
            mode=MODE_CRITIQUE,
            objective="Perform redaction audit before report export",
            context=f"pii_hits={len(pii_hits)}, token_hits={len(token_hits)}",
            options=["approve export", "redact sensitive values", "halt export"],
            fetch_facts=False,
        )
        if (critique.get("pivot_request") or {}).get("required"):
            findings.append("MODE_CRITIQUE requested additional redaction.")

        return RedactionAuditResult(
            safe=(len(findings) == 0),
            issues=findings,
            redacted_tokens=len(pii_hits) + len(token_hits),
            output_preview=self._trim(text, 200),
        )

    def _apply_redactions(self, text: str) -> str:
        out = self.PII_RE.sub("[REDACTED_PII]", text)
        out = self.TOKEN_RE.sub("[REDACTED_TOKEN]", out)
        return out

    def _categorize_artifact(self, *, path: Path, preview: str) -> Literal["flag", "hash", "log", "generic"]:
        if any(p.search(preview) for p in self.FLAG_PATTERNS):
            return "flag"
        if any(p.search(preview) for p in self.HASH_PATTERNS):
            return "hash"
        if path.suffix.lower() in self.LOG_EXTS:
            return "log"
        return "generic"

    def _derive_memory_terms(self, artifacts: Sequence[ArtifactRecord]) -> List[str]:
        terms: List[str] = []
        for art in artifacts[:1000]:
            path_bits = [x for x in re.split(r"[/_\-.]+", art.path) if x]
            terms.extend(path_bits[-3:])
            terms.extend(re.findall(r"[A-Za-z]{4,}", art.preview)[:4])
        dedup: List[str] = []
        seen: set[str] = set()
        for t in terms:
            key = t.lower()
            if key in seen:
                continue
            seen.add(key)
            dedup.append(t)
        return dedup

    def _derive_finding_title(self, artifact: ArtifactRecord, impact: Dict[str, Any]) -> str:
        if artifact.category == "flag":
            return "Sensitive Flag Exposure"
        if artifact.category == "hash":
            return "Credential Hash Artifact Discovery"
        if artifact.category == "log":
            if "error" in artifact.preview.lower() or "traceback" in artifact.preview.lower():
                return "Service Error Leakage"
            return "Operational Log-Derived Security Signal"
        return str(impact.get("title", "Security-relevant Artifact Detected"))

    def _derive_severity(self, artifact: ArtifactRecord, impact: Dict[str, Any]) -> str:
        if impact.get("severity"):
            return str(impact.get("severity"))
        if artifact.category == "flag":
            return "Critical"
        if artifact.category == "hash":
            return "High"
        if artifact.category == "log":
            return "Medium"
        return "Low"

    def _derive_technical_details(self, artifact: ArtifactRecord, csem_context: Dict[str, Any]) -> str:
        return (
            f"Artifact class={artifact.category}; source={artifact.path}; size={artifact.size_bytes} bytes. "
            f"Cross-reference methodology excerpt: {self._trim(str(csem_context.get('summary', 'N/A')), 260)}"
        )

    def _derive_repro_steps(self, artifact: ArtifactRecord) -> List[str]:
        return [
            f"Locate artifact at {artifact.path}",
            "Recompute SHA-256 and verify chain-of-custody integrity.",
            "Inspect artifact content and confirm security-relevant signal.",
            "Map observed behavior to OWASP/MITRE classification.",
        ]

    def _derive_remediation(self, artifact: ArtifactRecord, compliance: ComplianceMapping) -> List[str]:
        steps = [
            "Apply least-privilege access controls to evidence and output directories.",
            "Enable strict secret redaction in logs and telemetry sinks.",
            "Implement deterministic validation checks in CI for recurrence prevention.",
        ]
        if "Injection" in compliance.owasp_top10:
            steps.insert(0, "Enforce input validation and parameterized execution paths.")
        if "Credential" in artifact.preview or artifact.category == "hash":
            steps.insert(0, "Rotate exposed credentials and invalidate active session tokens.")
        return steps

    @staticmethod
    def _trim(text: str, max_chars: int = 800) -> str:
        data = (text or "").strip()
        if len(data) <= max_chars:
            return data
        return data[: max_chars - 20] + " ...[truncated]"

    @staticmethod
    def _roundup_1(value: float) -> float:
        return math.ceil(float(value) * 10.0) / 10.0

    @staticmethod
    def _resolve_workspace(workspace_root: Optional[str]) -> Path:
        if workspace_root:
            return Path(workspace_root).expanduser().resolve()
        try:
            return get_project_space().ensure_initialized().resolve()
        except Exception:
            return Path.cwd().resolve()


load_dotenv()
_report_prompt = load_prompt_template("prompts/system_reporting_agent.md")
_tools: List[Any] = []
for _meta in get_all_tools():
    if not getattr(_meta, "enabled", False):
        continue
    try:
        _tools.append(get_tool(_meta.name))
    except Exception:
        continue


reporting_agent = Agent(
    name="CEIR Reporting Agent",
    instructions=create_system_prompt_renderer(_report_prompt),
    description="Professional-grade intelligence synthesis and reporting engine for Cerberus AI.",
    tools=_tools,
    model=OpenAIChatCompletionsModel(
        model=os.getenv("CEREBRO_MODEL", "cerebro1"),
        openai_client=AsyncOpenAI(api_key=os.getenv("CEREBRO_API_KEY", os.getenv("OPENAI_API_KEY", "sk-placeholder"))),
    ),
)


cerebro_reporting_agent = CerebroReportingAgent()


def transfer_to_reporting_agent(**kwargs: Any) -> Agent:
    _ = kwargs
    return reporting_agent


__all__ = [
    "ArtifactRecord",
    "ComplianceMapping",
    "VulnerabilityEntry",
    "RedactionAuditResult",
    "CerebroFileWriter",
    "CerebroReportingAgent",
    "cerebro_reporting_agent",
    "reporting_agent",
    "transfer_to_reporting_agent",
]
