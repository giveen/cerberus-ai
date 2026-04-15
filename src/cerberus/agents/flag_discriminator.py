"""Cerebro Objective Validator (COV).

Commercial-grade objective validator that continuously inspects shared output
streams and validates mission-critical findings via context-aware reasoning.
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
from uuid import uuid4

from openai import AsyncOpenAI

from cerberus.memory.logic import clean, clean_data
from cerberus.sdk.agents import Agent, OpenAIChatCompletionsModel
from cerberus.tools.misc.reasoning import MODE_CRITIQUE, MODE_STRATEGY, REASONING_TOOL
from cerberus.tools.sessions import ACTIVE_SESSIONS, SESSIONS_LOCK
from cerberus.tools.workspace import get_project_space

try:
    from cerberus.repl.ui.logging import get_cerberus_logger
except Exception:  # pragma: no cover - optional logger in minimal env
    get_cerberus_logger = None


_UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b"
)


@dataclass(frozen=True)
class ObjectivePattern:
    name: str
    regex: re.Pattern[str]
    category: str
    base_confidence: float


@dataclass
class ObjectiveFinding:
    finding_id: str
    timestamp: str
    category: str
    pattern_name: str
    value: str
    source: str
    context_snippet: str
    confidence: int
    critique_note: str
    objective_reached: bool
    sha256: str
    redaction_flags: List[str]


class CerebroObjectiveValidator:
    """Async objective validator with critique and forensic artifact persistence."""

    def __init__(
        self,
        *,
        workspace_root: Optional[str] = None,
        objective_patterns: Optional[Sequence[str | ObjectivePattern]] = None,
        scope_targets: Optional[Sequence[str]] = None,
        output_provider: Optional[Callable[[], Awaitable[List[Tuple[str, str]]] | List[Tuple[str, str]]]] = None,
        poll_interval_seconds: float = 0.35,
    ) -> None:
        self.workspace_root = self._resolve_workspace(workspace_root)
        self.loot_root = (self.workspace_root / "loot").resolve()
        self.report_root = (self.workspace_root / "reports" / "objectives").resolve()
        self.redaction_hook_log = (self.workspace_root / ".cerberus" / "redaction_hooks.jsonl").resolve()
        self._logger = get_cerberus_logger() if get_cerberus_logger else None
        self._poll_interval = max(0.15, float(poll_interval_seconds))
        self._output_provider = output_provider or self._default_output_provider
        self._monitor_task: Optional[asyncio.Task[None]] = None
        self._stop_event = asyncio.Event()
        self._seen: set[str] = set()
        self._session_offsets: Dict[str, int] = {}

        self.loot_root.mkdir(parents=True, exist_ok=True)
        self.report_root.mkdir(parents=True, exist_ok=True)
        self.redaction_hook_log.parent.mkdir(parents=True, exist_ok=True)

        self._patterns = self._build_patterns(objective_patterns=objective_patterns, scope_targets=scope_targets)

    async def start(self) -> None:
        """Start background monitoring loop for shared output buffers."""
        if self._monitor_task and not self._monitor_task.done():
            return
        self._stop_event.clear()
        self._monitor_task = asyncio.create_task(self._monitor_loop(), name="cerebro-objective-validator")

    async def stop(self) -> None:
        """Stop background monitoring loop."""
        self._stop_event.set()
        if self._monitor_task:
            await self._monitor_task
            self._monitor_task = None

    async def scan_output(self, *, output: str, source: str = "tool_output") -> List[ObjectiveFinding]:
        """Scan one output payload and return validated objective findings."""
        raw = str(output or "")
        if not raw.strip():
            return []

        findings: List[ObjectiveFinding] = []
        for pattern in self._patterns:
            for match in pattern.regex.finditer(raw):
                value = match.group(0).strip()
                if not value:
                    continue

                dedupe_key = hashlib.sha256(f"{pattern.name}|{value}|{source}".encode("utf-8", errors="replace")).hexdigest()
                if dedupe_key in self._seen:
                    continue
                self._seen.add(dedupe_key)

                snippet = self._extract_context(raw, match.start(), match.end())
                critique = REASONING_TOOL.reason(
                    mode=MODE_CRITIQUE,
                    objective="Validate whether objective hit is real and mission-relevant",
                    context=snippet,
                    prior_output=value,
                    options=[
                        "Treat as objective success",
                        "Treat as decoy/help text",
                    ],
                    fetch_facts=False,
                )
                confidence = self._score_confidence(pattern=pattern, value=value, snippet=snippet, critique=critique)
                reached = confidence >= 85

                critique_note = str((critique.get("summary") if isinstance(critique, dict) else "") or "No critique note")
                redaction_flags = self._run_redaction_hook(value=value, snippet=snippet, source=source)

                finding = ObjectiveFinding(
                    finding_id=str(uuid4()),
                    timestamp=datetime.now(tz=UTC).isoformat(),
                    category=pattern.category,
                    pattern_name=pattern.name,
                    value=value,
                    source=source,
                    context_snippet=snippet,
                    confidence=confidence,
                    critique_note=critique_note,
                    objective_reached=reached,
                    sha256=hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest(),
                    redaction_flags=redaction_flags,
                )

                await self._persist_forensic_artifact(finding)
                if reached:
                    await self._persist_loot(finding)
                    self._emit_objective_reached(finding)

                findings.append(finding)
        return findings

    async def _monitor_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                raw_chunks = self._output_provider()
                if asyncio.iscoroutine(raw_chunks):
                    raw_chunks = await raw_chunks

                chunks: List[Tuple[str, str]]
                if isinstance(raw_chunks, list):
                    chunks = raw_chunks
                elif isinstance(raw_chunks, tuple):
                    chunks = list(raw_chunks)
                else:
                    chunks = []

                for source, payload in chunks:
                    await self.scan_output(output=payload, source=source)
            except Exception as exc:  # pragma: no cover - non-fatal background path
                self._audit("cov_monitor_error", {"error": str(exc)})
            await asyncio.sleep(self._poll_interval)

    def _default_output_provider(self) -> List[Tuple[str, str]]:
        batches: List[Tuple[str, str]] = []
        with SESSIONS_LOCK:
            sessions = list(ACTIVE_SESSIONS.items())

        for session_id, session in sessions:
            try:
                lines = list(getattr(session, "output_buffer", []) or [])
                start = self._session_offsets.get(session_id, 0)
                if start >= len(lines):
                    self._session_offsets[session_id] = len(lines)
                    continue
                chunk = "\n".join(str(x) for x in lines[start:])
                self._session_offsets[session_id] = len(lines)
                if chunk.strip():
                    batches.append((f"session:{session_id}", chunk))
            except Exception:
                continue

        return batches

    def _build_patterns(
        self,
        *,
        objective_patterns: Optional[Sequence[str | ObjectivePattern]],
        scope_targets: Optional[Sequence[str]],
    ) -> List[ObjectivePattern]:
        defaults: List[ObjectivePattern] = [
            ObjectivePattern(
                name="rsa_private_key",
                regex=re.compile(r"-----BEGIN RSA PRIVATE KEY-----[\\s\\S]{32,}?-----END RSA PRIVATE KEY-----"),
                category="CREDENTIAL",
                base_confidence=0.96,
            ),
            ObjectivePattern(
                name="jwt_token",
                regex=re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
                category="CREDENTIAL",
                base_confidence=0.86,
            ),
            ObjectivePattern(
                name="api_secret",
                regex=re.compile(r"\b(?:api[_-]?key|secret|token)\s*[:=]\s*[A-Za-z0-9_\-]{16,}\b", re.IGNORECASE),
                category="CREDENTIAL",
                base_confidence=0.84,
            ),
            ObjectivePattern(
                name="uuid",
                regex=_UUID_RE,
                category="OBJECTIVE_TOKEN",
                base_confidence=0.72,
            ),
            ObjectivePattern(
                name="hash_md5",
                regex=re.compile(r"\b[a-fA-F0-9]{32}\b"),
                category="HASH",
                base_confidence=0.64,
            ),
            ObjectivePattern(
                name="hash_sha1",
                regex=re.compile(r"\b[a-fA-F0-9]{40}\b"),
                category="HASH",
                base_confidence=0.68,
            ),
            ObjectivePattern(
                name="hash_sha256",
                regex=re.compile(r"\b[a-fA-F0-9]{64}\b"),
                category="HASH",
                base_confidence=0.74,
            ),
            ObjectivePattern(
                name="base64_blob",
                regex=re.compile(r"\b(?:[A-Za-z0-9+/]{24,}={0,2})\b"),
                category="ENCODED_ARTIFACT",
                base_confidence=0.58,
            ),
            ObjectivePattern(
                name="ctf_flag",
                regex=re.compile(r"\b(?:HTB|CTF|FLAG|flag)\{[^\n\r\t\}]{4,128}\}\b"),
                category="CTF_FLAG",
                base_confidence=0.92,
            ),
            ObjectivePattern(
                name="confidential_keyword",
                regex=re.compile(r"\bCONFIDENTIAL\b", re.IGNORECASE),
                category="SENSITIVE_DOC",
                base_confidence=0.66,
            ),
        ]

        for target in scope_targets or ():
            clean_target = str(target).strip()
            if not clean_target:
                continue
            defaults.append(
                ObjectivePattern(
                    name=f"scope_target_{clean_target.lower().replace(' ', '_')[:40]}",
                    regex=re.compile(re.escape(clean_target)),
                    category="SENSITIVE_DOC",
                    base_confidence=0.88,
                )
            )

        for item in objective_patterns or ():
            if isinstance(item, ObjectivePattern):
                defaults.append(item)
                continue
            token = str(item).strip()
            if not token:
                continue
            if token.startswith("re:"):
                compiled = re.compile(token[3:])
                name = f"custom_regex_{len(defaults)}"
            else:
                compiled = re.compile(re.escape(token), re.IGNORECASE)
                name = f"custom_keyword_{len(defaults)}"
            defaults.append(
                ObjectivePattern(
                    name=name,
                    regex=compiled,
                    category="TARGET_OBJECTIVE",
                    base_confidence=0.8,
                )
            )

        return defaults

    def _score_confidence(
        self,
        *,
        pattern: ObjectivePattern,
        value: str,
        snippet: str,
        critique: Mapping[str, Any],
    ) -> int:
        score = pattern.base_confidence * 100.0
        lower_snippet = snippet.lower()

        if any(token in lower_snippet for token in ("/hidden", ".git", "exfil", "vault", "secrets")):
            score += 8
        if any(token in lower_snippet for token in ("--help", "usage:", "example", "template")):
            score -= 25
        if pattern.category in {"CREDENTIAL", "CTF_FLAG", "SENSITIVE_DOC"}:
            score += 7

        entropy_bonus = self._entropy_bonus(value)
        score += entropy_bonus

        pivot = critique.get("pivot_request") if isinstance(critique, Mapping) else {}
        if isinstance(pivot, Mapping) and pivot.get("required"):
            score -= 18

        return int(max(0, min(100, round(score))))

    @staticmethod
    def _entropy_bonus(value: str) -> float:
        if not value:
            return 0.0
        unique = len(set(value))
        density = unique / max(1, len(value))
        return 10.0 * density

    def _run_redaction_hook(self, *, value: str, snippet: str, source: str) -> List[str]:
        flags: List[str] = []
        payload = f"{value}\n{snippet}"
        masked = clean(payload)
        if masked != payload:
            flags.append("SECRET_PATTERN")

        if re.search(r"\b\d{3}-\d{2}-\d{4}\b", payload):
            flags.append("PII_SSN")
        if re.search(r"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b", payload):
            flags.append("PII_EMAIL")
        if re.search(r"(?<!\d)(?:\+?\d[\d\s().-]{7,}\d)(?!\d)", payload):
            flags.append("PII_PHONE")

        if flags:
            row = {
                "timestamp": datetime.now(tz=UTC).isoformat(),
                "source": source,
                "flags": flags,
                "preview": clean_data(snippet[:280]),
            }
            with self.redaction_hook_log.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(row, ensure_ascii=True) + "\n")
            self._audit("cov_redaction_hook", row)

        return flags

    async def _persist_loot(self, finding: ObjectiveFinding) -> None:
        target = self.loot_root / f"{finding.finding_id}.json"
        data = {
            "finding_id": finding.finding_id,
            "category": finding.category,
            "sha256": finding.sha256,
            "captured_at": finding.timestamp,
            "source": finding.source,
            "confidence": finding.confidence,
            "objective_reached": finding.objective_reached,
            "metadata_summary": {
                "pattern_name": finding.pattern_name,
                "context_preview": clean_data(finding.context_snippet[:240]),
                "redaction_flags": finding.redaction_flags,
            },
        }
        target.write_text(json.dumps(data, ensure_ascii=True, indent=2), encoding="utf-8")

        manifest = self.loot_root / "loot_manifest.jsonl"
        with manifest.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(data, ensure_ascii=True) + "\n")

    async def _persist_forensic_artifact(self, finding: ObjectiveFinding) -> None:
        jsonl_path = self.report_root / "objective_findings.jsonl"
        with jsonl_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(asdict(finding), ensure_ascii=True) + "\n")

        md_path = self.report_root / "forensic_objective_artifacts.md"
        action_required = "Investigate"
        if finding.objective_reached:
            action_required = "Objective Reached"
        elif finding.confidence < 40:
            action_required = "Ignore"

        with md_path.open("a", encoding="utf-8") as handle:
            handle.write(
                "\n### Forensic Artifact Report\n"
                "| Attribute | Value |\n"
                "| :--- | :--- |\n"
                f"| **Artifact ID** | `{finding.finding_id}` |\n"
                "| **Phase** | `Objective Validation` |\n"
                f"| **Process ID (PID)** | `N/A` |\n"
                f"| **Memory Offset** | `N/A` |\n"
                f"| **Data Type** | `{finding.category}` |\n"
                f"| **Confidence Score** | `{finding.confidence}%` |\n"
                f"| **Critique Note** | `{clean_data(finding.critique_note)}` |\n"
                f"| **Action Required** | `{action_required}` |\n"
            )

    def _emit_objective_reached(self, finding: ObjectiveFinding) -> None:
        payload = {
            "event": "objective_reached",
            "finding_id": finding.finding_id,
            "category": finding.category,
            "confidence": finding.confidence,
            "source": finding.source,
            "sha256": finding.sha256,
        }
        self._audit("objective_reached", payload)

    def _audit(self, message: str, payload: Mapping[str, Any]) -> None:
        if self._logger and hasattr(self._logger, "audit"):
            try:
                self._logger.audit(
                    message,
                    actor="objective_validator",
                    data=clean_data(dict(payload)),
                    tags=["objective", "cov", message],
                )
            except Exception:
                pass

    @staticmethod
    def _extract_context(text: str, start: int, end: int, radius: int = 160) -> str:
        left = max(0, start - radius)
        right = min(len(text), end + radius)
        return text[left:right].replace("\n", " ").strip()

    @staticmethod
    def _resolve_workspace(workspace_root: Optional[str]) -> Path:
        if workspace_root:
            return Path(workspace_root).expanduser().resolve()
        try:
            return get_project_space().ensure_initialized().resolve()
        except Exception:
            return Path.cwd().resolve()


cov_validator = CerebroObjectiveValidator()


flag_discriminator = Agent(
    name="Cerebro Objective Validator",
    description="Context-aware objective and evidence validator with forensic reporting.",
    instructions=(
        "Use CerebroObjectiveValidator to verify mission objectives from tool outputs, "
        "run critique before success confirmation, and persist artifacts to loot/reports."
    ),
    model=OpenAIChatCompletionsModel(
        model=os.getenv("CERBERUS_MODEL", "cerebro1"),
        openai_client=AsyncOpenAI(api_key=os.getenv("OPENAI_API_KEY", "sk-placeholder-key-for-local-models")),
    ),
    tools=[],
)


def transfer_to_flag_discriminator(**kwargs: Any) -> Agent:  # pylint: disable=unused-argument
    """Compatibility transfer function returning the COV-backed agent export."""
    return flag_discriminator


__all__ = [
    "ObjectivePattern",
    "ObjectiveFinding",
    "CerebroObjectiveValidator",
    "cov_validator",
    "flag_discriminator",
    "transfer_to_flag_discriminator",
]
