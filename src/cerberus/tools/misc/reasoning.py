"""Structured Cognitive Engine for Cerberus AI.

Provides deterministic reasoning utilities with cognitive modes, truth anchoring,
self-correction pivots, execution weighting, and forensic logging.
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import re
import threading
from typing import Any, Dict, List, Optional, Sequence

from pydantic import BaseModel, Field, ValidationError, field_validator

from cerberus.memory.logic import clean_data
from cerberus.repl.ui.logging import get_cerberus_logger
from cerberus.agents import function_tool
from cerberus.tools.workspace import get_project_space


MODE_STRATEGY = "MODE_STRATEGY"
MODE_CRITIQUE = "MODE_CRITIQUE"
MODE_RISK_ASSESSMENT = "MODE_RISK_ASSESSMENT"
_ALLOWED_MODES = {MODE_STRATEGY, MODE_CRITIQUE, MODE_RISK_ASSESSMENT}


class ReasoningRequest(BaseModel):
    mode: str = Field(default=MODE_STRATEGY)
    objective: str = Field(min_length=1, max_length=2000)
    context: str = Field(default="", max_length=8000)
    prior_output: str = Field(default="", max_length=8000)
    options: List[str] = Field(default_factory=list)
    fetch_facts: bool = Field(default=False)
    fact_query: str = Field(default="", max_length=512)

    @field_validator("mode")
    @classmethod
    def _mode_valid(cls, value: str) -> str:
        mode = str(value).strip().upper()
        if mode not in _ALLOWED_MODES:
            raise ValueError("Unsupported reasoning mode")
        return mode

    @field_validator("options")
    @classmethod
    def _normalize_options(cls, value: List[str]) -> List[str]:
        return [str(v).strip() for v in value if str(v).strip()][:8]


@dataclass
class PivotRequest:
    required: bool
    reason: str
    new_tactic: str
    confidence: float


@dataclass
class WeightedOption:
    option: str
    success_probability: float
    risk_score: float
    utility_score: float


class CerebroReasoningTool:
    """Deterministic, LLM-agnostic reasoning engine with forensic transparency."""

    def __init__(self) -> None:
        self._workspace = get_project_space().ensure_initialized().resolve()
        self._reasoning_log = (self._workspace / "reasoning_log.jsonl").resolve()
        self._state_file = (self._workspace / "state.txt").resolve()
        self._logger = get_cerberus_logger()
        self._lock = threading.Lock()

    def reason(
        self,
        *,
        mode: str,
        objective: str,
        context: str = "",
        prior_output: str = "",
        options: Optional[Sequence[str]] = None,
        fetch_facts: bool = False,
        fact_query: str = "",
    ) -> Dict[str, Any]:
        try:
            request = ReasoningRequest(
                mode=mode,
                objective=objective,
                context=context,
                prior_output=prior_output,
                options=list(options or []),
                fetch_facts=fetch_facts,
                fact_query=fact_query,
            )
        except ValidationError as exc:
            return {
                "ok": False,
                "error": {
                    "code": "validation_error",
                    "message": str(exc),
                },
            }

        facts = self._fetch_facts_sync(query=request.fact_query or request.objective) if request.fetch_facts else []
        weighted = self._weight_options(request.objective, request.options, request.context)

        if request.mode == MODE_STRATEGY:
            reasoning_steps = self._strategy_steps(request, facts, weighted)
        elif request.mode == MODE_CRITIQUE:
            reasoning_steps = self._critique_steps(request, facts, weighted)
        else:
            reasoning_steps = self._risk_steps(request, facts, weighted)

        pivot = self._build_pivot_if_needed(request, reasoning_steps)
        summary = self.summarize_chain(reasoning_steps)

        response = {
            "ok": True,
            "mode": request.mode,
            "agent_id": self._agent_id(),
            "timestamp": datetime.now(tz=UTC).isoformat(),
            "objective": request.objective,
            "truth_anchors": facts,
            "weights": [asdict(w) for w in weighted],
            "pivot_request": asdict(pivot),
            "reasoning_steps": reasoning_steps,
            "summary": summary,
        }
        self._write_reasoning_log(response)
        return clean_data(response)

    def summarize_chain(self, steps: Sequence[str], max_points: int = 6, max_chars: int = 900) -> str:
        selected = [str(s).strip() for s in steps if str(s).strip()][: max(1, int(max_points))]
        if not selected:
            return "No reasoning steps recorded."
        text = "\n".join(f"- {line}" for line in selected)
        if len(text) <= max_chars:
            return text
        head = text[: max_chars // 2].rstrip()
        tail = text[-max_chars // 3 :].lstrip()
        return f"{head}\n... [summarized] ...\n{tail}"

    # ------------------------------------------------------------------
    # Cognitive modes
    # ------------------------------------------------------------------

    def _strategy_steps(self, req: ReasoningRequest, facts: List[Dict[str, Any]], weighted: List[WeightedOption]) -> List[str]:
        steps = [
            f"Define mission objective: {req.objective}",
            "Map prerequisite access and dependencies.",
            "Build phased execution tree: recon -> validation -> action -> verification.",
        ]
        if facts:
            steps.append(f"Anchor strategy on {len(facts)} verified fact(s).")
        if weighted:
            best = max(weighted, key=lambda item: item.utility_score)
            steps.append(
                f"Prefer option '{best.option}' (utility={best.utility_score:.3f}, success={best.success_probability:.3f}, risk={best.risk_score:.3f})."
            )
        steps.append("Define rollback checkpoints before each high-impact operation.")
        return steps

    def _critique_steps(self, req: ReasoningRequest, facts: List[Dict[str, Any]], weighted: List[WeightedOption]) -> List[str]:
        prior = req.prior_output.strip()
        failure_markers = [
            "timeout",
            "failed",
            "error",
            "exception",
            "permission denied",
            "refused",
            "false positive",
            "not vulnerable",
        ]
        detected = [marker for marker in failure_markers if marker in prior.lower()]

        steps = [
            "Evaluate evidence quality and reproducibility.",
            f"Detected failure markers: {', '.join(detected) if detected else 'none'}.",
            "Classify claim confidence: verified / weak / contradictory.",
        ]
        if facts:
            steps.append("Cross-check prior output against anchored facts and citations.")
        if weighted:
            alt = sorted(weighted, key=lambda item: item.utility_score, reverse=True)
            if len(alt) > 1:
                steps.append(f"Alternative option candidate: {alt[1].option}.")
        steps.append("Recommend pivot if confidence is weak or contradictory.")
        return steps

    def _risk_steps(self, req: ReasoningRequest, facts: List[Dict[str, Any]], weighted: List[WeightedOption]) -> List[str]:
        risky_terms = ["exploit", "rce", "dos", "fuzz", "overflow", "delete", "drop", "restart"]
        indicators = [term for term in risky_terms if term in req.objective.lower()]

        steps = [
            "Identify blast radius (service, data, network dependencies).",
            f"High-risk indicators: {', '.join(indicators) if indicators else 'none'}.",
            "Estimate failure impact and recovery complexity.",
            "Require pre-checks (health endpoint, backup, timeout guardrails).",
        ]
        if facts:
            steps.append("Leverage observed system facts to refine risk estimate.")
        if weighted:
            worst = max(weighted, key=lambda item: item.risk_score)
            steps.append(f"Highest-risk candidate: {worst.option} (risk={worst.risk_score:.3f}).")
        return steps

    # ------------------------------------------------------------------
    # Option weighting and pivots
    # ------------------------------------------------------------------

    def _weight_options(self, objective: str, options: Sequence[str], context: str) -> List[WeightedOption]:
        candidates = list(options)
        if not candidates:
            candidates = ["Option A", "Option B"]

        out: List[WeightedOption] = []
        for idx, option in enumerate(candidates):
            base_success = 0.62 - (idx * 0.08)
            risk = 0.28 + (idx * 0.12)

            text = f"{objective} {context} {option}".lower()
            if any(word in text for word in ("verified", "proof", "known-good", "validated")):
                base_success += 0.12
                risk -= 0.05
            if any(word in text for word in ("exploit", "dos", "unsafe", "crash", "destructive")):
                base_success -= 0.10
                risk += 0.16
            if any(word in text for word in ("backup", "readonly", "safe", "simulation")):
                risk -= 0.10

            success = max(0.05, min(0.98, base_success))
            risk = max(0.02, min(0.98, risk))
            utility = (0.70 * success) - (0.30 * risk)

            out.append(
                WeightedOption(
                    option=option,
                    success_probability=round(success, 3),
                    risk_score=round(risk, 3),
                    utility_score=round(utility, 3),
                )
            )
        return out

    def _build_pivot_if_needed(self, req: ReasoningRequest, steps: Sequence[str]) -> PivotRequest:
        if req.mode != MODE_CRITIQUE:
            return PivotRequest(required=False, reason="No critique failure detected.", new_tactic="", confidence=0.0)

        text = f"{req.prior_output}\n" + "\n".join(steps)
        risk_hits = sum(1 for m in ("timeout", "failed", "false positive", "not vulnerable", "contradict") if m in text.lower())
        if risk_hits >= 2:
            return PivotRequest(
                required=True,
                reason="Prior plan appears unreliable under critique indicators.",
                new_tactic="Switch to deterministic validation path with independent evidence collection.",
                confidence=round(min(0.95, 0.55 + (0.10 * risk_hits)), 3),
            )
        return PivotRequest(required=False, reason="No strong failure indicators.", new_tactic="", confidence=0.18)

    # ------------------------------------------------------------------
    # Truth anchoring
    # ------------------------------------------------------------------

    def _fetch_facts_sync(self, query: str, max_facts: int = 5) -> List[Dict[str, Any]]:
        anchors: List[Dict[str, Any]] = []

        # Anchor source 1: state.txt findings.
        if self._state_file.exists():
            try:
                findings = self._state_file.read_text(encoding="utf-8", errors="replace").splitlines()
                for line in findings:
                    if query.lower() in line.lower() or any(token in line.lower() for token in self._tokens(query)):
                        anchors.append(
                            {
                                "source": "workspace_state",
                                "citation": str(self._state_file.relative_to(self._workspace)),
                                "fact": line.strip(),
                            }
                        )
                        if len(anchors) >= max_facts:
                            break
            except OSError:
                pass

        # Anchor source 2: lightweight RAG audit/query artifacts.
        rag_audit = self._workspace / ".cerberus" / "rag_engine" / "rag_audit.jsonl"
        if len(anchors) < max_facts and rag_audit.exists():
            try:
                for line in rag_audit.read_text(encoding="utf-8", errors="replace").splitlines()[-200:]:
                    if not line.strip():
                        continue
                    try:
                        row = json.loads(line)
                    except Exception:
                        continue
                    payload = json.dumps(row.get("data", {}), ensure_ascii=True)
                    if query.lower() in payload.lower() or any(token in payload.lower() for token in self._tokens(query)):
                        anchors.append(
                            {
                                "source": "rag_audit",
                                "citation": str(rag_audit.relative_to(self._workspace)),
                                "fact": payload[:240],
                            }
                        )
                        if len(anchors) >= max_facts:
                            break
            except OSError:
                pass

        return anchors[:max_facts]

    @staticmethod
    def _tokens(text: str) -> List[str]:
        return [x.lower() for x in re.findall(r"[A-Za-z0-9_\-\.]{3,}", text or "")]

    # ------------------------------------------------------------------
    # Files, logs, compatibility methods
    # ------------------------------------------------------------------

    def write_key_findings(self, findings: str) -> str:
        self._state_file.parent.mkdir(parents=True, exist_ok=True)
        with self._state_file.open("a", encoding="utf-8") as handle:
            handle.write("\n" + findings.strip() + "\n")
        return f"Successfully wrote findings to {self._state_file.name}:\n{findings}"

    def read_key_findings(self) -> str:
        if not self._state_file.exists():
            return f"{self._state_file.name} file not found. No findings have been recorded."
        data = self._state_file.read_text(encoding="utf-8", errors="replace")
        return data if data.strip() else "Not finding"

    def _write_reasoning_log(self, payload: Dict[str, Any]) -> None:
        row = {
            "timestamp": datetime.now(tz=UTC).isoformat(),
            "agent_id": self._agent_id(),
            "cycle": clean_data(payload),
        }
        with self._lock:
            self._reasoning_log.parent.mkdir(parents=True, exist_ok=True)
            with self._reasoning_log.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(row, ensure_ascii=True, default=str) + "\n")

        if self._logger is not None:
            try:
                self._logger.audit(
                    "Reasoning cycle recorded",
                    actor="reasoning",
                    data={
                        "mode": payload.get("mode"),
                        "objective": payload.get("objective"),
                        "pivot_required": (payload.get("pivot_request") or {}).get("required", False),
                    },
                    tags=["reasoning", str(payload.get("mode", "unknown"))],
                )
            except Exception:
                pass

    @staticmethod
    def _agent_id() -> str:
        for key in ("CERBERUS_AGENT_ID", "AGENT_ID", "CERBERUS_AGENT", "CERBERUS_AGENT_TYPE"):
            value = os.getenv(key, "").strip()
            if value:
                return value
        return "unknown-agent"


REASONING_TOOL = CerebroReasoningTool()


@function_tool
def thought(
    breakdowns: str = "",
    reflection: str = "",
    action: str = "",
    next_step: str = "",
    key_clues: str = "",
    ctf: Any = None,
) -> str:
    """Compatibility reasoning entrypoint with structured strategy mode behind the scenes."""
    _ = ctf
    objective = " ".join(part for part in [breakdowns, action, next_step] if part).strip() or "Build next operational strategy"
    context = "\n".join(part for part in [reflection, key_clues] if part).strip()

    result = REASONING_TOOL.reason(
        mode=MODE_STRATEGY,
        objective=objective,
        context=context,
        options=[action, next_step] if (action or next_step) else [],
        fetch_facts=True,
        fact_query=key_clues or objective,
    )
    if not result.get("ok"):
        return f"Error: {(result.get('error') or {}).get('message', 'reasoning failed')}"
    return str(result.get("summary", ""))


@function_tool
def think(thought: str = "") -> str:
    """Append a lightweight reflection entry and return compact summary.

    *thought* is your private reasoning text.  Pass the full analysis of
    the current situation as a single string.  The field is optional so
    that a missing argument does not cause a hard schema error, but you
    should always populate it with meaningful reasoning.
    """
    result = REASONING_TOOL.reason(
        mode=MODE_CRITIQUE,
        objective="Reflect on current tactical assumption",
        context=thought,
        prior_output=thought,
        options=["Option A: continue current path", "Option B: pivot to alternative validation"],
        fetch_facts=False,
    )
    if not result.get("ok"):
        return f"Error: {(result.get('error') or {}).get('message', 'reasoning failed')}"
    pivot = result.get("pivot_request") or {}
    if pivot.get("required"):
        return f"{result.get('summary', '')}\nPivot: {pivot.get('new_tactic', '')}"
    return str(result.get("summary", ""))


@function_tool
def write_key_findings(findings: str) -> str:
    """Write critical findings for future truth-anchored reasoning cycles."""
    try:
        return REASONING_TOOL.write_key_findings(findings)
    except OSError as exc:
        return f"Error writing to state.txt: {exc}"


@function_tool
def read_key_findings() -> str:
    """Read accumulated key findings from workspace state file."""
    try:
        return REASONING_TOOL.read_key_findings()
    except OSError as exc:
        return f"Error reading state.txt: {exc}"


__all__ = [
    "CerebroReasoningTool",
    "MODE_STRATEGY",
    "MODE_CRITIQUE",
    "MODE_RISK_ASSESSMENT",
    "thought",
    "think",
    "write_key_findings",
    "read_key_findings",
]
