"""Cerebro Executive Cortex (CEC).

State-aware, token-efficient reasoning engine for local execution that implements
the Think-Act-Observe loop with CATR validation and PathGuard-backed persistence.
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
from cerberus.agents import Agent, OpenAIChatCompletionsModel, function_tool
from cerberus.tools.all_tools import get_all_tools, get_tool
from cerberus.tools.misc.reasoning import MODE_CRITIQUE, MODE_STRATEGY, REASONING_TOOL, think
from cerberus.tools.reconnaissance.filesystem import PathGuard as FilesystemPathGuard
from cerberus.tools.workspace import get_project_space
from cerberus.util import create_system_prompt_renderer, load_prompt_template


class MissionPhase(str, Enum):
    RECON = "recon"
    EXPLOITATION = "exploitation"
    POST_EX = "post-ex"


@dataclass
class ThoughtRecord:
    strategy_id: str
    confidence: float
    phase: MissionPhase
    summary: str
    branches: List[Dict[str, Any]] = field(default_factory=list)
    requires_confirmation: bool = False
    created_at: str = field(default_factory=lambda: datetime.now(tz=UTC).isoformat())


@dataclass
class MissionState:
    mission_id: str
    objective: str
    target: str
    phase: MissionPhase = MissionPhase.RECON
    turn: int = 0
    tool_history: List[Dict[str, Any]] = field(default_factory=list)
    thought_history: List[ThoughtRecord] = field(default_factory=list)
    strategic_digest: List[str] = field(default_factory=list)
    csem_cache: Dict[str, str] = field(default_factory=dict)


class CerebroFileWriter:
    """PathGuard-backed writer used for mission plans and audit traces."""

    def __init__(self, workspace_root: Path) -> None:
        self.workspace_root = workspace_root.resolve()
        self._guard = FilesystemPathGuard(self.workspace_root, self._audit)

    def write_text(self, relative_path: str, content: str, *, encoding: str = "utf-8") -> Dict[str, Any]:
        destination = self._guard.validate_path(relative_path, action="cec_write", mode="write")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content, encoding=encoding)
        return {"ok": True, "path": str(destination), "bytes_written": len(content.encode(encoding, errors="ignore"))}

    def write_json(self, relative_path: str, payload: Mapping[str, Any]) -> Dict[str, Any]:
        return self.write_text(relative_path, json.dumps(dict(payload), ensure_ascii=True, indent=2))

    @staticmethod
    def _audit(_event: str, _payload: Dict[str, Any]) -> None:
        return


class CerebroCortex:
    """High-velocity reasoning loop with state, validation, branching, and audit."""

    def __init__(
        self,
        *,
        workspace_root: Optional[str] = None,
        confidence_threshold: float = 0.62,
        max_branches: int = 2,
    ) -> None:
        self.workspace_root = self._resolve_workspace(workspace_root)
        self.missions_root = (self.workspace_root / "missions").resolve()
        self.missions_root.mkdir(parents=True, exist_ok=True)

        self.writer = CerebroFileWriter(self.workspace_root)
        self.runner = CerebroAtomicRunner(workspace_root=str(self.workspace_root))
        self.confidence_threshold = max(0.0, min(1.0, float(confidence_threshold)))
        self.max_branches = max(1, int(max_branches))

        self.tools_by_name: Dict[str, Any] = {}
        for meta in get_all_tools():
            if not getattr(meta, "enabled", False):
                continue
            try:
                self.tools_by_name[meta.name] = get_tool(meta.name)
            except Exception:
                continue

        self._executed_fingerprints: set[str] = set()

    def run_think_act_observe(
        self,
        *,
        objective: str,
        target: str,
        context: str = "",
        candidate_actions: Optional[Sequence[Dict[str, Any]]] = None,
        max_turns: int = 3,
        operator_approved_low_confidence: bool = False,
    ) -> Dict[str, Any]:
        state = MissionState(
            mission_id=self._new_id(prefix="MIS"),
            objective=objective.strip(),
            target=target.strip() or "unknown-target",
        )

        self._persist_plan(state, {"objective": state.objective, "target": state.target, "phase": state.phase.value})

        for turn in range(1, max(1, int(max_turns)) + 1):
            state.turn = turn
            thought = self._think(state=state, context=context)
            state.thought_history.append(thought)
            self._audit_thought(state=state, thought=thought)

            if thought.requires_confirmation and not operator_approved_low_confidence:
                return self._finalize(
                    state,
                    {
                        "ok": True,
                        "status": "awaiting_operator_confirmation",
                        "message": "Low-confidence strategy requires confirmation before action execution.",
                        "pending_strategy_id": thought.strategy_id,
                    },
                )

            action = self._select_action(state=state, candidate_actions=candidate_actions)
            if not action:
                return self._finalize(state, {"ok": True, "status": "no_action", "message": "No valid tool action was selected."})

            csem_gate = self._check_csem_before_action(state=state, action=action)
            if csem_gate.get("skip", False):
                obs = {
                    "ok": True,
                    "status": "skipped_redundant",
                    "reason": csem_gate.get("reason", "CSEM indicates prior equivalent action."),
                    "tool_name": action.get("tool_name"),
                }
            else:
                obs = self._act_with_validation(state=state, action=action)

            digest = self._compress_context(obs)
            state.strategic_digest.append(digest)
            self._persist_turn(state=state, thought=thought, action=action, observation=obs, digest=digest)
            self._advance_phase(state=state, observation=obs)

            if obs.get("ok") and obs.get("status") in {"executed", "skipped_redundant"}:
                return self._finalize(state, {"ok": True, "status": obs.get("status"), "observation": obs})

        return self._finalize(state, {"ok": False, "status": "max_turns_exceeded", "message": "Reasoning loop exhausted."})

    def _think(self, *, state: MissionState, context: str) -> ThoughtRecord:
        compact_context = self._trim(context, 700)
        compact_digest = self._trim("\n".join(state.strategic_digest[-3:]), 700)

        summary = (
            f"Phase={state.phase.value}. Objective={self._trim(state.objective, 120)}. "
            f"Target={self._trim(state.target, 80)}. "
            f"RecentDigest={self._trim(compact_digest or compact_context or 'none', 180)}"
        )

        confidence = self._estimate_confidence(summary=summary, context=context)
        branches = self._build_branches(state=state, context=context, confidence=confidence)
        strategy_id = self._new_id(prefix="STRAT")

        return ThoughtRecord(
            strategy_id=strategy_id,
            confidence=confidence,
            phase=state.phase,
            summary=self._trim(summary, 280),
            branches=branches,
            requires_confirmation=(confidence < self.confidence_threshold),
        )

    def _select_action(
        self,
        *,
        state: MissionState,
        candidate_actions: Optional[Sequence[Dict[str, Any]]],
    ) -> Optional[Dict[str, Any]]:
        candidates = list(candidate_actions or [])
        if candidates:
            for row in candidates:
                tool_name = str(row.get("tool_name", "")).strip()
                if tool_name in self.tools_by_name:
                    params = dict(row.get("parameters") or {})
                    return {"tool_name": tool_name, "parameters": params, "source": "user_candidates"}

        phase_preference = {
            MissionPhase.RECON: ["nmap_scan", "execute_cli_command", "verify_target_availability"],
            MissionPhase.EXPLOITATION: ["netcat", "execute_cli_command"],
            MissionPhase.POST_EX: ["filesystem_search", "query_memory", "execute_cli_command"],
        }
        for tool_name in phase_preference.get(state.phase, []):
            if tool_name not in self.tools_by_name:
                continue
            params = self._default_parameters(tool_name=tool_name, target=state.target)
            return {"tool_name": tool_name, "parameters": params, "source": "phase_default"}

        return None

    def _default_parameters(self, *, tool_name: str, target: str) -> Dict[str, Any]:
        if tool_name == "verify_target_availability":
            return {"target": target}
        if tool_name == "query_memory":
            return {"query": f"target {target} previous findings", "top_k": 3, "kb": "all"}
        if tool_name == "execute_cli_command":
            return {"command": f"echo cec recon target={target}", "timeout_seconds": 20}
        if tool_name == "nmap_scan":
            return {"target": target, "ports": "top-100"}
        return {"target": target}

    def _check_csem_before_action(self, *, state: MissionState, action: Mapping[str, Any]) -> Dict[str, Any]:
        tool_name = str(action.get("tool_name", ""))
        params = dict(action.get("parameters") or {})
        fingerprint = self._action_fingerprint(tool_name=tool_name, target=state.target, params=params)

        if fingerprint in self._executed_fingerprints:
            return {"skip": True, "reason": "Equivalent action already executed in this mission loop."}

        if "query_memory" not in self.tools_by_name:
            return {"skip": False}

        if fingerprint in state.csem_cache:
            prior = state.csem_cache[fingerprint]
            if prior and "No documents found" not in prior:
                return {"skip": True, "reason": "CSEM indicates prior coverage for this target/action."}
            return {"skip": False}

        query = f"{tool_name} {state.target} {' '.join(sorted(params.keys()))}"
        try:
            response = self._invoke_tool(self.tools_by_name["query_memory"], query=query, top_k=3, kb="all")
            text = str(response)
        except Exception:
            text = ""

        state.csem_cache[fingerprint] = text
        if text and "No documents found" not in text:
            return {"skip": True, "reason": "CSEM hit prevented redundant operation."}
        return {"skip": False}

    def _act_with_validation(self, *, state: MissionState, action: Mapping[str, Any]) -> Dict[str, Any]:
        tool_name = str(action.get("tool_name", ""))
        params = dict(action.get("parameters") or {})

        atomic = self.runner.execute_atomic(
            tool_name=tool_name,
            parameters=params,
            retry_limit=1,
            isolation_timeout_seconds=45,
        )
        if atomic.get("ok", False):
            self._executed_fingerprints.add(self._action_fingerprint(tool_name=tool_name, target=state.target, params=params))
            state.tool_history.append({"tool": tool_name, "params": params, "ok": True, "via": "catr"})
            return {"ok": True, "status": "executed", "tool": tool_name, "result": atomic}

        corrected = self._self_correct_with_critique(tool_name=tool_name, params=params, atomic_error=str(atomic.get("error", "")))
        if not corrected:
            state.tool_history.append({"tool": tool_name, "params": params, "ok": False, "via": "catr", "error": atomic.get("error")})
            return {"ok": False, "status": "validation_failed", "tool": tool_name, "result": atomic}

        retried = self.runner.execute_atomic(
            tool_name=tool_name,
            parameters=corrected,
            retry_limit=0,
            isolation_timeout_seconds=45,
        )
        if retried.get("ok", False):
            self._executed_fingerprints.add(self._action_fingerprint(tool_name=tool_name, target=state.target, params=corrected))
            state.tool_history.append({"tool": tool_name, "params": corrected, "ok": True, "via": "catr_recovery"})
            return {
                "ok": True,
                "status": "executed_after_critique",
                "tool": tool_name,
                "result": retried,
                "correction": {"original": params, "corrected": corrected},
            }

        state.tool_history.append({"tool": tool_name, "params": corrected, "ok": False, "via": "catr_recovery", "error": retried.get("error")})
        return {
            "ok": False,
            "status": "validation_failed_after_critique",
            "tool": tool_name,
            "result": retried,
            "correction": {"original": params, "corrected": corrected},
        }

    def _self_correct_with_critique(self, *, tool_name: str, params: Dict[str, Any], atomic_error: str) -> Optional[Dict[str, Any]]:
        try:
            REASONING_TOOL.reason(
                mode=MODE_CRITIQUE,
                objective="Repair invalid tool action parameters for secure execution.",
                context=f"tool={tool_name} error={atomic_error} params={self._trim(json.dumps(params, ensure_ascii=True), 1000)}",
                options=["drop unknown keys", "sanitize write path", "reduce risky flags"],
                fetch_facts=False,
            )
        except Exception:
            pass

        tool_callable = self.tools_by_name.get(tool_name)
        if tool_callable is None:
            return None

        allowed = self._allowed_param_names(tool_callable)
        corrected = {k: v for k, v in params.items() if (not allowed or k in allowed)}
        for key, value in list(corrected.items()):
            lowered = key.lower()
            if not isinstance(value, str):
                continue
            if lowered in {"path", "output", "output_path", "file", "file_path", "destination"}:
                corrected[key] = self._sanitize_workspace_relative_path(value)

        if corrected == params:
            return None
        return corrected

    def _allowed_param_names(self, tool_callable: Any) -> set[str]:
        try:
            signature = inspect.signature(tool_callable)
        except (TypeError, ValueError):
            return set()
        names: set[str] = set()
        for name, param in signature.parameters.items():
            if param.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.VAR_POSITIONAL):
                continue
            names.add(name)
        return names

    def _compress_context(self, observation: Mapping[str, Any]) -> str:
        raw = self._trim(json.dumps(dict(observation), ensure_ascii=True, default=str), 8000)
        if len(raw) <= 1000:
            return raw

        lines = re.split(r"[\n\\r]+", raw)
        key_lines = [
            ln.strip()
            for ln in lines
            if re.search(r"port|open|closed|service|vuln|error|timeout|cve|status", ln, flags=re.IGNORECASE)
        ]

        ports = sorted(set(re.findall(r"\b([1-9][0-9]{0,4})/(?:tcp|udp)\b", raw, flags=re.IGNORECASE)))
        port_summary = f"ports={','.join(ports[:30])}" if ports else "ports=none"

        head = self._trim(" | ".join(key_lines[:8]) or raw[:600], 800)
        digest = f"StrategicDigest: {port_summary}; highlights={head}"
        return self._trim(digest, 980)

    def _build_branches(self, *, state: MissionState, context: str, confidence: float) -> List[Dict[str, Any]]:
        uncertain = confidence < 0.58 or bool(re.search(r"waf|hardened|unknown|filtered|unstable", context, flags=re.IGNORECASE))
        if not uncertain:
            return []

        branches = [
            {
                "name": "Plan A",
                "intent": "Low-noise validation route",
                "step": "Validate target availability and collect minimal fingerprint before deeper scans.",
            },
            {
                "name": "Plan B",
                "intent": "Resilient fallback route",
                "step": "Use alternate telemetry and narrow-scope probes to bypass hardened controls.",
            },
        ]
        return branches[: self.max_branches]

    def _advance_phase(self, *, state: MissionState, observation: Mapping[str, Any]) -> None:
        payload = json.dumps(dict(observation), ensure_ascii=True, default=str).lower()
        if state.phase == MissionPhase.RECON and re.search(r"vuln|exploit|weakness|credential|rce", payload):
            state.phase = MissionPhase.EXPLOITATION
        elif state.phase == MissionPhase.EXPLOITATION and re.search(r"shell|session|loot|post", payload):
            state.phase = MissionPhase.POST_EX

    def _audit_thought(self, *, state: MissionState, thought: ThoughtRecord) -> None:
        rel = f"missions/{state.mission_id}/thought_audit.jsonl"
        row = {
            "mission_id": state.mission_id,
            "turn": state.turn,
            "strategy_id": thought.strategy_id,
            "confidence": thought.confidence,
            "phase": thought.phase.value,
            "summary": thought.summary,
            "requires_confirmation": thought.requires_confirmation,
            "branches": thought.branches,
            "timestamp": thought.created_at,
        }
        existing = ""
        audit_path = (self.workspace_root / rel).resolve()
        if audit_path.exists():
            existing = audit_path.read_text(encoding="utf-8")
        line = json.dumps(row, ensure_ascii=True)
        self.writer.write_text(rel, existing + line + "\n")

    def _persist_plan(self, state: MissionState, plan: Mapping[str, Any]) -> None:
        rel = f"missions/{state.mission_id}/plan.json"
        payload = {
            "mission_id": state.mission_id,
            "objective": state.objective,
            "target": state.target,
            "phase": state.phase.value,
            "generated_at": datetime.now(tz=UTC).isoformat(),
            "plan": dict(plan),
        }
        self.writer.write_json(rel, payload)

    def _persist_turn(
        self,
        *,
        state: MissionState,
        thought: ThoughtRecord,
        action: Mapping[str, Any],
        observation: Mapping[str, Any],
        digest: str,
    ) -> None:
        rel = f"missions/{state.mission_id}/turn_{state.turn:02d}.json"
        payload = {
            "mission_id": state.mission_id,
            "turn": state.turn,
            "phase": state.phase.value,
            "thought": asdict(thought),
            "action": dict(action),
            "observation": dict(observation),
            "strategic_digest": digest,
        }
        self.writer.write_json(rel, payload)

    def _finalize(self, state: MissionState, result: Mapping[str, Any]) -> Dict[str, Any]:
        rel = f"missions/{state.mission_id}/mission_state.json"
        snapshot = {
            "mission_id": state.mission_id,
            "objective": state.objective,
            "target": state.target,
            "phase": state.phase.value,
            "turn": state.turn,
            "strategic_digest": state.strategic_digest,
            "tool_history": state.tool_history,
            "thought_history": [asdict(item) for item in state.thought_history],
            "result": dict(result),
            "completed_at": datetime.now(tz=UTC).isoformat(),
        }
        self.writer.write_json(rel, snapshot)
        return {"ok": True, "mission_id": state.mission_id, "mission_path": str((self.workspace_root / "missions" / state.mission_id).resolve()), **dict(result)}

    @staticmethod
    def _estimate_confidence(*, summary: str, context: str) -> float:
        base = 0.72
        text = f"{summary} {context}".lower()
        if any(marker in text for marker in ("unknown", "uncertain", "hardened", "waf", "timeout", "error", "blocked")):
            base -= 0.22
        if any(marker in text for marker in ("verified", "confirmed", "reachable", "stable", "known")):
            base += 0.10
        return round(max(0.05, min(0.98, base)), 3)

    @staticmethod
    def _action_fingerprint(*, tool_name: str, target: str, params: Mapping[str, Any]) -> str:
        payload = json.dumps({"tool": tool_name, "target": target, "params": dict(params)}, ensure_ascii=True, sort_keys=True)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:24]

    def _invoke_tool(self, tool_callable: Any, **kwargs: Any) -> Any:
        if inspect.iscoroutinefunction(tool_callable):
            return asyncio.run(tool_callable(**kwargs))
        out = tool_callable(**kwargs)
        if inspect.isawaitable(out):
            return asyncio.run(self._await_any(out))
        return out

    @staticmethod
    async def _await_any(awaitable: Any) -> Any:
        return await awaitable

    @staticmethod
    def _sanitize_workspace_relative_path(value: str) -> str:
        cleaned = value.strip().replace("\\", "/")
        if cleaned.startswith("/"):
            cleaned = cleaned.lstrip("/")
        if ".." in cleaned.split("/"):
            cleaned = cleaned.replace("..", "")
        if not cleaned:
            cleaned = "missions/cec_output.txt"
        if not cleaned.startswith("missions/"):
            cleaned = f"missions/{cleaned}"
        return cleaned

    @staticmethod
    def _trim(text: str, limit: int) -> str:
        if len(text) <= limit:
            return text
        return text[: max(0, limit - 16)].rstrip() + " ...[trimmed]"

    @staticmethod
    def _new_id(*, prefix: str) -> str:
        ts = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%SZ")
        nonce = hashlib.sha256(os.urandom(12)).hexdigest()[:8]
        return f"{prefix}-{ts}-{nonce}"

    @staticmethod
    def _resolve_workspace(workspace_root: Optional[str]) -> Path:
        if workspace_root:
            return Path(workspace_root).expanduser().resolve()
        try:
            return get_project_space().ensure_initialized().resolve()
        except Exception:
            return Path.cwd().resolve()


@function_tool
def cec_think_act_observe(
    objective: str,
    target: str,
    context: str = "",
    max_turns: int = 3,
    operator_approved_low_confidence: bool = False,
) -> str:
    """Run the CerebroCortex Think-Act-Observe loop and return mission summary."""
    cortex = CerebroCortex()
    result = cortex.run_think_act_observe(
        objective=objective,
        target=target,
        context=context,
        max_turns=max_turns,
        operator_approved_low_confidence=operator_approved_low_confidence,
    )
    return json.dumps(result, ensure_ascii=True)


load_dotenv(override=False)
api_key = os.getenv("CERBERUS_API_KEY", os.getenv("OPENAI_API_KEY", ""))

thought_agent_system_prompt = load_prompt_template("prompts/system_thought_router.md")
thought_agent = Agent(
    name="ThoughtAgent",
    model=OpenAIChatCompletionsModel(
        model=os.getenv("CERBERUS_MODEL", "cerebro1"),
        openai_client=AsyncOpenAI(api_key=api_key),
    ),
    description="State-aware Cerebro Executive Cortex router for concise mission planning.",
    instructions=create_system_prompt_renderer(thought_agent_system_prompt),
    tools=[think, cec_think_act_observe],
)


__all__ = ["CerebroCortex", "CerebroFileWriter", "MissionPhase", "cec_think_act_observe", "thought_agent"]
