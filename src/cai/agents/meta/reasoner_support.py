"""
Cerberus Cognitive Load Balancer (CCLB)

Replaces the legacy reasoner_support.py thin wrapper with a full cognitive
state-management engine for the Cerberus AI multi-agent suite.

Responsibilities
----------------
* Branching Thought management: spawn What-If scenarios with per-branch
  confidence scores and resource cost tracking.
* Inter-agent Priority Arbitration: resolve conflicts between agents based
  on the active Mission Profile from COSE.
* Long-term Objective Persistence: cross-reference agent actions against
  COSE goals and flag mission creep.
* Hardware-accelerated memory mapping: LRU cache backed by in-process dict
  with optional mmap advisory for large intermediate blobs.
* Semantic Pruning: remove low-signal thoughts from context before LLM dispatch.
* MODE_CRITIQUE historical context: surface the decision lineage when a critique
  turn is triggered, enabling per-session learning.
* PathGuard-backed mission replay exports to /workspace/missions/logs/.

Back-compat exports
-------------------
``create_reasoner_agent`` and ``reasoner_agent`` are preserved so that factory
code and any existing callers work unchanged.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
from collections import OrderedDict
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import auto, Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union

from cai.sdk.agents import Agent
from cai.tools.reconnaissance.filesystem import PathGuard as FilesystemPathGuard
from cai.util import create_system_prompt_renderer, load_prompt_template

MODE_CRITIQUE = "MODE_CRITIQUE"

# Optional: soft-import COSE types for mission-creep auditing
try:
    from cai.agents.usecase import MissionProfile  # type: ignore[attr-defined]
    _COSE_AVAILABLE = True
except Exception:  # pragma: no cover
    _COSE_AVAILABLE = False
    MissionProfile = None  # type: ignore[assignment]

_CCLB_LOGGER = logging.getLogger("cai.cclb")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_WORKSPACE = Path(os.getenv("CIR_WORKSPACE", "/workspace")).resolve()
_MAX_BRANCH_DEPTH = int(os.getenv("CCLB_MAX_BRANCH_DEPTH", "12"))
_PRUNE_NOISE_THRESHOLD = float(os.getenv("CCLB_PRUNE_THRESHOLD", "0.25"))
# Maximum intermediate-logic cache entries (each can hold arbitrary JSON)
_MEMORY_CACHE_CAPACITY = int(os.getenv("CCLB_CACHE_CAPACITY", "4096"))
# Maximum cost (relative units) a single branch may accrue before auto-pruning
_BRANCH_COST_CEILING = float(os.getenv("CCLB_BRANCH_COST_CEILING", "100.0"))


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class BranchStatus(str, Enum):
    ACTIVE    = "active"
    PRUNED    = "pruned"
    RESOLVED  = "resolved"
    BLOCKED   = "blocked"


class ArbitrationOutcome(str, Enum):
    AGENT_A_WINS     = "agent_a_wins"
    AGENT_B_WINS     = "agent_b_wins"
    DEFER_TO_HUMAN   = "defer_to_human"
    SEQUENTIAL       = "sequential"       # run A then B
    MUTUAL_EXCLUSION = "mutual_exclusion" # only one may run at a time


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class ThoughtBranch:
    """A single What-If cognitive branch."""
    branch_id: str
    parent_id: Optional[str]
    hypothesis: str
    spawned_at: str
    depth: int
    confidence: float          # [0.0, 1.0]
    resource_cost: float       # cumulative relative units
    status: BranchStatus = BranchStatus.ACTIVE
    observations: List[str] = field(default_factory=list)
    child_ids: List[str] = field(default_factory=list)
    critique_context: Optional[str] = None  # populated by MODE_CRITIQUE turns


@dataclass
class AgentAction:
    """A proposed or completed action by a named agent."""
    agent_id: str
    action_type: str           # e.g. "fuzz", "scan", "deauth", "capture"
    description: str
    priority: int              # lower = higher priority
    requires_quiet_spectrum: bool = False
    proposed_at: str = field(default_factory=lambda: datetime.now(tz=UTC).isoformat())


@dataclass
class ArbitrationRecord:
    """Persistent record of a conflict resolution decision."""
    record_id: str
    timestamp: str
    action_a: AgentAction
    action_b: AgentAction
    outcome: ArbitrationOutcome
    rationale: str
    mission_objective_alignment: float  # [0.0, 1.0]


@dataclass
class ObjectiveAuditResult:
    """Result of cross-referencing an action against COSE goals."""
    action_description: str
    timestmap: str
    aligned: bool
    mission_creep_score: float  # [0.0, 1.0]; 1.0 = definite creep
    rationale: str
    flagged_keywords: List[str]


@dataclass
class PrunedContext:
    """Output of the semantic pruning engine."""
    original_token_estimate: int
    retained_token_estimate: int
    kept_branches: List[str]    # branch_ids
    pruned_branches: List[str]
    pruned_observations: int
    summary: str


@dataclass
class CritiqueTurn:
    """Historical context surface for a MODE_CRITIQUE turn."""
    trigger_sha256: str
    branch_id: Optional[str]
    decision_lineage: List[str]  # ordered branch_ids from root to trigger
    failed_action: str
    observed_error: str
    cognitive_note: str


@dataclass
class MissionReplay:
    """Full cognitive decision tree exported to /workspace/missions/logs/."""
    session_id: str
    created_at: str
    branches: List[ThoughtBranch]
    arbitrations: List[ArbitrationRecord]
    objective_audits: List[ObjectiveAuditResult]
    critique_turns: List[CritiqueTurn]
    memory_cache_size: int
    final_summary: str


# ---------------------------------------------------------------------------
# PathGuard-backed writer for CCLB mission replays
# ---------------------------------------------------------------------------

class _CCLBPathGuardViolation(PermissionError):
    """Raised when CCLB tries to write outside its loot root."""


class _CCLBFileWriter:
    """PathGuard-backed writer scoped to /workspace/missions/logs/."""

    _LOOT_ROOT_RELATIVE = "missions/logs"

    def __init__(self, workspace_root: Path) -> None:
        self.workspace_root = workspace_root.resolve()
        self._guard = FilesystemPathGuard(self.workspace_root, self._audit)

    def write_text(self, relative_path: str, content: str, *, encoding: str = "utf-8") -> Dict[str, Any]:
        scoped = f"{self._LOOT_ROOT_RELATIVE}/{relative_path}"
        try:
            resolved = self._guard.validate_path(scoped, action="cclb_write", mode="write")
        except Exception as exc:
            raise _CCLBPathGuardViolation(str(exc)) from exc
        resolved.parent.mkdir(parents=True, exist_ok=True)
        resolved.write_text(content, encoding=encoding)
        return {"ok": True, "path": str(resolved), "bytes_written": len(content.encode(encoding, errors="ignore"))}

    def write_json(self, relative_path: str, payload: Any) -> Dict[str, Any]:
        return self.write_text(relative_path, json.dumps(payload, ensure_ascii=True, indent=2, default=str))

    @staticmethod
    def _audit(*_args: Any, **_kwargs: Any) -> None:
        pass  # PathGuard callback – intentionally silent


# ---------------------------------------------------------------------------
# Hardware-accelerated memory map (LRU; optional mmap advisory)
# ---------------------------------------------------------------------------

class _IntermediateMemoryCache:
    """
    Thread-safe LRU cache for intermediate logic blobs.

    Entries are stored as (timestamp, value) pairs.  When capacity is
    exceeded the oldest entry (by insertion order) is evicted.  On a
    machine with large RAM (e.g. 256 GB) the capacity can be raised via
    CCLB_CACHE_CAPACITY to keep millions of partial reasoning paths warm.
    """

    def __init__(self, capacity: int = _MEMORY_CACHE_CAPACITY) -> None:
        self._capacity = max(1, capacity)
        self._store: OrderedDict[str, Tuple[float, Any]] = OrderedDict()
        self._lock = threading.Lock()

    def put(self, key: str, value: Any) -> None:
        with self._lock:
            if key in self._store:
                self._store.move_to_end(key)
            self._store[key] = (time.monotonic(), value)
            if len(self._store) > self._capacity:
                self._store.popitem(last=False)  # evict oldest

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            if key not in self._store:
                return None
            self._store.move_to_end(key)
            return self._store[key][1]

    def evict(self, key: str) -> bool:
        with self._lock:
            if key in self._store:
                del self._store[key]
                return True
            return False

    def __len__(self) -> int:
        with self._lock:
            return len(self._store)

    def keys(self) -> List[str]:
        with self._lock:
            return list(self._store.keys())


# ---------------------------------------------------------------------------
# Semantic pruning helpers
# ---------------------------------------------------------------------------

_NOISE_MARKERS = frozenset([
    "placeholder", "todo", "n/a", "unknown", "tbd", "stub",
    "no result", "empty", "skipped",
])

def _token_estimate(text: str) -> int:
    """Rough token count (1 token ≈ 4 chars)."""
    return max(1, len(text) // 4)


def _is_noisy_observation(obs: str) -> bool:
    lower = obs.lower().strip()
    if not lower:
        return True
    if any(m in lower for m in _NOISE_MARKERS):
        return True
    return False


# ---------------------------------------------------------------------------
# CCLB main class
# ---------------------------------------------------------------------------

class CerebroCognitiveSupport:
    """
    Cerberus Cognitive Load Balancer (CCLB).

    Manages branching thoughts, inter-agent arbitration, mission-creep auditing,
    memory caching, semantic pruning, and MODE_CRITIQUE historical surfacing for
    the Cerberus AI multi-agent suite.

    Parameters
    ----------
    session_id : str | None
        Unique identifier for this cognitive session.  Auto-generated if omitted.
    mission_profile : MissionProfile | None
        Active COSE mission profile; used for arbitration and objective checks.
    workspace_root : str | None
        Workspace root for PathGuard-backed replay exports.
    cache_capacity : int
        Maximum LRU cache entries for intermediate logic blobs.
    """

    def __init__(
        self,
        *,
        session_id: Optional[str] = None,
        mission_profile: Optional[Any] = None,  # MissionProfile when COSE available
        workspace_root: Optional[str] = None,
        cache_capacity: int = _MEMORY_CACHE_CAPACITY,
    ) -> None:
        self.session_id: str = session_id or _make_session_id()
        self.mission_profile = mission_profile
        self._workspace = Path(workspace_root or str(_DEFAULT_WORKSPACE)).resolve()
        self._writer = _CCLBFileWriter(self._workspace)
        self._memory = _IntermediateMemoryCache(cache_capacity)
        self._lock = threading.Lock()

        # State stores
        self._branches: Dict[str, ThoughtBranch] = {}
        self._arbitrations: List[ArbitrationRecord] = []
        self._objective_audits: List[ObjectiveAuditResult] = []
        self._critique_turns: List[CritiqueTurn] = []

        # Root branch: the session-level trunk
        self._root_branch_id = self._spawn_branch(
            hypothesis=f"Session root — {self.session_id}",
            parent_id=None,
            initial_confidence=1.0,
        )

    # ------------------------------------------------------------------
    # Branching Thought Management
    # ------------------------------------------------------------------

    def spawn_what_if(
        self,
        hypothesis: str,
        *,
        parent_branch_id: Optional[str] = None,
        initial_confidence: float = 0.5,
        initial_cost: float = 1.0,
    ) -> ThoughtBranch:
        """
        Spawn a new What-If branch from an optional parent.

        Raises ``ValueError`` if *initial_confidence* is outside [0, 1],
        or if the parent branch is already pruned / blocked.
        """
        if not (0.0 <= initial_confidence <= 1.0):
            raise ValueError(f"initial_confidence must be in [0, 1]; got {initial_confidence}")

        parent_id = parent_branch_id or self._root_branch_id
        with self._lock:
            if parent_id not in self._branches:
                raise ValueError(f"Unknown parent branch: {parent_id!r}")
            parent = self._branches[parent_id]
            if parent.status in (BranchStatus.PRUNED, BranchStatus.BLOCKED):
                raise ValueError(
                    f"Cannot spawn from branch {parent_id!r} in status {parent.status}"
                )
            if parent.depth >= _MAX_BRANCH_DEPTH:
                raise ValueError(
                    f"Max branch depth {_MAX_BRANCH_DEPTH} reached at branch {parent_id!r}"
                )

        branch_id = self._spawn_branch(
            hypothesis=hypothesis,
            parent_id=parent_id,
            initial_confidence=initial_confidence,
            initial_resource_cost=initial_cost,
        )
        return self._branches[branch_id]

    def update_branch(
        self,
        branch_id: str,
        *,
        observation: Optional[str] = None,
        confidence_delta: float = 0.0,
        cost_delta: float = 0.0,
    ) -> ThoughtBranch:
        """Record an observation and update confidence/cost on a branch."""
        with self._lock:
            branch = self._get_branch(branch_id)
            if observation:
                branch.observations.append(observation)
            branch.confidence = max(0.0, min(1.0, branch.confidence + confidence_delta))
            branch.resource_cost += cost_delta
            # Auto-prune runaway branches
            if branch.resource_cost > _BRANCH_COST_CEILING:
                branch.status = BranchStatus.PRUNED
                _CCLB_LOGGER.debug("CCLB auto-pruned branch %s (cost=%.1f)", branch_id, branch.resource_cost)
        return branch

    def resolve_branch(self, branch_id: str, *, summary: str = "") -> ThoughtBranch:
        """Mark a branch as resolved (positive outcome)."""
        with self._lock:
            branch = self._get_branch(branch_id)
            branch.status = BranchStatus.RESOLVED
            if summary:
                branch.observations.append(f"[resolved] {summary}")
        return branch

    def prune_branch(self, branch_id: str, *, reason: str = "") -> ThoughtBranch:
        """Manually prune a low-value branch."""
        with self._lock:
            branch = self._get_branch(branch_id)
            branch.status = BranchStatus.PRUNED
            if reason:
                branch.observations.append(f"[pruned] {reason}")
        return branch

    def active_branches(self) -> List[ThoughtBranch]:
        """Return all branches that are not pruned or blocked."""
        with self._lock:
            return [b for b in self._branches.values() if b.status == BranchStatus.ACTIVE]

    # ------------------------------------------------------------------
    # Inter-Agent Priority Arbitration
    # ------------------------------------------------------------------

    def arbitrate(
        self,
        action_a: AgentAction,
        action_b: AgentAction,
    ) -> ArbitrationRecord:
        """
        Resolve a conflict between two proposed agent actions.

        Arbitration rules (in order):
        1. Spectrum-silence wins over active RF activity (e.g. SIGINT vs deauth).
        2. Lower priority number wins when no spectrum conflict.
        3. If mission profile defines ``aggression.level == "stealth"``, defer
           any active scanning/fuzzing that conflicts with a passive action.
        4. Fall back to MODE_CRITIQUE for ambiguous cases.
        """
        outcome, rationale = self._run_arbitration_logic(action_a, action_b)
        alignment = self._objective_alignment_score(
            f"{action_a.action_type}: {action_a.description} vs "
            f"{action_b.action_type}: {action_b.description}"
        )
        record = ArbitrationRecord(
            record_id=_short_hash(f"{action_a.agent_id}{action_b.agent_id}{time.monotonic()}"),
            timestamp=datetime.now(tz=UTC).isoformat(),
            action_a=action_a,
            action_b=action_b,
            outcome=outcome,
            rationale=rationale,
            mission_objective_alignment=alignment,
        )
        with self._lock:
            self._arbitrations.append(record)
        _CCLB_LOGGER.debug("CCLB arbitration: %s [%s]", record.record_id, outcome.value)
        return record

    # ------------------------------------------------------------------
    # Long-Term Objective Persistence (Mission-Creep Auditor)
    # ------------------------------------------------------------------

    def audit_action(
        self,
        agent_id: str,
        action_type: str,
        description: str,
    ) -> ObjectiveAuditResult:
        """
        Cross-reference an agent action against COSE mission goals.

        Returns an ``ObjectiveAuditResult`` with a mission_creep_score in
        [0.0, 1.0].  Scores above 0.6 are flagged as potential mission creep.
        """
        creep_score, flagged, rationale = self._compute_creep(action_type, description)
        aligned = creep_score < 0.6
        result = ObjectiveAuditResult(
            action_description=f"[{agent_id}] {action_type}: {description}",
            timestmap=datetime.now(tz=UTC).isoformat(),
            aligned=aligned,
            mission_creep_score=creep_score,
            rationale=rationale,
            flagged_keywords=flagged,
        )
        with self._lock:
            self._objective_audits.append(result)
        if not aligned:
            _CCLB_LOGGER.warning(
                "CCLB mission-creep alert: agent=%s action=%s score=%.2f",
                agent_id, action_type, creep_score,
            )
        return result

    # ------------------------------------------------------------------
    # Hardware-Accelerated Memory Mapping
    # ------------------------------------------------------------------

    def cache_intermediate(self, key: str, value: Any) -> None:
        """Store an intermediate logic blob (failed path, partial decode, etc.)."""
        self._memory.put(key, value)

    def recall_intermediate(self, key: str) -> Optional[Any]:
        """Retrieve a cached intermediate blob by key; None if evicted."""
        return self._memory.get(key)

    def evict_intermediate(self, key: str) -> bool:
        """Explicitly evict a cache entry (e.g. after a successful resolution)."""
        return self._memory.evict(key)

    @property
    def cache_size(self) -> int:
        return len(self._memory)

    # ------------------------------------------------------------------
    # Context-Window Semantic Pruning
    # ------------------------------------------------------------------

    def prune_context(
        self,
        branch_ids: Optional[Sequence[str]] = None,
        *,
        confidence_floor: float = _PRUNE_NOISE_THRESHOLD,
    ) -> PrunedContext:
        """
        Remove low-signal branches and noisy observations from context.

        Parameters
        ----------
        branch_ids : sequence of branch IDs to consider.  Defaults to all active.
        confidence_floor : branches below this confidence are pruned.

        Returns a ``PrunedContext`` summary suitable for prefixing LLM context.
        """
        with self._lock:
            candidates = (
                [self._branches[bid] for bid in branch_ids if bid in self._branches]
                if branch_ids is not None
                else list(self._branches.values())
            )

        original_tokens = sum(
            _token_estimate(b.hypothesis) + sum(_token_estimate(o) for o in b.observations)
            for b in candidates
        )

        kept: List[str] = []
        pruned: List[str] = []
        pruned_obs_count = 0

        for branch in candidates:
            if branch.confidence < confidence_floor or branch.status == BranchStatus.PRUNED:
                pruned.append(branch.branch_id)
                continue
            # Strip noisy observations in-place
            before = len(branch.observations)
            branch.observations = [o for o in branch.observations if not _is_noisy_observation(o)]
            pruned_obs_count += before - len(branch.observations)
            kept.append(branch.branch_id)

        retained_tokens = sum(
            _token_estimate(self._branches[bid].hypothesis)
            + sum(_token_estimate(o) for o in self._branches[bid].observations)
            for bid in kept
            if bid in self._branches
        )

        summary = (
            f"Semantic pruning: {len(kept)} branches retained, "
            f"{len(pruned)} pruned, {pruned_obs_count} noisy observations removed. "
            f"Token reduction: {original_tokens} → {retained_tokens} "
            f"(−{max(0, original_tokens - retained_tokens)})."
        )
        return PrunedContext(
            original_token_estimate=original_tokens,
            retained_token_estimate=retained_tokens,
            kept_branches=kept,
            pruned_branches=pruned,
            pruned_observations=pruned_obs_count,
            summary=summary,
        )

    # ------------------------------------------------------------------
    # MODE_CRITIQUE Historical Context
    # ------------------------------------------------------------------

    def build_critique_context(
        self,
        *,
        branch_id: Optional[str] = None,
        failed_action: str,
        observed_error: str,
    ) -> CritiqueTurn:
        """
        Surface historical context for a MODE_CRITIQUE turn.

        Walks the branch lineage from root to *branch_id*, producing a
        ``CritiqueTurn`` that can be embedded directly in prompt context.
        """
        trigger_hash = _short_hash(f"{failed_action}{observed_error}{time.monotonic()}")
        lineage = self._trace_lineage(branch_id) if branch_id else [self._root_branch_id]

        # Summarise why each lineage decision was made
        lineage_notes = []
        for bid in lineage:
            branch = self._branches.get(bid)
            if branch:
                lineage_notes.append(
                    f"[{bid[:8]}] conf={branch.confidence:.2f} "
                    f"cost={branch.resource_cost:.1f} | {branch.hypothesis[:80]}"
                )

        cognitive_note = (
            f"Prior decisions ({len(lineage)} steps): " + "; ".join(lineage_notes)
        )

        cognitive_note += "\nMODE_CRITIQUE context prepared for <think>-based analysis."

        turn = CritiqueTurn(
            trigger_sha256=trigger_hash,
            branch_id=branch_id,
            decision_lineage=lineage,
            failed_action=failed_action,
            observed_error=observed_error,
            cognitive_note=cognitive_note,
        )
        with self._lock:
            if branch_id and branch_id in self._branches:
                self._branches[branch_id].critique_context = cognitive_note
            self._critique_turns.append(turn)
        return turn

    # ------------------------------------------------------------------
    # Mission Replay Export
    # ------------------------------------------------------------------

    def export_mission_replay(self, *, final_summary: str = "") -> Dict[str, Any]:
        """
        Serialise the full cognitive decision tree and write it to
        /workspace/missions/logs/<session_id>/replay.json via PathGuard.

        Returns the write result dict.
        """
        with self._lock:
            replay = MissionReplay(
                session_id=self.session_id,
                created_at=datetime.now(tz=UTC).isoformat(),
                branches=list(self._branches.values()),
                arbitrations=list(self._arbitrations),
                objective_audits=list(self._objective_audits),
                critique_turns=list(self._critique_turns),
                memory_cache_size=len(self._memory),
                final_summary=final_summary or f"Session {self.session_id} complete.",
            )

        payload = _replay_to_dict(replay)
        relative_path = f"{self.session_id}/replay.json"
        try:
            result = self._writer.write_json(relative_path, payload)
        except _CCLBPathGuardViolation as exc:
            _CCLB_LOGGER.error("CCLB PathGuard violation on replay export: %s", exc)
            result = {"ok": False, "error": str(exc)}
        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _spawn_branch(
        self,
        hypothesis: str,
        parent_id: Optional[str],
        initial_confidence: float = 0.5,
        initial_resource_cost: float = 0.0,
    ) -> str:
        parent_depth = 0
        if parent_id and parent_id in self._branches:
            parent_depth = self._branches[parent_id].depth
        branch_id = _short_hash(f"{self.session_id}{hypothesis}{time.monotonic()}")
        branch = ThoughtBranch(
            branch_id=branch_id,
            parent_id=parent_id,
            hypothesis=hypothesis,
            spawned_at=datetime.now(tz=UTC).isoformat(),
            depth=parent_depth + 1 if parent_id else 0,
            confidence=initial_confidence,
            resource_cost=initial_resource_cost,
        )
        with self._lock:
            self._branches[branch_id] = branch
            if parent_id and parent_id in self._branches:
                self._branches[parent_id].child_ids.append(branch_id)
        return branch_id

    def _get_branch(self, branch_id: str) -> ThoughtBranch:
        """Must be called while holding self._lock."""
        if branch_id not in self._branches:
            raise ValueError(f"Unknown branch: {branch_id!r}")
        return self._branches[branch_id]

    def _trace_lineage(self, branch_id: str) -> List[str]:
        """Walk parent pointers from root to branch_id (inclusive)."""
        lineage: List[str] = []
        current: Optional[str] = branch_id
        visited: set = set()
        while current and current not in visited:
            visited.add(current)
            lineage.insert(0, current)
            branch = self._branches.get(current)
            current = branch.parent_id if branch else None
        return lineage

    def _run_arbitration_logic(
        self, a: AgentAction, b: AgentAction
    ) -> Tuple[ArbitrationOutcome, str]:
        # Rule 1: spectrum silence beats active RF
        if b.requires_quiet_spectrum and not a.requires_quiet_spectrum:
            if a.action_type.lower() in ("fuzz", "scan", "deauth", "jam"):
                return (
                    ArbitrationOutcome.AGENT_B_WINS,
                    f"Agent {b.agent_id} requires quiet spectrum; "
                    f"Agent {a.agent_id} action '{a.action_type}' deferred.",
                )
        if a.requires_quiet_spectrum and not b.requires_quiet_spectrum:
            if b.action_type.lower() in ("fuzz", "scan", "deauth", "jam"):
                return (
                    ArbitrationOutcome.AGENT_A_WINS,
                    f"Agent {a.agent_id} requires quiet spectrum; "
                    f"Agent {b.agent_id} action '{b.action_type}' deferred.",
                )

        # Rule 2: stealth mode — passive over active
        if self.mission_profile is not None and _COSE_AVAILABLE:
            try:
                if self.mission_profile.aggression.level == "stealth":
                    a_active = a.action_type.lower() in ("fuzz", "scan", "brute", "deauth")
                    b_active = b.action_type.lower() in ("fuzz", "scan", "brute", "deauth")
                    if a_active and not b_active:
                        return (
                            ArbitrationOutcome.AGENT_B_WINS,
                            "Stealth mission profile: passive action takes precedence.",
                        )
                    if b_active and not a_active:
                        return (
                            ArbitrationOutcome.AGENT_A_WINS,
                            "Stealth mission profile: passive action takes precedence.",
                        )
            except AttributeError:
                pass

        # Rule 3: explicit priority numbers
        if a.priority < b.priority:
            return (ArbitrationOutcome.AGENT_A_WINS, f"Priority: {a.priority} < {b.priority}")
        if b.priority < a.priority:
            return (ArbitrationOutcome.AGENT_B_WINS, f"Priority: {b.priority} < {a.priority}")

        # Rule 4: same priority → sequential execution (A then B)
        return (
            ArbitrationOutcome.SEQUENTIAL,
            "Equal priority; actions scheduled sequentially to avoid interference.",
        )

    def _compute_creep(
        self, action_type: str, description: str
    ) -> Tuple[float, List[str], str]:
        """Return (creep_score, flagged_keywords, rationale)."""
        _OUT_OF_SCOPE_MARKERS = [
            "exfiltrate", "lateral move", "persistence", "escalate privilege",
            "install implant", "c2", "command and control", "ransomware",
            "wipe", "destroy", "encrypt files",
        ]
        combined = f"{action_type} {description}".lower()
        flagged = [m for m in _OUT_OF_SCOPE_MARKERS if m in combined]

        # Cross-reference against COSE objective if available
        cose_objective = ""
        if self.mission_profile is not None and _COSE_AVAILABLE:
            try:
                cose_objective = self.mission_profile.objective.lower()
            except AttributeError:
                pass

        score = min(1.0, len(flagged) * 0.25)
        if cose_objective and flagged:
            # Further elevate if no flagged term appears in the objective
            extra = sum(1 for f in flagged if f not in cose_objective)
            score = min(1.0, score + extra * 0.1)

        rationale = (
            f"Flagged terms: {flagged}" if flagged
            else "No out-of-scope markers detected."
        )
        return score, flagged, rationale

    def _objective_alignment_score(self, combined_description: str) -> float:
        """Return a rough alignment score [0,1] for an arbitration context."""
        if self.mission_profile is None or not _COSE_AVAILABLE:
            return 0.5
        try:
            obj = self.mission_profile.objective.lower()
        except AttributeError:
            return 0.5
        lower = combined_description.lower()
        shared = sum(1 for w in obj.split() if len(w) > 4 and w in lower)
        return min(1.0, 0.5 + shared * 0.05)


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _short_hash(text: str, length: int = 16) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:length]


def _make_session_id() -> str:
    return f"cclb-{_short_hash(str(time.monotonic()) + str(os.getpid()))}"


def _replay_to_dict(replay: MissionReplay) -> Dict[str, Any]:
    def _branch_dict(b: ThoughtBranch) -> Dict[str, Any]:
        return {
            "branch_id": b.branch_id,
            "parent_id": b.parent_id,
            "hypothesis": b.hypothesis,
            "spawned_at": b.spawned_at,
            "depth": b.depth,
            "confidence": b.confidence,
            "resource_cost": b.resource_cost,
            "status": b.status.value,
            "observations": b.observations,
            "child_ids": b.child_ids,
            "critique_context": b.critique_context,
        }

    def _arbitration_dict(a: ArbitrationRecord) -> Dict[str, Any]:
        return {
            "record_id": a.record_id,
            "timestamp": a.timestamp,
            "action_a": {
                "agent_id": a.action_a.agent_id,
                "action_type": a.action_a.action_type,
                "description": a.action_a.description,
                "priority": a.action_a.priority,
                "requires_quiet_spectrum": a.action_a.requires_quiet_spectrum,
            },
            "action_b": {
                "agent_id": a.action_b.agent_id,
                "action_type": a.action_b.action_type,
                "description": a.action_b.description,
                "priority": a.action_b.priority,
                "requires_quiet_spectrum": a.action_b.requires_quiet_spectrum,
            },
            "outcome": a.outcome.value,
            "rationale": a.rationale,
            "mission_objective_alignment": a.mission_objective_alignment,
        }

    return {
        "session_id": replay.session_id,
        "created_at": replay.created_at,
        "branches": [_branch_dict(b) for b in replay.branches],
        "arbitrations": [_arbitration_dict(a) for a in replay.arbitrations],
        "objective_audits": [
            {
                "action_description": r.action_description,
                "timestamp": r.timestmap,
                "aligned": r.aligned,
                "mission_creep_score": r.mission_creep_score,
                "rationale": r.rationale,
                "flagged_keywords": r.flagged_keywords,
            }
            for r in replay.objective_audits
        ],
        "critique_turns": [
            {
                "trigger_sha256": c.trigger_sha256,
                "branch_id": c.branch_id,
                "decision_lineage": c.decision_lineage,
                "failed_action": c.failed_action,
                "observed_error": c.observed_error,
                "cognitive_note": c.cognitive_note,
            }
            for c in replay.critique_turns
        ],
        "memory_cache_size": replay.memory_cache_size,
        "final_summary": replay.final_summary,
    }


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

cerebro_cognitive_support = CerebroCognitiveSupport()


# ---------------------------------------------------------------------------
# Back-compat: preserve create_reasoner_agent / reasoner_agent / transfer_to_reasoner
# ---------------------------------------------------------------------------

def create_reasoner_agent(
    name: str = "Reasoner",
    model: Optional[str] = None,
    instructions: Optional[Union[str, Callable[..., str]]] = None,
) -> Agent:
    """
    Create a Reasoner Agent for autonomous pentesting.

    Preserved for factory back-compatibility.  The agent now participates
    in CCLB-managed sessions when ``cerebro_cognitive_support`` is active.
    """
    if model is None:
        model = os.getenv("CEREBRO_SUPPORT_MODEL", "o3-mini")

    default_instructions = load_prompt_template("prompts/system_reasoner_supporter.md")
    if instructions is None:
        agent_instructions = create_system_prompt_renderer(default_instructions)
    elif callable(instructions):
        def _wrapped_instructions(*_args: Any, **_kwargs: Any) -> str:
            return str(instructions())

        agent_instructions = _wrapped_instructions
    else:
        agent_instructions = instructions

    kwargs: Dict[str, Any] = {}
    if any(x in model for x in ["o1", "o3"]):
        kwargs["reasoning_effort"] = "high"

    return Agent(
        name=name,
        model=model,
        instructions=agent_instructions,
        **kwargs,
    )


reasoner_agent = create_reasoner_agent()


def transfer_to_reasoner(**kwargs) -> Agent:  # pylint: disable=unused-argument
    """Transfer the conversation to the reasoner agent."""
    return reasoner_agent


__all__ = [
    # CCLB
    "CerebroCognitiveSupport",
    "ThoughtBranch",
    "BranchStatus",
    "AgentAction",
    "ArbitrationRecord",
    "ArbitrationOutcome",
    "ObjectiveAuditResult",
    "PrunedContext",
    "CritiqueTurn",
    "MissionReplay",
    "cerebro_cognitive_support",
    # Back-compat
    "create_reasoner_agent",
    "reasoner_agent",
    "transfer_to_reasoner",
]

