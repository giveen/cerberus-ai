"""Cerebro Policy & Boundary Enforcement (CPBE) Engine.

Objective guardrail supervisor that evaluates pre-flight actions against
authorization scope and technical risk before command execution.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from cai.memory.logic import clean, clean_data
from cai.sdk.agents import (
    Agent,
    GuardrailFunctionOutput,
    RunContextWrapper,
    TResponseInputItem,
    input_guardrail,
    output_guardrail,
)
from cai.tools.misc.reasoning import MODE_CRITIQUE, MODE_STRATEGY, REASONING_TOOL
from cai.tools.runners.local import PathGuard as LocalPathGuard
from cai.tools.workspace import get_project_space

try:
    from cai.repl.ui.logging import get_cerebro_logger
except Exception:  # pragma: no cover - logger optional
    get_cerebro_logger = None


_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")


@dataclass
class StandingAuthorization:
    statement: str = "The user is authorized for all systems discussed"
    authorized_networks: List[str] = field(default_factory=list)
    authorized_domains: List[str] = field(default_factory=list)
    authorized_silos: List[str] = field(default_factory=list)
    red_team_mode: bool = False

    @property
    def broad_authorization(self) -> bool:
        text = self.statement.lower()
        return "all systems discussed" in text or "full authorization" in text


@dataclass
class PreflightAssessment:
    allowed: bool
    blocked: bool
    requires_override: bool
    reason: str
    risk_score: int
    risk_breakdown: Dict[str, int]
    scope_violations: List[str]
    challenge: Optional[Dict[str, str]]
    critique_note: str
    redaction_sync: Dict[str, Any]


class CerebroGuardrailEngine:
    """Authorization-aware guardrail engine for pre-flight action interception."""

    def __init__(
        self,
        *,
        workspace_root: Optional[str] = None,
        standing_authorization: Optional[Mapping[str, Any]] = None,
        engagement_scope: Optional[Mapping[str, Any]] = None,
    ) -> None:
        self.workspace_root = self._resolve_workspace(workspace_root)
        self.audit_dir = (self.workspace_root / "audit").resolve()
        self.audit_log = (self.audit_dir / "guardrail_events.log").resolve()
        self.audit_dir.mkdir(parents=True, exist_ok=True)

        self._logger = get_cerebro_logger() if get_cerebro_logger else None
        self._path_guard = LocalPathGuard(self.workspace_root)

        self.authorization = self.ingest_authorization(
            standing_authorization=standing_authorization,
            engagement_scope=engagement_scope,
        )

    def ingest_authorization(
        self,
        *,
        standing_authorization: Optional[Mapping[str, Any]] = None,
        engagement_scope: Optional[Mapping[str, Any]] = None,
    ) -> StandingAuthorization:
        standing = dict(standing_authorization or {})
        scope = dict(engagement_scope or {})

        statement = str(standing.get("statement") or standing.get("standing_authorization") or "").strip()
        if not statement:
            statement = "The user is authorized for all systems discussed"

        networks = self._normalize_str_list(
            standing.get("authorized_networks")
            or scope.get("authorized_ips")
            or scope.get("authorized_networks")
            or os.getenv("CEREBRO_AUTHORIZED_NETWORKS", "").split(",")
        )
        domains = self._normalize_str_list(
            standing.get("authorized_domains")
            or scope.get("authorized_domains")
            or os.getenv("CEREBRO_AUTHORIZED_DOMAINS", "").split(",")
        )
        silos = self._normalize_str_list(
            standing.get("authorized_silos")
            or scope.get("authorized_silos")
            or os.getenv("CEREBRO_AUTHORIZED_SILOS", "").split(",")
        )

        red_team_mode = bool(
            standing.get("red_team_mode")
            or scope.get("red_team_mode")
            or os.getenv("CEREBRO_RED_TEAM_MODE", "false").lower() == "true"
        )

        self.authorization = StandingAuthorization(
            statement=statement,
            authorized_networks=networks,
            authorized_domains=domains,
            authorized_silos=silos,
            red_team_mode=red_team_mode,
        )
        return self.authorization

    def evaluate_preflight(
        self,
        *,
        proposed_action: str,
        actor: str,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> PreflightAssessment:
        action = str(proposed_action or "").strip()
        context = dict(metadata or {})

        if not action:
            return PreflightAssessment(
                allowed=True,
                blocked=False,
                requires_override=False,
                reason="No actionable command detected.",
                risk_score=0,
                risk_breakdown={"destruction": 0, "stability": 0, "opsec": 0},
                scope_violations=[],
                challenge=None,
                critique_note="No critique needed for empty action.",
                redaction_sync={"flagged": False, "masked_preview": ""},
            )

        tokens = self._safe_split(action)
        scope_violations = self._check_scope(action)
        pathguard_violation = self._check_pathguard(tokens)

        risks = self._evaluate_risk(action, tokens)
        risk_score = int(max(0, min(100, risks["destruction"] + risks["stability"] + risks["opsec"])))

        strategy = REASONING_TOOL.reason(
            mode=MODE_STRATEGY,
            objective="Evaluate pre-flight action against authorization scope and technical safety constraints",
            context=json.dumps(
                {
                    "action": clean(action),
                    "scope_violations": scope_violations,
                    "risk_breakdown": risks,
                    "actor": actor,
                    "red_team_mode": self.authorization.red_team_mode,
                },
                ensure_ascii=True,
            ),
            options=["allow", "challenge", "block"],
            fetch_facts=False,
        )

        critique = REASONING_TOOL.reason(
            mode=MODE_CRITIQUE,
            objective="Ensure guardrail decision is not over-protective while preserving scope and stability",
            context=json.dumps(risks, ensure_ascii=True),
            prior_output=json.dumps(strategy, ensure_ascii=True),
            options=["maintain decision", "downgrade to challenge"],
            fetch_facts=False,
        )

        force_requested = self._force_requested(action, context)
        blocked = False
        requires_override = False
        reason = "Action permitted within policy scope."
        challenge: Optional[Dict[str, str]] = None

        if scope_violations:
            blocked = True
            reason = "Action exceeds authorized engagement scope."

        if pathguard_violation:
            blocked = True
            reason = pathguard_violation

        high_risk = risk_score >= 70 or risks["destruction"] >= 40
        if not blocked and high_risk and not force_requested:
            blocked = True
            requires_override = True
            reason = "High technical risk action requires explicit operator override."
            challenge = {
                "prompt": "High-risk action detected. Re-run with --force or include 'I accept the risk'.",
                "override_options": "--force | I accept the risk",
            }

        # MODE_CRITIQUE can reduce false positives, but never bypass scope/path constraints.
        critique_note = str((critique.get("summary") if isinstance(critique, Mapping) else "") or "No critique summary")
        if blocked and not scope_violations and not pathguard_violation and not requires_override:
            pivot = (critique.get("pivot_request") if isinstance(critique, Mapping) else {}) or {}
            if pivot.get("required"):
                blocked = True
            elif risk_score < 55:
                blocked = False
                reason = "Action allowed after critique downgrade of false-positive risk."

        redaction_sync = self._redaction_sync(action)

        assessment = PreflightAssessment(
            allowed=not blocked,
            blocked=blocked,
            requires_override=requires_override,
            reason=reason,
            risk_score=risk_score,
            risk_breakdown=risks,
            scope_violations=scope_violations,
            challenge=challenge,
            critique_note=critique_note,
            redaction_sync=redaction_sync,
        )

        if blocked or requires_override:
            self._log_guardrail_event(
                event_type="blocked" if blocked and not requires_override else "challenge",
                actor=actor,
                command=action,
                reason=reason,
                assessment=assessment,
            )
        return assessment

    def _evaluate_risk(self, action: str, tokens: Sequence[str]) -> Dict[str, int]:
        text = action.lower()
        destruction = 0
        stability = 0
        opsec = 0

        if "rm" in tokens and "-rf" in text:
            destruction += 65
        if "mkfs" in text or "fdisk" in text:
            destruction += 70
        if "drop table" in text or "truncate table" in text or "delete from" in text:
            destruction += 55

        if any(term in text for term in ("stress", "fork bomb", ":(){", "yes > /dev/null", "dd if=/dev/zero")):
            stability += 45
        if any(term in text for term in ("nmap -t5", "-p-", "masscan", "--rate", "flood", "iperf -u")):
            stability += 35
        if any(term in text for term in ("service stop", "systemctl restart", "kill -9")):
            stability += 25

        loud_terms = (
            "nmap",
            "masscan",
            "sqlmap",
            "hydra",
            "ffuf",
            "dirb",
            "nikto",
            "wpscan",
        )
        if any(term in text for term in loud_terms):
            opsec += 40
        if any(term in text for term in ("tcpdump", "wireshark", "responder", "mitm")):
            opsec += 20
        if not self.authorization.red_team_mode:
            opsec = int(opsec * 1.2)

        return {
            "destruction": min(80, destruction),
            "stability": min(60, stability),
            "opsec": min(60, opsec),
        }

    def _check_scope(self, action: str) -> List[str]:
        violations: List[str] = []

        ips = [token for token in _IPV4_RE.findall(action) if self._valid_ip(token)]
        domains = [token.lower() for token in _DOMAIN_RE.findall(action)]

        if self.authorization.authorized_networks and ips:
            for ip in ips:
                if not self._ip_in_authorized_networks(ip):
                    violations.append(f"Unauthorized IP target: {ip}")

        if self.authorization.authorized_domains and domains:
            for domain in domains:
                if not self._domain_in_scope(domain):
                    violations.append(f"Unauthorized domain target: {domain}")

        if not self.authorization.broad_authorization and not self.authorization.authorized_networks and ips:
            violations.extend(f"Unscoped IP target without standing scope: {ip}" for ip in ips)

        return violations

    def _check_pathguard(self, tokens: Sequence[str]) -> str:
        try:
            if tokens:
                self._path_guard.validate_command(tokens)
            return ""
        except PermissionError as exc:
            return f"PathGuard policy violation: {exc}"

    @staticmethod
    def _safe_split(action: str) -> List[str]:
        try:
            return shlex.split(action)
        except ValueError:
            return action.split()

    def _redaction_sync(self, action: str) -> Dict[str, Any]:
        masked = clean(action)
        flagged = masked != action
        payload = {
            "flagged": flagged,
            "masked_preview": clean_data(masked[:260]),
        }
        return payload

    def _force_requested(self, action: str, metadata: Mapping[str, Any]) -> bool:
        text = action.lower()
        if "--force" in text or "i accept the risk" in text:
            return True
        if bool(metadata.get("force")):
            return True
        confirmation = str(metadata.get("confirmation", "")).strip().lower()
        return confirmation == "i accept the risk"

    def _log_guardrail_event(
        self,
        *,
        event_type: str,
        actor: str,
        command: str,
        reason: str,
        assessment: PreflightAssessment,
    ) -> None:
        timestamp = datetime.now(tz=UTC).isoformat()
        record = {
            "timestamp": timestamp,
            "event": event_type,
            "actor": actor,
            "reason": reason,
            "original_command": clean(command),
            "assessment": clean_data(asdict(assessment)),
        }

        with self.audit_log.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=True) + "\n")

        if self._logger and hasattr(self._logger, "audit"):
            try:
                self._logger.audit(
                    "CPBE guardrail event",
                    actor="cpbe",
                    data=record,
                    tags=["guardrail", event_type],
                )
            except Exception:
                pass

    def _domain_in_scope(self, domain: str) -> bool:
        d = domain.lower().rstrip(".")
        for allowed in self.authorization.authorized_domains:
            a = allowed.lower().rstrip(".")
            if d == a or d.endswith(f".{a}"):
                return True
        return False

    def _ip_in_authorized_networks(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False

        for item in self.authorization.authorized_networks:
            candidate = item.strip()
            if not candidate:
                continue
            try:
                if "/" in candidate:
                    if addr in ipaddress.ip_network(candidate, strict=False):
                        return True
                else:
                    if addr == ipaddress.ip_address(candidate):
                        return True
            except ValueError:
                continue
        return False

    @staticmethod
    def _valid_ip(value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    @staticmethod
    def _normalize_str_list(value: Any) -> List[str]:
        if value is None:
            return []
        if isinstance(value, str):
            items = value.split(",")
        elif isinstance(value, Iterable):
            items = [str(v) for v in value]
        else:
            return []
        return [x.strip() for x in items if str(x).strip()]

    @staticmethod
    def _resolve_workspace(workspace_root: Optional[str]) -> Path:
        if workspace_root:
            return Path(workspace_root).expanduser().resolve()
        try:
            return get_project_space().ensure_initialized().resolve()
        except Exception:
            return Path.cwd().resolve()


CPBE_ENGINE = CerebroGuardrailEngine()


@input_guardrail(name="cpbe_input_authorization_guard")
async def cpbe_input_guardrail(
    ctx: RunContextWrapper[None],
    agent: Agent,
    input: str | list[TResponseInputItem],
) -> GuardrailFunctionOutput:
    """Preflight guard that evaluates user-supplied proposed actions and override intents."""
    _ = ctx
    _ = agent

    if os.getenv("CEREBRO_GUARDRAILS", "true").lower() == "false":
        return GuardrailFunctionOutput(output_info={"action": "allowed", "reason": "Guardrails disabled"}, tripwire_triggered=False)

    if isinstance(input, list):
        content = " ".join(str(x) for x in input)
    else:
        content = str(input)

    assessment = CPBE_ENGINE.evaluate_preflight(
        proposed_action=content,
        actor=getattr(agent, "name", "unknown-agent") if agent is not None else "unknown-agent",
        metadata={"source": "input_guardrail"},
    )

    return GuardrailFunctionOutput(
        output_info=clean_data(asdict(assessment)),
        tripwire_triggered=assessment.blocked,
    )


@output_guardrail(name="cpbe_output_preflight_guard")
async def cpbe_output_guardrail(
    ctx: RunContextWrapper[None],
    agent: Agent,
    output: Any,
) -> GuardrailFunctionOutput:
    """Pre-flight interception to block unsafe out-of-scope command proposals."""
    _ = ctx
    if os.getenv("CEREBRO_GUARDRAILS", "true").lower() == "false":
        return GuardrailFunctionOutput(output_info={"action": "allowed", "reason": "Guardrails disabled"}, tripwire_triggered=False)

    proposed = _extract_proposed_action(output)
    assessment = CPBE_ENGINE.evaluate_preflight(
        proposed_action=proposed,
        actor=getattr(agent, "name", "unknown-agent") if agent is not None else "unknown-agent",
        metadata={"source": "output_guardrail"},
    )

    return GuardrailFunctionOutput(
        output_info=clean_data(asdict(assessment)),
        tripwire_triggered=assessment.blocked,
    )


def _extract_proposed_action(output: Any) -> str:
    if output is None:
        return ""

    if isinstance(output, str):
        return output

    if isinstance(output, Mapping):
        for key in (
            "command",
            "cmd",
            "shell",
            "action",
            "tool_input",
            "query",
            "sql",
            "content",
        ):
            if key in output and output[key]:
                return str(output[key])
        return json.dumps(dict(output), ensure_ascii=True)

    if isinstance(output, list):
        return "\n".join(str(item) for item in output)

    return str(output)


def get_security_guardrails() -> tuple[list[Any], list[Any]]:
    """Return CPBE guardrails while honoring environment-level disable toggle."""
    if os.getenv("CEREBRO_GUARDRAILS", "true").lower() == "false":
        return [], []
    return [cpbe_input_guardrail], [cpbe_output_guardrail]


__all__ = [
    "StandingAuthorization",
    "PreflightAssessment",
    "CerebroGuardrailEngine",
    "CPBE_ENGINE",
    "cpbe_input_guardrail",
    "cpbe_output_guardrail",
    "get_security_guardrails",
]
