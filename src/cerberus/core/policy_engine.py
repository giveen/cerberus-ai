from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from cerberus.config import settings
from cerberus.verification.policy_engine import (
    PolicyEngine as VerificationPolicyEngine,
    PolicyFinding,
    PolicyReport,
    format_logic_audit_report,
    render_logic_audit_report_markdown,
)


class PolicyDecision(str, Enum):
    APPROVED = "APPROVED"
    LOG_AND_APPROVE = "LOG_AND_APPROVE"
    REQUIRES_HUMAN_APPROVAL = "REQUIRES_HUMAN_APPROVAL"


_TIER_4_BY_NAME = set(settings.tier4_tool_names)


def infer_risk_tier(tool_name: str, declared_risk_tier: int | None = None) -> int:
    min_tier = int(settings.risk_tier_min)
    max_tier = int(settings.risk_tier_max)

    if declared_risk_tier is not None:
        return max(min_tier, min(int(declared_risk_tier), max_tier))

    if tool_name in _TIER_4_BY_NAME:
        return int(settings.manual_approval_tier)

    return min_tier


@dataclass(frozen=True)
class PolicyResult:
    decision: PolicyDecision
    risk_tier: int
    was_repaired: bool
    tool_name: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "risk_tier": self.risk_tier,
            "was_repaired": self.was_repaired,
            "tool_name": self.tool_name,
            "reason": self.reason,
        }


def evaluate_tool_execution(
    *,
    tool_name: str,
    risk_tier: int,
    was_repaired: bool,
    arguments: dict[str, Any],
) -> PolicyResult:
    """Evaluate tool execution policy for runtime invocation gating."""
    tier = infer_risk_tier(tool_name, risk_tier)

    if tier <= int(settings.auto_approve_max_tier):
        return PolicyResult(
            decision=PolicyDecision.APPROVED,
            risk_tier=tier,
            was_repaired=was_repaired,
            tool_name=tool_name,
            reason="low_risk_tier_auto_approved",
        )

    if tier >= int(settings.elevated_logged_min_tier) and not was_repaired:
        return PolicyResult(
            decision=PolicyDecision.LOG_AND_APPROVE,
            risk_tier=tier,
            was_repaired=was_repaired,
            tool_name=tool_name,
            reason="high_risk_but_strict_json",
        )

    if tier == int(settings.manual_approval_tier) and was_repaired:
        return PolicyResult(
            decision=PolicyDecision.REQUIRES_HUMAN_APPROVAL,
            risk_tier=tier,
            was_repaired=was_repaired,
            tool_name=tool_name,
            reason="tier4_repaired_payload_requires_hitl",
        )

    return PolicyResult(
        decision=PolicyDecision.LOG_AND_APPROVE,
        risk_tier=tier,
        was_repaired=was_repaired,
        tool_name=tool_name,
        reason="repaired_payload_elevated_tier_logged",
    )


class PolicyEngine(VerificationPolicyEngine):
    """Unified policy engine facade with a single validate_command entrypoint."""

    def validate_command(
        self,
        *,
        action: dict[str, Any] | None = None,
        tool_name: str = "",
        risk_tier: int | None = None,
        was_repaired: bool = False,
        arguments: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        command = dict(action or {})
        resolved_tool = str(tool_name or command.get("tool_name", "") or "").strip()
        resolved_arguments = arguments if isinstance(arguments, dict) else command.get("arguments", {})
        if not isinstance(resolved_arguments, dict):
            resolved_arguments = {}

        if resolved_tool and "tool_name" not in command:
            command["tool_name"] = resolved_tool
        if "arguments" not in command:
            command["arguments"] = resolved_arguments

        report = self.verify(command)
        runtime_policy = evaluate_tool_execution(
            tool_name=resolved_tool or str(command.get("tool_name", "") or ""),
            risk_tier=infer_risk_tier(resolved_tool, risk_tier),
            was_repaired=bool(was_repaired),
            arguments=resolved_arguments,
        )

        return {
            "verification": report.to_dict(),
            "runtime": runtime_policy.to_dict(),
            "decision": runtime_policy.decision.value,
            "requires_approval": (
                report.manual_approval_required
                or runtime_policy.decision == PolicyDecision.REQUIRES_HUMAN_APPROVAL
            ),
        }


__all__ = [
    "PolicyDecision",
    "PolicyEngine",
    "PolicyFinding",
    "PolicyReport",
    "PolicyResult",
    "evaluate_tool_execution",
    "format_logic_audit_report",
    "render_logic_audit_report_markdown",
]
