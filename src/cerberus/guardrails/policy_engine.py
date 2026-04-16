from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class PolicyDecision(str, Enum):
    APPROVED = "APPROVED"
    LOG_AND_APPROVE = "LOG_AND_APPROVE"
    REQUIRES_HUMAN_APPROVAL = "REQUIRES_HUMAN_APPROVAL"


_TIER_4_BY_NAME = {
    "generic_linux_command",
    "run_metasploit",
    "nmap_scan",
    "nmap",
}


def infer_risk_tier(tool_name: str, declared_risk_tier: int | None = None) -> int:
    if declared_risk_tier is not None:
        return max(1, min(int(declared_risk_tier), 4))

    if tool_name in _TIER_4_BY_NAME:
        return 4

    return 1


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
    """Evaluate whether a tool call can execute immediately.

    Policy logic:
    - Tier <= 2: APPROVED
    - Tier >= 3 and strict JSON parse (no repair): LOG_AND_APPROVE
    - Tier 4 and repaired payload: REQUIRES_HUMAN_APPROVAL
    - Tier 3 and repaired payload: LOG_AND_APPROVE
    """
    tier = infer_risk_tier(tool_name, risk_tier)

    if tier <= 2:
        return PolicyResult(
            decision=PolicyDecision.APPROVED,
            risk_tier=tier,
            was_repaired=was_repaired,
            tool_name=tool_name,
            reason="low_risk_tier_auto_approved",
        )

    if tier >= 3 and not was_repaired:
        return PolicyResult(
            decision=PolicyDecision.LOG_AND_APPROVE,
            risk_tier=tier,
            was_repaired=was_repaired,
            tool_name=tool_name,
            reason="high_risk_but_strict_json",
        )

    if tier == 4 and was_repaired:
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
