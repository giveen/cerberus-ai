from cerberus.core.policy_engine import PolicyDecision, evaluate_tool_execution


def test_tier_two_tool_is_auto_approved() -> None:
    result = evaluate_tool_execution(
        tool_name="whoami",
        risk_tier=2,
        was_repaired=False,
        arguments={},
    )

    assert result.decision == PolicyDecision.APPROVED


def test_tier_three_tool_is_logged_and_allowed() -> None:
    result = evaluate_tool_execution(
        tool_name="nmap",
        risk_tier=3,
        was_repaired=False,
        arguments={"target": "127.0.0.1"},
    )

    assert result.decision == PolicyDecision.LOG_AND_APPROVE
    assert result.reason == "tier3_logged_execution"


def test_tier_four_tool_always_requires_human_approval() -> None:
    repaired = evaluate_tool_execution(
        tool_name="generic_linux_command",
        risk_tier=4,
        was_repaired=True,
        arguments={"command": "rm -rf /tmp/demo"},
    )
    strict = evaluate_tool_execution(
        tool_name="generic_linux_command",
        risk_tier=4,
        was_repaired=False,
        arguments={"command": "rm -rf /tmp/demo"},
    )

    assert repaired.decision == PolicyDecision.REQUIRES_HUMAN_APPROVAL
    assert strict.decision == PolicyDecision.REQUIRES_HUMAN_APPROVAL