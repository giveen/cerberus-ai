from __future__ import annotations

import pytest
from rxconfig import config

from cerberus_dashboard.cerberus_dashboard import (
    _build_sessions,
    _new_session,
    _next_session_slot,
    determine_grid_layout,
)


def test_dashboard_starts_with_single_agent_terminal() -> None:
    sessions = _build_sessions()

    assert len(sessions) == 1
    assert sessions[0].session_id == "AGENT-1"
    assert sessions[0].role
    assert sessions[0].status == "ready"


def test_next_session_slot_reuses_first_open_agent_slot() -> None:
    sessions = [_new_session(0), _new_session(2)]

    assert _next_session_slot(sessions) == 1


@pytest.mark.parametrize(
    ("count", "expected"),
    [
        (0, ("1", "1")),
        (1, ("1", "1")),
        (2, ("2", "1")),
        (3, ("2", "2")),
        (4, ("2", "2")),
    ],
)
def test_determine_grid_layout_matches_workspace_rules(
    count: int,
    expected: tuple[str, str],
) -> None:
    assert determine_grid_layout(count) == expected


def test_reflex_badge_is_disabled_in_config() -> None:
    assert config.show_built_with_reflex is False