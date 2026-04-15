import time
import pytest

import cerberus.tools.sessions as sessions


@pytest.fixture(autouse=True)
def reset_sessions():
    """Reset the session registry before and after each test."""
    sessions.SESSION_COUNTER = 0
    with sessions.SESSIONS_LOCK:
        sessions.ACTIVE_SESSIONS.clear()
        sessions.FRIENDLY_SESSION_MAP.clear()
        sessions.REVERSE_SESSION_MAP.clear()
        sessions.SESSION_OUTPUT_COUNTER.clear()
    yield
    with sessions.SESSIONS_LOCK:
        sessions.ACTIVE_SESSIONS.clear()
        sessions.FRIENDLY_SESSION_MAP.clear()
        sessions.REVERSE_SESSION_MAP.clear()
        sessions.SESSION_OUTPUT_COUNTER.clear()
    sessions.SESSION_COUNTER = 0


class DummyCTF:
    def __init__(self):
        self.calls = []

    def get_shell(self, cmd):
        self.calls.append(cmd)
        return f"ctf:{cmd}"


def test_create_ctf_session_send_and_get_output_and_terminate():
    ctf = DummyCTF()
    session_id = sessions.create_shell_session("echo hello", ctf=ctf, workspace_dir="/tmp")
    assert isinstance(session_id, str)

    s = sessions.get_session(session_id)
    assert s is not None

    # Start appended CTF output should be present
    out = sessions.get_session_output(session_id)
    assert "ctf:echo hello" in out

    # Sending input to CTF-backed session should call get_shell again
    # Mark session as running to exercise the CTF input code path
    s.is_running = True
    res = sessions.send_to_session(session_id, "whoami")
    assert res == "Input sent to CTF session"
    out2 = sessions.get_session_output(session_id)
    assert "ctf:whoami" in out2

    # Resolve by session id and friendly identifiers
    friendly = s.friendly_id
    assert sessions._resolve_session_id(session_id) == session_id
    assert sessions._resolve_session_id(friendly) == session_id
    num = friendly[1:]
    assert sessions._resolve_session_id(f"#{num}") == session_id

    # Terminate removes session from registry
    term = sessions.terminate_session(session_id)
    assert session_id not in sessions.ACTIVE_SESSIONS
    assert "terminated" in term or "already terminated" in term


def test_get_new_output_behaviour():
    ctf = DummyCTF()
    sid = sessions.create_shell_session("a", ctf=ctf, workspace_dir="/tmp")
    s = sessions.get_session(sid)

    # First call returns existing output and advances position
    new1 = s.get_new_output(mark_position=True)
    assert "ctf:a" in new1

    # Second call returns empty string
    new2 = s.get_new_output(mark_position=True)
    assert new2 == ""


def test_resolve_last_prefers_running_session():
    ctf1 = DummyCTF()
    ctf2 = DummyCTF()
    s1_id = sessions.create_shell_session("cmd1", ctf=ctf1, workspace_dir="/tmp")
    s2_id = sessions.create_shell_session("cmd2", ctf=ctf2, workspace_dir="/tmp")
    s1 = sessions.get_session(s1_id)
    s2 = sessions.get_session(s2_id)

    # Simulate s2 as running and more recent
    s2.is_running = True
    s2.created_at = s1.created_at + 10

    resolved = sessions._resolve_session_id("last")
    assert resolved == s2_id
