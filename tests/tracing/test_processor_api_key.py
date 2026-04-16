"""Tests confirming that WorkspaceSpanExporter never requires an API key and
never makes external network calls.
"""

import pytest

from cerberus.agents.tracing.processors import WorkspaceSpanExporter


def test_workspace_exporter_ignores_set_api_key():
    """set_api_key must be a no-op — calling it must not raise and the exporter
    must remain usable with no side-effects."""
    exporter = WorkspaceSpanExporter()
    # Should not raise regardless of what value is passed
    exporter.set_api_key("should-be-ignored")
    exporter.set_api_key("")
    exporter.set_api_key("OPENAI_API_KEY_PLACEHOLDER")


def test_workspace_exporter_export_empty_list(tmp_path, monkeypatch):
    """Exporting an empty list must be a silent no-op."""
    monkeypatch.setenv("CERBERUS_WORKSPACE_ACTIVE_ROOT", str(tmp_path))
    exporter = WorkspaceSpanExporter()
    # Must not raise and must not create any log file
    exporter.export([])


def test_workspace_exporter_close_is_noop(tmp_path, monkeypatch):
    """close() must never raise."""
    monkeypatch.setenv("CERBERUS_WORKSPACE_ACTIVE_ROOT", str(tmp_path))
    exporter = WorkspaceSpanExporter()
    exporter.close()  # should be a no-op


@pytest.mark.asyncio
async def test_workspace_exporter_no_network_access(monkeypatch):
    """WorkspaceSpanExporter must never open any socket.

    We patch socket.socket.__init__ to raise if instantiated so that any
    accidental network call would fail the test loudly.
    """
    import socket

    original_init = socket.socket.__init__

    def _raise_on_socket(*args, **kwargs):
        raise AssertionError("WorkspaceSpanExporter must not open a network socket")

    monkeypatch.setattr(socket.socket, "__init__", _raise_on_socket)

    # Constructing the exporter and calling set_api_key must be socket-free
    exporter = WorkspaceSpanExporter()
    exporter.set_api_key("any-key")
    exporter.close()

    monkeypatch.setattr(socket.socket, "__init__", original_init)
