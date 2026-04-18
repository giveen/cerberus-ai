"""Tests for CerebroAgentFactory MCP tool injection and shadow gating."""
from __future__ import annotations

from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest

from cerberus.agents import Agent
from cerberus.agents.tool import FunctionTool


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_function_tool(name: str) -> FunctionTool:
    async def _noop(_ctx: Any, _input: str) -> str:
        return ""

    return FunctionTool(
        name=name,
        description=f"test tool {name}",
        params_json_schema={"type": "object", "properties": {}},
        on_invoke_tool=_noop,
        strict_json_schema=False,
    )


def _make_base_agent(tool_names: list[str]) -> Agent:
    tools = [_make_function_tool(n) for n in tool_names]
    return Agent(name="test_agent", instructions="test", tools=tools)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestInjectMcpTools:
    """Unit tests for CerebroAgentFactory._inject_mcp_tools."""

    def _make_factory(self):
        from cerberus.agents.factory import CerebroAgentFactory
        with patch("cerberus.agents.factory.CerebroAgentFactory._discover_agents"):
            factory = CerebroAgentFactory.__new__(CerebroAgentFactory)
            factory._lock = __import__("threading").RLock()
            factory._logger = __import__("logging").getLogger("test")
            return factory

    def _make_mock_manager(self, tool_names: list[str], connected_aliases: list[str]) -> MagicMock:
        manager = MagicMock()
        manager.connections = {alias: MagicMock() for alias in connected_aliases}
        manager.tool_registry = {name: _make_function_tool(name) for name in tool_names}
        return manager

    def test_mcp_tools_added_to_agent(self):
        """MCP tools from tool_registry are injected into the agent."""
        factory = self._make_factory()
        agent = _make_base_agent(["generic_linux_command"])

        mock_manager = self._make_mock_manager(
            tool_names=["mcp::wiremcp::check_ip_threats", "mcp::nmap-mcp::run_nmap_scan"],
            connected_aliases=["wiremcp", "nmap-mcp"],
        )

        with patch("importlib.import_module") as mock_import:
            mock_module = MagicMock()
            mock_module.get_mcp_manager = lambda bootstrap: mock_manager
            mock_import.return_value = mock_module

            factory._inject_mcp_tools(agent, "red_teamer")

        tool_names = {t.name for t in agent.tools}
        assert "mcp::wiremcp::check_ip_threats" in tool_names
        assert "mcp::nmap-mcp::run_nmap_scan" in tool_names
        assert "generic_linux_command" in tool_names

    def test_shadowed_builtin_nmap_removed_when_nmap_mcp_connected(self):
        """Built-in 'nmap' is removed when nmap-mcp MCP server is connected."""
        factory = self._make_factory()
        agent = _make_base_agent(["nmap", "generic_linux_command", "curl"])

        mock_manager = self._make_mock_manager(
            tool_names=["mcp::nmap-mcp::run_nmap_scan"],
            connected_aliases=["nmap-mcp"],
        )

        with patch("importlib.import_module") as mock_import:
            mock_module = MagicMock()
            mock_module.get_mcp_manager = lambda bootstrap: mock_manager
            mock_import.return_value = mock_module

            factory._inject_mcp_tools(agent, "red_teamer")

        tool_names = {t.name for t in agent.tools}
        assert "nmap" not in tool_names, "Built-in nmap should be removed when nmap-mcp is connected"
        assert "mcp::nmap-mcp::run_nmap_scan" in tool_names
        assert "generic_linux_command" in tool_names
        assert "curl" in tool_names

    def test_shadowed_wiremcp_capture_tools_removed_when_wiremcp_connected(self):
        """Built-in capture tools are removed when wiremcp is connected."""
        factory = self._make_factory()
        agent = _make_base_agent(["capture_remote_traffic", "remote_capture_session", "curl"])

        mock_manager = self._make_mock_manager(
            tool_names=["mcp::wiremcp::capture_packets", "mcp::wiremcp::get_summary_stats"],
            connected_aliases=["wiremcp"],
        )

        with patch("importlib.import_module") as mock_import:
            mock_module = MagicMock()
            mock_module.get_mcp_manager = lambda bootstrap: mock_manager
            mock_import.return_value = mock_module

            factory._inject_mcp_tools(agent, "network_traffic_analyzer")

        tool_names = {t.name for t in agent.tools}
        assert "capture_remote_traffic" not in tool_names
        assert "remote_capture_session" not in tool_names
        assert "mcp::wiremcp::capture_packets" in tool_names
        assert "curl" in tool_names

    def test_shadowed_builtin_kept_when_mcp_server_not_connected(self):
        """Built-in 'nmap' is kept when nmap-mcp is NOT connected."""
        factory = self._make_factory()
        agent = _make_base_agent(["nmap", "curl"])

        # nmap-mcp not in connections
        mock_manager = self._make_mock_manager(
            tool_names=[],
            connected_aliases=[],
        )

        with patch("importlib.import_module") as mock_import:
            mock_module = MagicMock()
            mock_module.get_mcp_manager = lambda bootstrap: mock_manager
            mock_import.return_value = mock_module

            factory._inject_mcp_tools(agent, "red_teamer")

        tool_names = {t.name for t in agent.tools}
        assert "nmap" in tool_names, "Built-in nmap should be kept when nmap-mcp is not connected"

    def test_no_mcp_tools_is_noop(self):
        """When manager has no tools, agent tools are unchanged."""
        factory = self._make_factory()
        agent = _make_base_agent(["nmap", "curl"])

        mock_manager = self._make_mock_manager(tool_names=[], connected_aliases=[])

        with patch("importlib.import_module") as mock_import:
            mock_module = MagicMock()
            mock_module.get_mcp_manager = lambda bootstrap: mock_manager
            mock_import.return_value = mock_module

            factory._inject_mcp_tools(agent, "red_teamer")

        tool_names = {t.name for t in agent.tools}
        assert tool_names == {"nmap", "curl"}

    def test_mcp_exception_leaves_agent_unchanged(self):
        """Exception during MCP injection leaves agent tools unchanged."""
        factory = self._make_factory()
        agent = _make_base_agent(["nmap", "curl"])
        original_tools = list(agent.tools)

        with patch("importlib.import_module", side_effect=RuntimeError("mcp unavailable")):
            factory._inject_mcp_tools(agent, "red_teamer")

        assert agent.tools == original_tools

    def test_mcp_tool_shadows_constant_defines_expected_entries(self):
        """_MCP_TOOL_SHADOWS contains the expected built-in → alias mappings."""
        from cerberus.agents.factory import CerebroAgentFactory

        shadows = CerebroAgentFactory._MCP_TOOL_SHADOWS
        assert shadows["nmap"] == "nmap-mcp"
        assert shadows["capture_remote_traffic"] == "wiremcp"
        assert shadows["remote_capture_session"] == "wiremcp"
