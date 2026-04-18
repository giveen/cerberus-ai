from pathlib import Path
from types import SimpleNamespace
import tempfile
from unittest.mock import AsyncMock, Mock, patch

from cerberus.mcp_bootstrap import (
    ManagedMCPServerSettings,
    _augment_path_with_package_manager_shims,
    _bootstrap_commands,
    default_managed_mcp_servers,
    prepare_managed_mcp_server,
    _package_manager_command,
    resolve_managed_mcp_endpoint,
)
from cerberus.repl.commands.mcp import (
    _AGENT_MCP_ASSOCIATIONS,
    ensure_configured_mcp_servers,
    reset_mcp_bootstrap_state,
)


class TestMCPBootstrap:
    def setup_method(self):
        _AGENT_MCP_ASSOCIATIONS.clear()
        reset_mcp_bootstrap_state()

    def teardown_method(self):
        _AGENT_MCP_ASSOCIATIONS.clear()
        reset_mcp_bootstrap_state()

    @patch("cerberus.repl.commands.mcp.get_available_agents")
    @patch("cerberus.repl.commands.mcp.resolve_managed_mcp_endpoint")
    @patch("cerberus.repl.commands.mcp.prepare_managed_mcp_server")
    @patch("cerberus.repl.commands.mcp.get_settings")
    def test_ensure_configured_mcp_servers_connects_enabled_specs(
        self,
        mock_get_settings,
        mock_prepare,
        mock_resolve_endpoint,
        mock_get_available_agents,
    ):
        mock_get_available_agents.return_value = {"agent_a": Mock(), "agent_b": Mock()}
        mock_get_settings.return_value = SimpleNamespace(
            mcp_autoload_enabled=True,
            mcp_bootstrap_root="/tmp/managed-mcp",
            mcp_managed_servers=[
                ManagedMCPServerSettings(
                    alias="nmap-mcp",
                    enabled=True,
                    package_spec="mcp-nmap-server@1.0.1",
                    launch_command=["node", "{install_dir}/node_modules/mcp-nmap-server/dist/index.js"],
                    required_commands=[],
                    ready_paths=["node_modules/mcp-nmap-server/dist/index.js"],
                    bootstrap_strategy="npm-package",
                    agents=["*"],
                )
            ],
        )
        mock_prepare.return_value = {"alias": "nmap-mcp", "status": "ready", "install_dir": "/tmp/managed-mcp/nmap-mcp"}
        mock_resolve_endpoint.return_value = "stdio:node /tmp/managed-mcp/nmap-mcp/node_modules/mcp-nmap-server/dist/index.js"

        manager = Mock()
        manager.connections = {}
        manager.connect = AsyncMock()

        results = ensure_configured_mcp_servers(manager=manager, force=True)

        manager.connect.assert_awaited_once_with(
            alias="nmap-mcp",
            endpoint="stdio:node /tmp/managed-mcp/nmap-mcp/node_modules/mcp-nmap-server/dist/index.js",
            associate_agents=["*"],
        )
        assert _AGENT_MCP_ASSOCIATIONS["agent_a"] == ["nmap-mcp"]
        assert _AGENT_MCP_ASSOCIATIONS["agent_b"] == ["nmap-mcp"]
        assert results[0]["status"] == "connected"

    @patch("cerberus.repl.commands.mcp.get_settings")
    def test_ensure_configured_mcp_servers_noops_when_disabled(self, mock_get_settings):
        mock_get_settings.return_value = SimpleNamespace(
            mcp_autoload_enabled=False,
            mcp_bootstrap_root="",
            mcp_managed_servers=[],
        )

        manager = Mock()
        manager.connections = {}
        manager.connect = AsyncMock()

        results = ensure_configured_mcp_servers(manager=manager)

        assert results == []
        manager.connect.assert_not_called()

    @patch("cerberus.repl.commands.mcp.get_settings")
    def test_ensure_configured_mcp_servers_skips_when_required_env_missing(self, mock_get_settings):
        mock_get_settings.return_value = SimpleNamespace(
            mcp_autoload_enabled=True,
            mcp_bootstrap_root="/tmp/managed-mcp",
            mcp_managed_servers=[
                ManagedMCPServerSettings(
                    alias="hexstrike-ai",
                    enabled=True,
                    transport="stdio",
                    management_mode="external",
                    endpoint_env="CERBERUS_HEXSTRIKE_MCP_COMMAND",
                    required_env=["CERBERUS_HEXSTRIKE_MCP_COMMAND"],
                    required_commands=[],
                )
            ],
        )

        manager = Mock()
        manager.connections = {}
        manager.connect = AsyncMock()

        with patch.dict("os.environ", {}, clear=True):
            results = ensure_configured_mcp_servers(manager=manager, force=True)

        assert results[0]["status"] == "skipped"
        assert results[0]["reason"] == "missing_required_env:CERBERUS_HEXSTRIKE_MCP_COMMAND"
        manager.connect.assert_not_called()

    @patch("cerberus.repl.commands.mcp.get_settings")
    def test_ensure_configured_mcp_servers_skips_external_when_endpoint_missing(self, mock_get_settings):
        mock_get_settings.return_value = SimpleNamespace(
            mcp_autoload_enabled=True,
            mcp_bootstrap_root="/tmp/managed-mcp",
            mcp_managed_servers=[
                ManagedMCPServerSettings(
                    alias="portswigger-mcp",
                    enabled=True,
                    transport="sse",
                    management_mode="external",
                    endpoint_env="CERBERUS_PORTSWIGGER_MCP_URL",
                    required_env=[],
                    required_commands=[],
                )
            ],
        )

        manager = Mock()
        manager.connections = {}
        manager.connect = AsyncMock()

        with patch.dict("os.environ", {}, clear=True):
            results = ensure_configured_mcp_servers(manager=manager, force=True)

        assert results[0]["status"] == "skipped"
        assert results[0]["reason"] == "missing_endpoint"
        manager.connect.assert_not_called()

    @patch("cerberus.repl.commands.mcp.get_available_agents")
    @patch("cerberus.repl.commands.mcp.resolve_managed_mcp_endpoint")
    @patch("cerberus.repl.commands.mcp.prepare_managed_mcp_server")
    @patch("cerberus.repl.commands.mcp.get_settings")
    def test_ensure_configured_mcp_servers_tolerates_agent_enumeration_failure(
        self,
        mock_get_settings,
        mock_prepare,
        mock_resolve_endpoint,
        mock_get_available_agents,
    ):
        mock_get_available_agents.side_effect = RuntimeError("missing OPENAI_API_KEY")
        mock_get_settings.return_value = SimpleNamespace(
            mcp_autoload_enabled=True,
            mcp_bootstrap_root="/tmp/managed-mcp",
            mcp_managed_servers=[
                ManagedMCPServerSettings(
                    alias="nmap-mcp",
                    enabled=True,
                    package_spec="mcp-nmap-server@1.0.1",
                    launch_command=["node", "{install_dir}/node_modules/mcp-nmap-server/dist/index.js"],
                    required_commands=[],
                    ready_paths=["node_modules/mcp-nmap-server/dist/index.js"],
                    bootstrap_strategy="npm-package",
                    agents=["*"],
                )
            ],
        )
        mock_prepare.return_value = {"alias": "nmap-mcp", "status": "ready", "install_dir": "/tmp/managed-mcp/nmap-mcp"}
        mock_resolve_endpoint.return_value = "stdio:node /tmp/managed-mcp/nmap-mcp/node_modules/mcp-nmap-server/dist/index.js"

        manager = Mock()
        manager.connections = {}
        manager.connect = AsyncMock()

        results = ensure_configured_mcp_servers(manager=manager, force=True)

        manager.connect.assert_awaited_once()
        assert results[0]["status"] == "connected"
        assert results[0]["agents"] == []

    @patch("cerberus.mcp_bootstrap.shutil.which")
    def test_package_manager_command_uses_corepack_fallback(self, mock_which):
        def _fake_which(name: str) -> str | None:
            if name == "corepack":
                return "/usr/bin/corepack"
            if name == "npm":
                return None
            return f"/usr/bin/{name}"

        mock_which.side_effect = _fake_which

        command = _package_manager_command("npm", "ci", "--no-fund")

        assert command == ["corepack", "npm", "ci", "--no-fund"]

    @patch("cerberus.mcp_bootstrap.shutil.which")
    def test_augment_path_with_package_manager_shims_creates_wrappers(self, mock_which):
        def _fake_which(name: str) -> str | None:
            if name == "corepack":
                return "/usr/bin/corepack"
            if name in {"npm", "pnpm"}:
                return None
            return f"/usr/bin/{name}"

        mock_which.side_effect = _fake_which

        with tempfile.TemporaryDirectory() as temp_dir:
            with patch("cerberus.mcp_bootstrap.tempfile.gettempdir", return_value=temp_dir):
                env = _augment_path_with_package_manager_shims({"PATH": "/usr/bin"})

                shim_dir = Path(temp_dir) / "cerberus-mcp-shims"
                assert (shim_dir / "npm").exists()
                assert (shim_dir / "pnpm").exists()
                assert env["PATH"].split(":", 1)[0] == str(shim_dir)

    @patch("cerberus.mcp_bootstrap.shutil.which")
    def test_npm_build_ignore_scripts_strategy(self, mock_which):
        def _fake_which(name: str) -> str | None:
            if name == "corepack":
                return "/usr/bin/corepack"
            if name == "npm":
                return None
            return f"/usr/bin/{name}"

        mock_which.side_effect = _fake_which

        commands = _bootstrap_commands(
            ManagedMCPServerSettings(
                alias="nmap-mcp",
                repo="https://example.invalid/nmap-mcp.git",
                bootstrap_strategy="npm-build-ignore-scripts",
            ),
            Path("/tmp/nmap-mcp"),
        )

        assert commands == [
            ["corepack", "npm", "install", "--ignore-scripts", "--no-fund", "--no-audit"],
            ["corepack", "npm", "run", "build"],
        ]

    @patch("cerberus.mcp_bootstrap.shutil.which")
    def test_npm_package_strategy(self, mock_which):
        def _fake_which(name: str) -> str | None:
            if name == "corepack":
                return "/usr/bin/corepack"
            if name == "npm":
                return None
            return f"/usr/bin/{name}"

        mock_which.side_effect = _fake_which

        commands = _bootstrap_commands(
            ManagedMCPServerSettings(
                alias="nmap-mcp",
                package_spec="mcp-nmap-server@1.0.1",
                bootstrap_strategy="npm-package",
            ),
            Path("/tmp/nmap-mcp"),
        )

        assert commands == [
            ["corepack", "npm", "install", "--ignore-scripts", "--no-fund", "--no-audit", "--omit=dev", "mcp-nmap-server@1.0.1"],
        ]

    def test_prepare_managed_package_server_without_repo(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            install_dir = Path(temp_dir) / "nmap-mcp" / "node_modules" / "mcp-nmap-server" / "dist"
            install_dir.mkdir(parents=True)
            (install_dir / "index.js").write_text("console.log('ready')\n", encoding="utf-8")

            result = prepare_managed_mcp_server(
                ManagedMCPServerSettings(
                    alias="nmap-mcp",
                    package_spec="mcp-nmap-server@1.0.1",
                    required_commands=[],
                    ready_paths=["node_modules/mcp-nmap-server/dist/index.js"],
                    bootstrap_strategy="npm-package",
                ),
                Path(temp_dir),
            )

            assert result["status"] == "ready"

    def test_resolve_managed_mcp_endpoint_stdio_uses_endpoint_env(self):
        with patch.dict("os.environ", {"CERBERUS_TEST_STDIO_CMD": "python3 /tmp/fake_mcp.py"}, clear=False):
            endpoint = resolve_managed_mcp_endpoint(
                ManagedMCPServerSettings(
                    alias="test-stdio",
                    enabled=True,
                    transport="stdio",
                    management_mode="external",
                    endpoint_env="CERBERUS_TEST_STDIO_CMD",
                    required_commands=[],
                )
            )

        assert endpoint == "python3 /tmp/fake_mcp.py"

    def test_default_managed_mcp_servers_contains_requested_aliases(self):
        aliases = {spec.alias for spec in default_managed_mcp_servers()}

        assert "wiremcp" in aliases
        assert "nmap-mcp" in aliases
        assert "nmap-mcp-source" in aliases
        assert "hexstrike-ai" in aliases
        assert "burp-mcp" in aliases
        assert "portswigger-mcp" in aliases
        assert "container-mcp" in aliases
        assert "awsome-kali-mcpservers" in aliases