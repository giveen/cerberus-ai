from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Any, Literal, Sequence

from pydantic import BaseModel, Field


class ManagedMCPServerSettings(BaseModel):
    alias: str
    enabled: bool = True
    transport: Literal["stdio", "sse"] = "stdio"
    management_mode: Literal["managed", "external"] = "managed"
    repo: str | None = None
    package_spec: str | None = None
    ref: str = "main"
    launch_command: list[str] = Field(default_factory=list)
    endpoint: str | None = None
    endpoint_env: str | None = None
    required_commands: list[str] = Field(default_factory=list)
    required_env: list[str] = Field(default_factory=list)
    ready_paths: list[str] = Field(default_factory=list)
    bootstrap_strategy: Literal["none", "npm", "npm-build", "npm-build-ignore-scripts", "npm-package", "pnpm-build"] = "none"
    agents: list[str] = Field(default_factory=lambda: ["*"])
    notes: str = ""


def default_managed_mcp_servers() -> list[ManagedMCPServerSettings]:
    return [
        ManagedMCPServerSettings(
            alias="wiremcp",
            enabled=True,
            management_mode="managed",
            repo="https://github.com/0xKoda/WireMCP.git",
            launch_command=["node", "{install_dir}/index.js"],
            required_commands=["git", "node", "npm", "tshark"],
            ready_paths=["node_modules"],
            bootstrap_strategy="npm",
            notes="Managed stdio integration for packet capture and PCAP analysis.",
        ),
        ManagedMCPServerSettings(
            alias="nmap-mcp",
            enabled=True,
            management_mode="managed",
            package_spec="mcp-nmap-server@1.0.1",
            launch_command=["node", "{install_dir}/node_modules/mcp-nmap-server/dist/index.js"],
            required_commands=["node", "npm", "nmap"],
            ready_paths=["node_modules/mcp-nmap-server/dist/index.js"],
            bootstrap_strategy="npm-package",
            notes="Managed stdio integration for Nmap scans exposed through the pinned published npm package.",
        ),
        ManagedMCPServerSettings(
            alias="nmap-mcp-source",
            enabled=False,
            management_mode="managed",
            repo="https://github.com/PhialsBasement/nmap-mcp-server.git",
            launch_command=["node", "{install_dir}/dist/index.js"],
            required_commands=["git", "node", "npm", "nmap"],
            ready_paths=["node_modules", "dist/index.js"],
            bootstrap_strategy="npm-build-ignore-scripts",
            notes="Disabled source build variant of nmap-mcp-server for environments that require repo pinning.",
        ),
        ManagedMCPServerSettings(
            alias="hexstrike-ai",
            enabled=True,
            transport="stdio",
            management_mode="external",
            endpoint_env="CERBERUS_HEXSTRIKE_MCP_COMMAND",
            required_commands=["python3"],
            required_env=["CERBERUS_HEXSTRIKE_MCP_COMMAND"],
            notes=(
                "HexStrike MCP bridge command. Configure CERBERUS_HEXSTRIKE_MCP_COMMAND "
                "to point at the stdio MCP bridge command, e.g. "
                "python3 /opt/hexstrike-ai/hexstrike_mcp.py --server http://127.0.0.1:8888"
            ),
        ),
        ManagedMCPServerSettings(
            alias="container-mcp",
            enabled=True,
            transport="sse",
            management_mode="external",
            endpoint_env="CERBERUS_CONTAINER_MCP_URL",
            required_env=["CERBERUS_CONTAINER_MCP_URL"],
            notes="Container-MCP SSE endpoint (typically http://127.0.0.1:8000/sse).",
        ),
        ManagedMCPServerSettings(
            alias="awsome-kali-mcpservers",
            enabled=True,
            transport="stdio",
            management_mode="external",
            endpoint_env="CERBERUS_AWSOME_KALI_MCP_COMMAND",
            required_commands=["docker"],
            required_env=["CERBERUS_AWSOME_KALI_MCP_COMMAND"],
            notes=(
                "Awesome Kali MCP stdio command, typically docker run -i <image>. "
                "Set CERBERUS_AWSOME_KALI_MCP_COMMAND to the full command."
            ),
        ),
        ManagedMCPServerSettings(
            alias="burp-mcp",
            enabled=False,
            transport="sse",
            management_mode="external",
            endpoint_env="CERBERUS_BURP_MCP_URL",
            required_env=["CERBERUS_BURP_MCP_URL"],
            notes="User-managed Burp MCP endpoint. Not bootstrapped inside the Kali runtime.",
        ),
        ManagedMCPServerSettings(
            alias="portswigger-mcp",
            enabled=True,
            transport="sse",
            management_mode="external",
            endpoint_env="CERBERUS_PORTSWIGGER_MCP_URL",
            required_env=["CERBERUS_PORTSWIGGER_MCP_URL"],
            notes="PortSwigger Burp MCP SSE endpoint (typically http://127.0.0.1:9876 or /sse).",
        ),
    ]


def resolve_mcp_bootstrap_root(configured_root: str | None = None) -> Path:
    candidate = (configured_root or "").strip() or os.getenv("CERBERUS_MCP_BOOTSTRAP_ROOT", "").strip()
    if candidate:
        return Path(candidate).expanduser().resolve()

    xdg_cache = os.getenv("XDG_CACHE_HOME", "").strip()
    if xdg_cache:
        return (Path(xdg_cache).expanduser() / "cerberus" / "mcp").resolve()
    return (Path.home() / ".cache" / "cerberus" / "mcp").resolve()


def prepare_configured_mcp_servers(
    server_specs: Sequence[ManagedMCPServerSettings] | None = None,
    configured_root: str | None = None,
) -> list[dict[str, Any]]:
    bootstrap_root = resolve_mcp_bootstrap_root(configured_root)
    results: list[dict[str, Any]] = []

    for spec in server_specs or default_managed_mcp_servers():
        if not spec.enabled or spec.management_mode != "managed":
            continue
        try:
            results.append(prepare_managed_mcp_server(spec, bootstrap_root))
        except RuntimeError as exc:
            message = str(exc)
            if "Missing required environment variables:" in message:
                results.append(
                    {
                        "alias": spec.alias,
                        "status": "skipped",
                        "reason": message,
                    }
                )
                continue
            raise

    return results


def prepare_managed_mcp_server(
    spec: ManagedMCPServerSettings,
    bootstrap_root: str | Path | None = None,
) -> dict[str, Any]:
    root = resolve_mcp_bootstrap_root(str(bootstrap_root) if bootstrap_root is not None else None)
    install_dir = root / spec.alias
    root.mkdir(parents=True, exist_ok=True)

    _ensure_requirements(spec)
    if spec.management_mode != "managed":
        return {"alias": spec.alias, "status": "external"}

    _prepare_install_dir(spec, install_dir)
    changed = False
    if not _is_ready(spec, install_dir):
        for command in _bootstrap_commands(spec, install_dir):
            _run_command(command, cwd=install_dir)
        changed = True

    return {
        "alias": spec.alias,
        "status": "bootstrapped" if changed else "ready",
        "install_dir": str(install_dir.resolve()),
    }


def resolve_managed_mcp_endpoint(
    spec: ManagedMCPServerSettings,
    bootstrap_root: str | Path | None = None,
) -> str:
    missing_env = [key for key in spec.required_env if not os.getenv(key, "").strip()]
    if missing_env:
        raise RuntimeError(f"Missing required environment variables: {', '.join(missing_env)}")

    endpoint = (spec.endpoint or "").strip()
    if not endpoint and spec.endpoint_env:
        endpoint = os.getenv(spec.endpoint_env, "").strip()

    if spec.transport == "sse":
        if not endpoint:
            raise RuntimeError(f"No SSE endpoint configured for MCP alias '{spec.alias}'")
        return endpoint

    if endpoint:
        return endpoint

    if spec.management_mode != "managed":
        raise RuntimeError(f"No stdio command configured for external MCP alias '{spec.alias}'")

    root = resolve_mcp_bootstrap_root(str(bootstrap_root) if bootstrap_root is not None else None)
    install_dir = root / spec.alias
    if not install_dir.exists():
        raise RuntimeError(f"Managed MCP install directory missing for '{spec.alias}': {install_dir}")
    if not spec.launch_command:
        raise RuntimeError(f"No launch command configured for managed MCP alias '{spec.alias}'")

    tokens = [token.format(install_dir=str(install_dir.resolve())) for token in spec.launch_command]
    return "stdio:" + " ".join(tokens)


def _ensure_requirements(spec: ManagedMCPServerSettings) -> None:
    missing_commands = [command for command in spec.required_commands if not _command_is_available(command)]
    if missing_commands:
        raise RuntimeError(f"Missing required commands: {', '.join(missing_commands)}")

    missing_env = [key for key in spec.required_env if not os.getenv(key, "").strip()]
    if missing_env:
        raise RuntimeError(f"Missing required environment variables: {', '.join(missing_env)}")

    if spec.management_mode == "managed" and not spec.repo and not spec.package_spec:
        raise RuntimeError(f"Managed MCP alias '{spec.alias}' is missing a repository URL or package spec")


def _prepare_install_dir(spec: ManagedMCPServerSettings, install_dir: Path) -> None:
    if spec.bootstrap_strategy == "npm-package":
        install_dir.mkdir(parents=True, exist_ok=True)
        return

    if install_dir.exists():
        if not (install_dir / ".git").exists():
            raise RuntimeError(f"Existing MCP install directory is not a git checkout: {install_dir}")
        return

    _run_command(
        ["git", "clone", "--depth", "1", "--branch", spec.ref, str(spec.repo), str(install_dir)],
        cwd=None,
    )


def _is_ready(spec: ManagedMCPServerSettings, install_dir: Path) -> bool:
    if not spec.ready_paths:
        return False
    return all((install_dir / relative_path).exists() for relative_path in spec.ready_paths)


def _bootstrap_commands(spec: ManagedMCPServerSettings, install_dir: Path) -> list[list[str]]:
    if spec.bootstrap_strategy == "none":
        return []
    if spec.bootstrap_strategy == "npm":
        return [_npm_install_command(install_dir)]
    if spec.bootstrap_strategy == "npm-build":
        return [_npm_install_command(install_dir), _package_manager_command("npm", "run", "build")]
    if spec.bootstrap_strategy == "npm-build-ignore-scripts":
        return [_npm_install_ignore_scripts_command(), _package_manager_command("npm", "run", "build")]
    if spec.bootstrap_strategy == "npm-package":
        return [_npm_package_install_command(spec.package_spec)]
    if spec.bootstrap_strategy == "pnpm-build":
        return [_pnpm_install_command(install_dir), _package_manager_command("pnpm", "run", "build")]
    raise RuntimeError(f"Unsupported MCP bootstrap strategy: {spec.bootstrap_strategy}")


def _npm_install_command(install_dir: Path) -> list[str]:
    if (install_dir / "package-lock.json").exists():
        return _package_manager_command("npm", "ci", "--no-fund", "--no-audit")
    return _package_manager_command("npm", "install", "--no-fund", "--no-audit")


def _npm_install_ignore_scripts_command() -> list[str]:
    return _package_manager_command("npm", "install", "--ignore-scripts", "--no-fund", "--no-audit")


def _npm_package_install_command(package_spec: str | None) -> list[str]:
    if not package_spec:
        raise RuntimeError("Missing npm package spec for managed MCP bootstrap")
    return _package_manager_command("npm", "install", "--ignore-scripts", "--no-fund", "--no-audit", "--omit=dev", package_spec)


def _pnpm_install_command(install_dir: Path) -> list[str]:
    if (install_dir / "pnpm-lock.yaml").exists():
        return _package_manager_command("pnpm", "install", "--frozen-lockfile")
    return _package_manager_command("pnpm", "install")


def _command_is_available(command: str) -> bool:
    if command in {"npm", "pnpm"}:
        return _resolve_package_manager_prefix(command) is not None
    return shutil.which(command) is not None


def _package_manager_command(manager: Literal["npm", "pnpm"], *args: str) -> list[str]:
    prefix = _resolve_package_manager_prefix(manager)
    if prefix is None:
        raise RuntimeError(f"Missing required commands: {manager}")
    return [*prefix, *args]


def _resolve_package_manager_prefix(manager: Literal["npm", "pnpm"]) -> list[str] | None:
    if shutil.which(manager) is not None:
        return [manager]
    if shutil.which("corepack") is not None:
        return ["corepack", manager]
    return None


def _run_command(command: Sequence[str], cwd: Path | None) -> None:
    env = _augment_path_with_package_manager_shims({**os.environ, "CI": os.environ.get("CI", "1")})
    completed = subprocess.run(
        list(command),
        cwd=str(cwd) if cwd is not None else None,
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    if completed.returncode == 0:
        return

    stderr = (completed.stderr or "").strip()
    stdout = (completed.stdout or "").strip()
    message = stderr or stdout or f"command exited with {completed.returncode}"
    raise RuntimeError(f"Command '{' '.join(command)}' failed: {message}")


def _augment_path_with_package_manager_shims(env: dict[str, str]) -> dict[str, str]:
    shim_dir = _ensure_package_manager_shims()
    if shim_dir is None:
        return env

    updated_env = dict(env)
    current_path = updated_env.get("PATH", "")
    updated_env["PATH"] = ":".join(entry for entry in (str(shim_dir), current_path) if entry)
    return updated_env


def _ensure_package_manager_shims() -> Path | None:
    if shutil.which("corepack") is None:
        return None

    missing_managers = [manager for manager in ("npm", "pnpm") if shutil.which(manager) is None]
    if not missing_managers:
        return None

    shim_dir = Path(tempfile.gettempdir()) / "cerberus-mcp-shims"
    shim_dir.mkdir(parents=True, exist_ok=True)
    for manager in missing_managers:
        shim_path = shim_dir / manager
        if not shim_path.exists():
            shim_path.write_text(f"#!/bin/sh\nexec corepack {manager} \"$@\"\n", encoding="utf-8")
            shim_path.chmod(0o755)
    return shim_dir


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Prepare managed third-party MCP servers")
    parser.add_argument(
        "--prepare-supported",
        action="store_true",
        help="Clone and bootstrap the enabled managed MCP servers.",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    if not args.prepare_supported:
        parser.print_help()
        return 0

    results = prepare_configured_mcp_servers()
    print(json.dumps(results, indent=2))
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())