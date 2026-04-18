from __future__ import annotations

import json

from cerberus.repl.commands.mcp import (
    ensure_configured_mcp_servers,
    get_mcp_manager,
    reset_mcp_bootstrap_state,
)


def main() -> int:
    reset_mcp_bootstrap_state()
    status = ensure_configured_mcp_servers(force=True)
    manager = get_mcp_manager()

    payload = {
        "connections": sorted(manager.connections.keys()),
        "tool_count": len(manager.tool_registry),
        "tools": sorted(manager.tool_registry.keys()),
        "status": status,
    }
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
