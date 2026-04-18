from __future__ import annotations

from typing import TypedDict


class CommandMetadata(TypedDict):
    desc: str
    tier: int


COMMAND_REGISTRY: dict[str, CommandMetadata] = {
    "/clear": {"desc": "Clear the active terminal session", "tier": 1},
    "/reset": {"desc": "Reset the Agent context and memory", "tier": 2},
    "/search": {"desc": "Toggle Global Search Mode (On/Off)", "tier": 1},
    "/approve": {"desc": "Approve the pending Tier-4 tool call", "tier": 3},
    "/logs": {"desc": "Export current session logs to /logs", "tier": 1},
    "/archive": {"desc": "Archive current session as Mission Report", "tier": 1},
    "/help": {"desc": "Show this command list", "tier": 1},
}

# Stable list form for menu rendering in Reflex.
COMMAND_MENU_ITEMS: list[dict[str, str | int]] = [
    {"command": command, "desc": meta["desc"], "tier": int(meta["tier"])}
    for command, meta in COMMAND_REGISTRY.items()
]
