"""Canary tool to attest Kali Docker execution path."""

from __future__ import annotations

from typing import Any, Dict

from cerberus.sdk.agents import function_tool
from cerberus.tools.common import execute_system_command


@function_tool
async def ping_kali() -> Dict[str, Any]:
    """Run a minimal canary command to prove execution happens in Kali Docker."""

    result = await execute_system_command(argv=["uname", "-a"])
    payload = result.model_dump()
    payload.setdefault("metadata", {})
    payload["metadata"]["canary_tool"] = "ping_kali"
    return payload


__all__ = ["ping_kali"]
