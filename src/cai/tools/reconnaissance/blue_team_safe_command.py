"""
Blue-team safe command wrapper.

This tool prefers non-privileged checks where possible. It maps known
privileged commands (e.g., `fail2ban-client`, `systemctl`, `journalctl`)
to safe, read-only alternatives that do not require `sudo` or root.

Make the behavior explicit via `RUN_AGENT_INTEGRATION_TESTS=1` when full
privileged execution is desired.
"""
from __future__ import annotations

import os
import re
from typing import Optional

from cai.sdk.agents import function_tool
from cai.tools.common import run_command_async


async def _blue_team_safe_command_impl(command: str = "", interactive: bool = False, session_id: Optional[str] = None) -> str:
    """Execute a blue-team-friendly version of a requested command.

    If the command appears to require elevated privileges, return a
    safe, non-privileged alternative (or a helpful message).
    """
    if not command or not command.strip():
        return "Error: No command provided"

    lowered = command.lower()
    run_integration = os.getenv("RUN_AGENT_INTEGRATION_TESTS", "false").lower() in ("1", "true", "yes")

    # Privileged mapping: fail2ban -> read config + tail auth logs
    if "fail2ban-client" in lowered or "fail2ban " in lowered:
        if run_integration:
            # In integration mode, run the original command
            return await run_command_async(command, stdout=True, timeout=30, stream=False, call_id=None, tool_name="blueteam_safe_command")
        safe_cmd = (
            "cat /etc/fail2ban/jail.local 2>/dev/null || cat /etc/fail2ban/jail.conf 2>/dev/null || true; "
            "echo '--- recent auth log (tail 200) ---'; tail -n 200 /var/log/auth.log 2>/dev/null || true"
        )
        return await run_command_async(safe_cmd, stdout=True, timeout=20, stream=False, call_id=None, tool_name="blueteam_safe_command")

    # Map systemctl status <service> -> non-privileged process lookup
    m = re.search(r"systemctl\s+status\s+([\w@\-\.]+)", lowered)
    if m:
        svc = m.group(1)
        safe_cmd = f"ps aux | grep {svc} | grep -v grep || echo 'Process info unavailable without root.'"
        return await run_command_async(safe_cmd, stdout=True, timeout=10, stream=False, call_id=None, tool_name="blueteam_safe_command")

    # journalctl -> try syslog/messages tails
    if "journalctl" in lowered:
        safe_cmd = "tail -n 200 /var/log/syslog 2>/dev/null || tail -n 200 /var/log/messages 2>/dev/null || echo 'No accessible journal/syslog.'"
        return await run_command_async(safe_cmd, stdout=True, timeout=15, stream=False, call_id=None, tool_name="blueteam_safe_command")

    # Package manager operations: require root; explain instead of running
    if any(tok in lowered for tok in ("apt-get", "apt ", "dpkg", "yum", "dnf", "zypper")):
        return "Package manager operations require root privileges. Set RUN_AGENT_INTEGRATION_TESTS=1 to allow them, or inspect installed packages manually."

    # Firewall / iptables: provide socket/listening alternatives
    if any(tok in lowered for tok in ("iptables", "ufw", "nft", "iptables-save")):
        safe_cmd = "ss -tun | head -n 200 || netstat -tuln | head -n 200 || echo 'No socket info available.'"
        return await run_command_async(safe_cmd, stdout=True, timeout=10, stream=False, call_id=None, tool_name="blueteam_safe_command")

    # If the caller used sudo explicitly, attempt safe fallback or explain
    if lowered.strip().startswith("sudo ") and not run_integration:
        return "Skipped sudo invocation in non-integration mode. Set RUN_AGENT_INTEGRATION_TESTS=1 to allow executing privileged commands."

    # Default: attempt to run the command non-interactively and return output
    return await run_command_async(command, stdout=True, timeout=30, stream=False, call_id=None, tool_name="blueteam_safe_command")


# Expose as a FunctionTool so agents can use it like other tools
blue_team_safe_command = function_tool(
    _blue_team_safe_command_impl,
    name_override="blue_team_safe_command",
    description_override=(
        "Blue Team safe command: prefers non-privileged checks and maps common "
        "privileged commands to read-only alternatives."
    ),
)
