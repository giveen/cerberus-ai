# NetworkConnectionstool in exploitFlow
"""
Netstat tool
"""
import re

from cerberus.tools.common import run_command   # pylint: disable=import-error
from cerberus.sdk.agents import function_tool

from cerberus.tools.validation import validate_args_no_injection  # pylint: disable=import-error
from cerberus.tools import validation  # pylint: disable=import-error


def _validate_netstat_input(args: str):
    """Return an error string if inputs are unsafe, else None."""
    err = validate_args_no_injection(args, 'args', max_length=256)
    if err:
        return err
    return None


@function_tool
def netstat(args: str = '', timeout: int = 5) -> str:
    """
    netstat tool to list listening ports and associated programs.

    Args:
        args: Additional arguments to pass to the netstat command (e.g. "-tulnp").
              Do not include shell metacharacters or redirections.
        timeout: Maximum seconds to wait for the command (default 5).

    Returns:
        str: The output of running the netstat command, or an error string.

    Examples:
        netstat()  # default: `netstat -tuln`
        netstat(args='-tulnp')  # include program/PID column
    """
    err = _validate_netstat_input(args)
    if err:
        return err

    base = 'netstat -tuln'
    command = f"{base} {args.strip()}" if args else base
    guard_err = validation.validate_command_guardrails(command)
    if guard_err:
        return guard_err
    return run_command(command, timeout=timeout)
