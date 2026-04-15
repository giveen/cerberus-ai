"""Process reaper command for Cerebro REPL.

This module provides a commercial-safe implementation for terminating
runaway agents and background tool processes while preserving forensic state.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import inspect
import json
import logging
import os
from pathlib import Path
import signal
from typing import Any, Dict, List, Optional, Set, Tuple

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from cai.memory import MemoryManager
from cai.repl.commands.base import FrameworkCommand, register_command
from cai.repl.commands.parallel import PARALLEL_AGENT_INSTANCES, PARALLEL_CONFIGS
from cai.sdk.agents.parallel_isolation import PARALLEL_ISOLATION
from cai.sdk.agents.simple_agent_manager import AGENT_MANAGER
from cai.tools.sessions import ACTIVE_SESSIONS, FRIENDLY_SESSION_MAP, REVERSE_SESSION_MAP, SESSIONS_LOCK

try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover - handled at runtime
    psutil = None


console = Console()
_log = logging.getLogger(__name__)


_REASON_CODES = {
    "USER_INTERVENTION",
    "RESOURCE_EXHAUSTION",
    "AGENT_LOOP_DETECTED",
}


@dataclass
class ReapResult:
    """Outcome for a reaped process target."""

    pid: int
    success: bool
    graceful_signal: int
    forced_signal: Optional[int]
    reaped_pids: List[int]
    message: str


class ProcessReaper:
    """Validated psutil-based process termination utility."""

    def __init__(self, workspace_root: Optional[Path] = None) -> None:
        self._root_pid = os.getpid()
        self._workspace_root = workspace_root or self._resolve_workspace_root()
        self._audit_path = self._workspace_root / ".cai" / "audit" / "kill_actions.jsonl"

    @staticmethod
    def _resolve_workspace_root() -> Path:
        try:
            from cai.tools.workspace import get_project_space

            return get_project_space().ensure_initialized().resolve()
        except Exception:
            return Path.cwd().resolve()

    def _session_pids(self) -> Set[int]:
        pids: Set[int] = set()
        with SESSIONS_LOCK:
            for session in ACTIVE_SESSIONS.values():
                proc = getattr(session, "process", None)
                pid = getattr(proc, "pid", None)
                if isinstance(pid, int) and pid > 0:
                    pids.add(pid)
        return pids

    def _is_descendant_of_root(self, proc: Any) -> bool:
        cur = proc
        while True:
            if cur.pid == self._root_pid:
                return True
            parent = cur.parent()
            if parent is None:
                return False
            cur = parent

    def validate_boundary(self, pid: int) -> Tuple[bool, str]:
        if psutil is None:
            return False, "psutil is required for kill operations"
        if pid <= 1:
            return False, "Refusing to terminate PID <= 1"
        if pid == self._root_pid:
            return False, "Refusing to terminate current REPL process"
        if not psutil.pid_exists(pid):
            return False, f"PID {pid} does not exist"

        try:
            proc = psutil.Process(pid)
        except psutil.Error as exc:  # type: ignore[attr-defined]
            return False, f"Unable to inspect PID {pid}: {exc}"

        if self._is_descendant_of_root(proc):
            return True, "PID belongs to framework process tree"

        if pid in self._session_pids():
            # Extra allowance for framework-managed tool sessions.
            return True, "PID belongs to framework session registry"

        return False, "PID is outside framework process tree boundary"

    def terminate_pid(self, pid: int, *, force: bool = False) -> ReapResult:
        ok, reason = self.validate_boundary(pid)
        if not ok:
            return ReapResult(
                pid=pid,
                success=False,
                graceful_signal=signal.SIGTERM,
                forced_signal=signal.SIGKILL if force else None,
                reaped_pids=[],
                message=reason,
            )

        assert psutil is not None

        try:
            root = psutil.Process(pid)
        except psutil.Error as exc:  # type: ignore[attr-defined]
            return ReapResult(
                pid=pid,
                success=False,
                graceful_signal=signal.SIGTERM,
                forced_signal=signal.SIGKILL if force else None,
                reaped_pids=[],
                message=f"Cannot access process: {exc}",
            )

        targets: List[Any] = []
        try:
            targets = root.children(recursive=True)
        except psutil.Error:
            targets = []
        targets.append(root)

        # Children first, root last.
        ordered = sorted({p.pid: p for p in targets}.values(), key=lambda p: p.pid, reverse=True)

        for proc in ordered:
            try:
                proc.send_signal(signal.SIGTERM)
            except psutil.NoSuchProcess:  # type: ignore[attr-defined]
                continue
            except psutil.AccessDenied:  # type: ignore[attr-defined]
                continue
            except psutil.Error:
                continue

        gone, alive = psutil.wait_procs(ordered, timeout=2.0)

        force_used = False
        if alive and force:
            force_used = True
            for proc in alive:
                try:
                    proc.send_signal(signal.SIGKILL)
                except psutil.NoSuchProcess:  # type: ignore[attr-defined]
                    continue
                except psutil.AccessDenied:  # type: ignore[attr-defined]
                    continue
                except psutil.Error:
                    continue
            gone2, alive = psutil.wait_procs(alive, timeout=1.5)
            gone.extend(gone2)

        # Best-effort zombie reaping for exited descendants.
        for proc in gone:
            try:
                proc.wait(timeout=0.2)
            except Exception:
                continue

        reaped = sorted({p.pid for p in gone})
        if alive:
            return ReapResult(
                pid=pid,
                success=False,
                graceful_signal=signal.SIGTERM,
                forced_signal=signal.SIGKILL if force_used else None,
                reaped_pids=reaped,
                message=f"{len(alive)} process(es) survived termination",
            )

        return ReapResult(
            pid=pid,
            success=True,
            graceful_signal=signal.SIGTERM,
            forced_signal=signal.SIGKILL if force_used else None,
            reaped_pids=reaped,
            message="Process tree terminated and reaped",
        )

    def append_audit(self, payload: Dict[str, Any]) -> None:
        self._audit_path.parent.mkdir(parents=True, exist_ok=True)
        with self._audit_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=True) + "\n")


class KillCommand(FrameworkCommand):
    """Terminate agent loops or framework-scoped tool processes safely."""

    name = "/kill"
    description = "Terminate active agent loops or background tool processes"
    aliases = ["/k"]

    def __init__(self) -> None:
        super().__init__()
        self._memory = self._resolve_memory_manager()
        self._reaper = ProcessReaper()

    @property
    def help(self) -> str:
        return (
            "Usage: /kill --agent <name> [--reason <CODE>]\n"
            "       /kill --tool <pid> [--force] [--reason <CODE>]\n"
            "       /kill --all [--force] [--reason <CODE>]\n"
            "Reason Codes: USER_INTERVENTION | RESOURCE_EXHAUSTION | AGENT_LOOP_DETECTED"
        )

    async def execute(self, args: List[str]) -> bool:
        if psutil is None:
            console.print("[red]psutil is required. Install with: pip install psutil[/red]")
            return False

        parsed = self._parse_args(args)
        if parsed is None:
            return False

        action = parsed["action"]
        reason = parsed["reason"]
        force = parsed["force"]

        if action == "agent":
            return await self._kill_agent(target=str(parsed["target"]), reason=reason)
        if action == "tool":
            return self._kill_tool_pid(target=int(parsed["target"]), reason=reason, force=force)
        if action == "all":
            return await self._kill_all(reason=reason, force=force)

        console.print(self.help)
        return False

    def _parse_args(self, args: List[str]) -> Optional[Dict[str, Any]]:
        if not args:
            console.print(self.help)
            return None

        out: Dict[str, Any] = {
            "action": None,
            "target": None,
            "reason": "USER_INTERVENTION",
            "force": False,
        }

        # Backward compatibility: /kill <pid>
        if len(args) == 1 and args[0].isdigit():
            out["action"] = "tool"
            out["target"] = int(args[0])
            return out

        i = 0
        while i < len(args):
            token = args[i]
            if token in {"--help", "-h", "help"}:
                console.print(self.help)
                return None

            if token == "--force":
                out["force"] = True
                i += 1
                continue

            if token == "--reason":
                if i + 1 >= len(args):
                    console.print("[red]--reason requires a code[/red]")
                    return None
                reason = args[i + 1].strip().upper()
                if reason not in _REASON_CODES:
                    console.print(f"[red]Invalid reason code: {reason}[/red]")
                    console.print(f"[yellow]Allowed: {', '.join(sorted(_REASON_CODES))}[/yellow]")
                    return None
                out["reason"] = reason
                i += 2
                continue

            if token == "--agent":
                if i + 1 >= len(args):
                    console.print("[red]--agent requires a name[/red]")
                    return None
                out["action"] = "agent"
                out["target"] = args[i + 1]
                i += 2
                continue

            if token == "--tool":
                if i + 1 >= len(args):
                    console.print("[red]--tool requires a pid[/red]")
                    return None
                if not args[i + 1].isdigit():
                    console.print("[red]--tool pid must be numeric[/red]")
                    return None
                out["action"] = "tool"
                out["target"] = int(args[i + 1])
                i += 2
                continue

            if token == "--all":
                out["action"] = "all"
                i += 1
                continue

            console.print(f"[red]Unknown argument: {token}[/red]")
            console.print(self.help)
            return None

        if out["action"] is None:
            console.print("[red]Missing target: use --agent, --tool, or --all[/red]")
            console.print(self.help)
            return None

        return out

    async def _kill_agent(self, *, target: str, reason: str) -> bool:
        matched = self._find_agents(target)
        if not matched:
            console.print(f"[yellow]No matching agent found for '{target}'[/yellow]")
            return False

        stopped_count = 0
        for agent_name, agent_id in matched:
            stopped_count += await self._stop_agent_loops(agent_name=agent_name)
            self._recover_agent_state(agent_name=agent_name, reason=reason)
            self._audit_action(
                action="agent",
                reason=reason,
                target=agent_name,
                success=True,
                details={"agent_id": agent_id, "stopped_loops": stopped_count},
            )

        console.print(
            Panel(
                f"Stopped {stopped_count} loop(s) across {len(matched)} agent target(s).",
                title="Kill Agent",
                border_style="green",
                box=box.ROUNDED,
            )
        )
        return True

    def _kill_tool_pid(self, *, target: int, reason: str, force: bool) -> bool:
        result = self._reaper.terminate_pid(target, force=force)
        self._cleanup_session_registry_for_pid(target)
        self._recover_tool_state(pid=target, reason=reason, success=result.success, message=result.message)

        self._record_memory_event(
            topic="kill.tool",
            finding=f"Tool PID {target} termination requested by user",
            artifacts={
                "reason": reason,
                "force": force,
                "success": result.success,
                "message": result.message,
                "reaped_pids": result.reaped_pids,
            },
        )

        self._audit_action(
            action="tool",
            reason=reason,
            target=str(target),
            success=result.success,
            details={
                "message": result.message,
                "reaped_pids": result.reaped_pids,
                "graceful_signal": result.graceful_signal,
                "forced_signal": result.forced_signal,
            },
        )

        style = "green" if result.success else "red"
        console.print(
            Panel(
                f"PID {target}: {result.message}",
                title="Kill Tool",
                border_style=style,
                box=box.ROUNDED,
            )
        )
        return result.success

    async def _kill_all(self, *, reason: str, force: bool) -> bool:
        rows: List[Tuple[str, str]] = []
        success = True

        # 1) Cancel known agent loops first.
        total_stopped = 0
        for name in AGENT_MANAGER.get_registered_agents().keys():
            total_stopped += await self._stop_agent_loops(agent_name=name)
            self._recover_agent_state(agent_name=name, reason=reason)

        rows.append(("agent_loops", str(total_stopped)))

        # 2) Reap known session processes.
        pids = self._collect_framework_tool_pids()
        pids.update(self._collect_framework_descendant_pids())
        reaped = 0
        for pid in sorted(pids):
            result = self._reaper.terminate_pid(pid, force=force)
            if result.success:
                reaped += 1
            else:
                success = False
            self._cleanup_session_registry_for_pid(pid)
            self._audit_action(
                action="tool",
                reason=reason,
                target=str(pid),
                success=result.success,
                details={"message": result.message, "reaped_pids": result.reaped_pids},
            )
            self._recover_tool_state(pid=pid, reason=reason, success=result.success, message=result.message)

        rows.append(("tool_processes", f"{reaped}/{len(pids)}"))

        # 3) Reset parallel metadata if panic used.
        if PARALLEL_CONFIGS:
            PARALLEL_AGENT_INSTANCES.clear()
            rows.append(("parallel_instances", "cleared"))

        self._record_memory_event(
            topic="kill.all",
            finding="Emergency kill --all executed",
            artifacts={
                "reason": reason,
                "force": force,
                "agent_loops_stopped": total_stopped,
                "tool_targets": sorted(pids),
                "success": success,
            },
        )

        table = Table(title="Kill All Summary", box=box.SIMPLE_HEAVY)
        table.add_column("Component", style="cyan")
        table.add_column("Result", style="white")
        for key, value in rows:
            table.add_row(key, value)
        console.print(table)

        self._audit_action(
            action="all",
            reason=reason,
            target="*",
            success=success,
            details={"agent_loops_stopped": total_stopped, "tool_targets": sorted(pids)},
        )
        return success

    def _resolve_memory_manager(self) -> MemoryManager:
        candidate = self.memory
        if isinstance(candidate, MemoryManager):
            return candidate
        return MemoryManager()

    def _find_agents(self, target: str) -> List[Tuple[str, str]]:
        needle = target.strip().lower()
        matched: List[Tuple[str, str]] = []
        for name, agent_id in AGENT_MANAGER.get_registered_agents().items():
            if needle == name.lower() or needle == str(agent_id).lower() or needle in name.lower():
                matched.append((name, agent_id))
        return matched

    async def _stop_agent_loops(self, *, agent_name: str) -> int:
        stopped = 0

        # Stop active agent if name matches.
        active = AGENT_MANAGER.get_active_agent()
        if active is not None:
            active_name = getattr(active, "name", "")
            if active_name and active_name.lower() == agent_name.lower():
                stopped += await self._stop_agent_object(active)

        # Stop known parallel instances tied to this agent.
        for (config_name, _idx), agent in list(PARALLEL_AGENT_INSTANCES.items()):
            display = getattr(agent, "name", config_name)
            if agent_name.lower() in {display.lower(), config_name.lower()}:
                stopped += await self._stop_agent_object(agent)

        return stopped

    async def _stop_agent_object(self, agent: Any) -> int:
        count = 0

        task_obj = getattr(agent, "_task", None)
        if task_obj is not None and hasattr(task_obj, "done") and not task_obj.done():
            task_obj.cancel()
            count += 1

        stop_fn = getattr(agent, "stop", None)
        if callable(stop_fn):
            try:
                res = stop_fn()
                if inspect.isawaitable(res):
                    await res
                count += 1
            except Exception as exc:
                _log.warning("Agent stop() failed: %s", exc)

        model = getattr(agent, "model", None)
        if model is not None:
            model_task = getattr(model, "_task", None)
            if model_task is not None and hasattr(model_task, "done") and not model_task.done():
                model_task.cancel()
                count += 1

        return count

    def _recover_agent_state(self, *, agent_name: str, reason: str) -> None:
        stamp = datetime.now(tz=UTC).isoformat()
        marker = {
            "role": "system",
            "content": (
                f"[TERMINATED_BY_USER] agent={agent_name} reason={reason} "
                f"timestamp={stamp}"
            ),
            "timestamp": stamp,
            "metadata": {
                "event": "kill.agent",
                "reason": reason,
            },
        }

        AGENT_MANAGER.add_to_history(agent_name, marker)

        agent_id = AGENT_MANAGER.get_id_by_name(agent_name)
        if agent_id and PARALLEL_ISOLATION.has_isolated_histories():
            hist = PARALLEL_ISOLATION.get_isolated_history(agent_id) or []
            hist.append(marker)
            PARALLEL_ISOLATION.replace_isolated_history(agent_id, hist)

        self._record_memory_event(
            topic="kill.recovery",
            finding=f"Agent loop halted and recovery marker inserted for {agent_name}",
            artifacts={
                "agent": agent_name,
                "reason": reason,
                "timestamp": stamp,
            },
        )

    def _collect_framework_tool_pids(self) -> Set[int]:
        pids: Set[int] = set()
        with SESSIONS_LOCK:
            for session in ACTIVE_SESSIONS.values():
                proc = getattr(session, "process", None)
                pid = getattr(proc, "pid", None)
                if isinstance(pid, int) and pid > 0:
                    pids.add(pid)
        return pids

    def _collect_framework_descendant_pids(self) -> Set[int]:
        if psutil is None:
            return set()
        pids: Set[int] = set()
        try:
            root = psutil.Process(os.getpid())
            for proc in root.children(recursive=True):
                if proc.pid > 1 and proc.pid != os.getpid():
                    pids.add(proc.pid)
        except Exception:
            return pids
        return pids

    def _recover_tool_state(self, *, pid: int, reason: str, success: bool, message: str) -> None:
        stamp = datetime.now(tz=UTC).isoformat()
        marker = {
            "role": "system",
            "content": (
                f"[TOOL_TERMINATED_BY_USER] pid={pid} reason={reason} "
                f"success={str(success).lower()} message={message} timestamp={stamp}"
            ),
            "timestamp": stamp,
            "metadata": {
                "event": "kill.tool.recovery",
                "reason": reason,
                "pid": pid,
                "success": success,
            },
        }

        target_agent_name = None
        active = AGENT_MANAGER.get_active_agent()
        if active is not None:
            name = getattr(active, "name", None)
            if isinstance(name, str) and name.strip():
                target_agent_name = name

        if target_agent_name is None:
            reg = AGENT_MANAGER.get_registered_agents()
            if reg:
                target_agent_name = next(iter(reg.keys()))

        if target_agent_name:
            AGENT_MANAGER.add_to_history(target_agent_name, marker)

        self._record_memory_event(
            topic="kill.recovery",
            finding=f"Tool termination marker inserted for pid {pid}",
            artifacts={
                "pid": pid,
                "reason": reason,
                "success": success,
                "message": message,
                "timestamp": stamp,
                "agent": target_agent_name,
            },
        )

    def _cleanup_session_registry_for_pid(self, pid: int) -> None:
        stale_ids: List[str] = []
        with SESSIONS_LOCK:
            for sid, session in ACTIVE_SESSIONS.items():
                proc = getattr(session, "process", None)
                spid = getattr(proc, "pid", None)
                if spid == pid:
                    setattr(session, "is_running", False)
                    stale_ids.append(sid)

            for sid in stale_ids:
                ACTIVE_SESSIONS.pop(sid, None)
                friendly = REVERSE_SESSION_MAP.pop(sid, None)
                if friendly:
                    FRIENDLY_SESSION_MAP.pop(friendly, None)

    def _record_memory_event(self, *, topic: str, finding: str, artifacts: Dict[str, Any]) -> None:
        try:
            self._memory.record(
                {
                    "topic": topic,
                    "finding": finding,
                    "source": "kill_command",
                    "tags": ["kill", "forensics", "state-recovery"],
                    "artifacts": artifacts,
                }
            )
        except Exception as exc:
            _log.debug("memory record failed: %s", exc)

    def _audit_action(
        self,
        *,
        action: str,
        reason: str,
        target: str,
        success: bool,
        details: Dict[str, Any],
    ) -> None:
        payload = {
            "timestamp": datetime.now(tz=UTC).isoformat(),
            "user": self.session.user,
            "action": action,
            "target": target,
            "reason_code": reason,
            "success": success,
            "details": details,
        }
        try:
            self._reaper.append_audit(payload)
        except Exception as exc:
            _log.debug("audit write failed: %s", exc)


KILL_COMMAND_INSTANCE = KillCommand()
register_command(KILL_COMMAND_INSTANCE)
