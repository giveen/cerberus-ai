"""Shutdown coordination utilities.

Provides a small coordinator that can be used to perform VRAM-aware cleanup
and optional process termination (e.g., for external router processes) on
controlled shutdown (Ctrl+C) events.
"""
from __future__ import annotations

import os
from typing import Callable, Iterable, List, Optional


class ShutdownCoordinator:
    """Coordinate shutdown actions and best-effort hardware cleanup."""

    def __init__(self):
        self._callbacks: List[Callable[[], None]] = []

    def register(self, cb: Callable[[], None]) -> None:
        """Register a synchronous callback to be invoked during shutdown."""
        if cb not in self._callbacks:
            self._callbacks.append(cb)

    def unregister(self, cb: Callable[[], None]) -> None:
        if cb in self._callbacks:
            self._callbacks.remove(cb)

    def _attempt_gpu_cleanup(self) -> None:
        try:
            import torch

            if hasattr(torch, "cuda") and torch.cuda.is_available():
                try:
                    torch.cuda.empty_cache()
                except Exception:
                    pass
        except Exception:
            # torch not installed or unavailable - ignore
            pass

    def _terminate_processes_by_name(self, names: Optional[Iterable[str]]) -> None:
        if not names:
            return
        try:
            import psutil

            for name in names:
                if not name:
                    continue
                for proc in psutil.process_iter(["pid", "name", "cmdline"]):
                    try:
                        info = proc.info
                        pname = (info.get("name") or "")
                        cmdline = info.get("cmdline") or []
                        if name in pname or any(name in str(c) for c in cmdline):
                            try:
                                proc.terminate()
                            except Exception:
                                try:
                                    proc.kill()
                                except Exception:
                                    pass
                    except Exception:
                        continue
        except Exception:
            # psutil not installed or failure enumerating processes - ignore
            pass

    def shutdown(self, sigterm_targets: Optional[Iterable[str]] = None) -> None:
        """Perform coordinated shutdown actions.

        This will attempt GPU cleanup, terminate named processes, and run
        any registered callbacks. All actions are best-effort and errors
        are silently ignored to avoid masking the original interrupt.
        """
        try:
            # Attempt to clean GPU memory first
            self._attempt_gpu_cleanup()
        except Exception:
            pass

        try:
            self._terminate_processes_by_name(sigterm_targets)
        except Exception:
            pass

        # Run registered callbacks
        for cb in list(self._callbacks):
            try:
                cb()
            except Exception:
                # Swallow errors during shutdown
                pass


# Global coordinator instance
SHUTDOWN_COORDINATOR = ShutdownCoordinator()

__all__ = ["ShutdownCoordinator", "SHUTDOWN_COORDINATOR"]
