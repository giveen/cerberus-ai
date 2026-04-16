from __future__ import annotations

import queue
import threading
import time
from typing import Any

from cerberus.internal.debug_logger import get_debug_logger

from ..logger import logger
from .processor_interface import TracingExporter, TracingProcessor
from .spans import Span
from .traces import Trace


class ConsoleSpanExporter(TracingExporter):
    """Prints the traces and spans to the console."""

    def export(self, items: list[Trace | Span[Any]]) -> None:
        for item in items:
            if isinstance(item, Trace):
                print(f"[Exporter] Export trace_id={item.trace_id}, name={item.name}, ")
            else:
                print(f"[Exporter] Export span: {item.export()}")


class WorkspaceSpanExporter(TracingExporter):
    def __init__(
        self,
        *,
        channel: str = "trace",
    ):
        self._channel = channel
        self._logger = get_debug_logger()

    def set_api_key(self, api_key: str):
        """Compatibility shim retained for legacy callers.

        This exporter never performs remote IO and ignores API keys.
        """
        _ = api_key

    def export(self, items: list[Trace | Span[Any]]) -> None:
        if not items:
            return
        exported_items = [item.export() for item in items if item.export()]
        self._logger.write(
            channel=self._channel,
            message="trace_batch",
            payload={
                "count": len(exported_items),
                "items": exported_items,
            },
        )
        logger.debug("Exported %d trace item(s) to local debug log", len(exported_items))

    def close(self):
        """No-op close hook for interface compatibility."""
        return


class BatchTraceProcessor(TracingProcessor):
    """Some implementation notes:
    1. Using Queue, which is thread-safe.
    2. Using a background thread to export spans, to minimize any performance issues.
    3. Spans are stored in memory until they are exported.
    """

    def __init__(
        self,
        exporter: TracingExporter,
        max_queue_size: int = 8192,
        max_batch_size: int = 128,
        schedule_delay: float = 5.0,
        export_trigger_ratio: float = 0.7,
    ):
        """
        Args:
            exporter: The exporter to use.
            max_queue_size: The maximum number of spans to store in the queue. After this, we will
                start dropping spans.
            max_batch_size: The maximum number of spans to export in a single batch.
            schedule_delay: The delay between checks for new spans to export.
            export_trigger_ratio: The ratio of the queue size at which we will trigger an export.
        """
        self._exporter = exporter
        self._queue: queue.Queue[Trace | Span[Any]] = queue.Queue(maxsize=max_queue_size)
        self._max_queue_size = max_queue_size
        self._max_batch_size = max_batch_size
        self._schedule_delay = schedule_delay
        self._shutdown_event = threading.Event()

        # The queue size threshold at which we export immediately.
        self._export_trigger_size = int(max_queue_size * export_trigger_ratio)

        # Track when we next *must* perform a scheduled export
        self._next_export_time = time.time() + self._schedule_delay

        self._shutdown_event = threading.Event()
        self._worker_thread = threading.Thread(target=self._run, daemon=True)
        self._worker_thread.start()

    def on_trace_start(self, trace: Trace) -> None:
        try:
            self._queue.put_nowait(trace)
        except queue.Full:
            logger.warning("Queue is full, dropping trace.")

    def on_trace_end(self, trace: Trace) -> None:
        # We send traces via on_trace_start, so we don't need to do anything here.
        pass

    def on_span_start(self, span: Span[Any]) -> None:
        # We send spans via on_span_end, so we don't need to do anything here.
        pass

    def on_span_end(self, span: Span[Any]) -> None:
        try:
            self._queue.put_nowait(span)
        except queue.Full:
            logger.warning("Queue is full, dropping span.")

    def shutdown(self, timeout: float | None = None):
        """
        Called when the application stops. We signal our thread to stop, then join it.
        """
        self._shutdown_event.set()
        self._worker_thread.join(timeout=timeout)

    def force_flush(self):
        """
        Forces an immediate flush of all queued spans.
        """
        self._export_batches(force=True)

    def _run(self):
        while not self._shutdown_event.is_set():
            current_time = time.time()
            queue_size = self._queue.qsize()

            # If it's time for a scheduled flush or queue is above the trigger threshold
            if current_time >= self._next_export_time or queue_size >= self._export_trigger_size:
                self._export_batches(force=False)
                # Reset the next scheduled flush time
                self._next_export_time = time.time() + self._schedule_delay
            else:
                # Sleep a short interval so we don't busy-wait.
                time.sleep(0.2)

        # Final drain after shutdown
        self._export_batches(force=True)

    def _export_batches(self, force: bool = False):
        """Drains the queue and exports in batches. If force=True, export everything.
        Otherwise, export up to `max_batch_size` repeatedly until the queue is empty or below a
        certain threshold.
        """
        while True:
            items_to_export: list[Span[Any] | Trace] = []

            # Gather a batch of spans up to max_batch_size
            while not self._queue.empty() and (
                force or len(items_to_export) < self._max_batch_size
            ):
                try:
                    items_to_export.append(self._queue.get_nowait())
                except queue.Empty:
                    # Another thread might have emptied the queue between checks
                    break

            # If we collected nothing, we're done
            if not items_to_export:
                break

            # Export the batch
            self._exporter.export(items_to_export)


# Create a shared global instance:
_global_exporter = WorkspaceSpanExporter()
_global_processor = BatchTraceProcessor(_global_exporter)


def default_exporter() -> WorkspaceSpanExporter:
    """The default exporter, which exports traces and spans to the backend in batches."""
    return _global_exporter


def default_processor() -> BatchTraceProcessor:
    """The default processor, which exports traces and spans to the backend in batches."""
    return _global_processor
