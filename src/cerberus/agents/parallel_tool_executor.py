"""
Parallel Tool Executor - Enables tool execution across multiple agents in parallel.

This module provides a shared tool execution pool that allows multiple agents to submit
tool calls that execute in parallel, breaking the sequential LLM->Tools->LLM bottleneck.
"""

import asyncio
import json
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple, Callable
from dataclasses import dataclass, field
from collections import defaultdict
import weakref
import logging
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .tool import FunctionTool
from .items import ToolCallOutputItem, ItemHelpers
from .agent import Agent
from .run_context import RunContextWrapper

logger = logging.getLogger(__name__)


PARALLEL_TOOL_TIMEOUT_S = 60.0


@dataclass
class PendingToolCall:
    """Represents a tool call waiting to be executed."""
    tool_call_id: str
    tool_name: str
    tool_function: Callable
    arguments: Dict[str, Any]
    raw_arguments: str
    original_arguments: str
    agent_name: str
    context_wrapper: RunContextWrapper
    submitted_at: float = field(default_factory=time.time)
    result: Optional[Any] = None
    error: Optional[Exception] = None
    completed: bool = False
    completion_event: asyncio.Event = field(default_factory=asyncio.Event)


class SubmittedToolCallPayload(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    tool_name: str
    arguments: dict[str, Any]
    raw_arguments: str = Field(min_length=2)
    original_arguments: str = ""
    agent_name: str


class ToolCallMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    tool_name: str
    arguments: dict[str, Any]
    raw_arguments: str
    original_arguments: str = ""


class ParallelToolExecutor:
    """
    Manages parallel tool execution across multiple agents.
    
    This executor allows agents to submit tool calls that execute immediately
    in parallel, rather than waiting for the LLM response cycle to complete.
    """
    
    def __init__(self, max_concurrent_tools: int = 50):
        self.max_concurrent_tools = max_concurrent_tools
        self.pending_calls: Dict[str, PendingToolCall] = {}
        self.active_tasks: List[asyncio.Task] = []
        self.agent_queues: Dict[str, List[str]] = defaultdict(list)  # agent_name -> [tool_call_ids]
        self._lock = asyncio.Lock()
        self._semaphore = asyncio.Semaphore(max_concurrent_tools)
        self._running = True
        self._executor_task: Optional[asyncio.Task] = None
        self._task_sweep_interval = 0.5
        self._next_task_sweep = 0.0

    def _sweep_active_tasks(self, force: bool = False) -> None:
        """Remove completed tasks from the active task registry."""
        now = time.monotonic()
        if not force and now < self._next_task_sweep:
            return

        self.active_tasks = [task for task in self.active_tasks if not task.done()]
        self._next_task_sweep = now + self._task_sweep_interval

    def _register_active_task(self, task: asyncio.Task) -> None:
        """Register a newly created task after pruning completed entries."""
        self._sweep_active_tasks(force=True)
        self.active_tasks.append(task)
        
    async def start(self):
        """Start the background executor task."""
        if self._executor_task is None:
            self._executor_task = asyncio.create_task(self._run_executor())
            logger.debug("Started parallel tool executor")
    
    async def stop(self):
        """Stop the executor and wait for pending tasks."""
        self._running = False
        if self._executor_task:
            self._executor_task.cancel()
            await asyncio.gather(self._executor_task, return_exceptions=True)

        self._sweep_active_tasks(force=True)
        
        # Cancel any remaining tasks
        for task in self.active_tasks:
            if not task.done():
                task.cancel()
        
        if self.active_tasks:
            await asyncio.gather(*self.active_tasks, return_exceptions=True)

    async def mark_tool_call_timeout(self, tool_call_id: str, timeout_error: Exception) -> bool:
        """
        Mark a pending tool call as timed out and remove it from executor queues.

        Returns True when the call existed and was marked/removed.
        """
        async with self._lock:
            call = self.pending_calls.get(tool_call_id)
            if call is None:
                return False

            call.error = timeout_error
            call.result = None
            call.completed = True
            call.completion_event.set()

            self.pending_calls.pop(tool_call_id, None)
            queue = self.agent_queues.get(call.agent_name)
            if queue and tool_call_id in queue:
                queue.remove(tool_call_id)

        return True
    
    async def submit_tool_call(
        self,
        tool_name: str,
        tool_function: Callable,
        arguments: Dict[str, Any],
        agent_name: str,
        context_wrapper: RunContextWrapper,
        tool_call_id: Optional[str] = None
    ) -> str:
        """
        Submit a tool call for parallel execution.
        
        Returns the tool_call_id that can be used to retrieve the result.
        """
        if tool_call_id is None:
            tool_call_id = f"call_{uuid.uuid4().hex[:16]}"
        
        async with self._lock:
            try:
                raw_arguments = json.dumps(arguments, ensure_ascii=True, separators=(",", ":"), default=str)
            except Exception:
                raw_arguments = str(arguments)

            original_arguments = raw_arguments
            if isinstance(arguments, dict):
                candidate_original = arguments.get("original_arguments")
                if not candidate_original:
                    candidate_original = arguments.get("_raw_arguments")
                if candidate_original is not None and str(candidate_original).strip():
                    original_arguments = str(candidate_original)

            try:
                validated_payload = SubmittedToolCallPayload.model_validate(
                    {
                        "tool_name": tool_name,
                        "arguments": arguments,
                        "raw_arguments": raw_arguments,
                        "original_arguments": original_arguments,
                        "agent_name": agent_name,
                    },
                    strict=True,
                )
            except ValidationError as exc:
                logger.error("Rejected malformed parallel tool payload for %s: %s", tool_name, exc)
                raise ValueError("tool_arguments_malformed_json: invalid parallel tool payload") from exc

            pending_call = PendingToolCall(
                tool_call_id=tool_call_id,
                tool_name=validated_payload.tool_name,
                tool_function=tool_function,
                arguments=validated_payload.arguments,
                raw_arguments=validated_payload.raw_arguments,
                original_arguments=validated_payload.original_arguments,
                agent_name=validated_payload.agent_name,
                context_wrapper=context_wrapper
            )
            
            self.pending_calls[tool_call_id] = pending_call
            self.agent_queues[agent_name].append(tool_call_id)
            
        logger.debug(f"Submitted tool call {tool_call_id} for {tool_name} from {agent_name}")
        return tool_call_id
    
    async def get_tool_result(
        self,
        tool_call_id: str,
        timeout: float = PARALLEL_TOOL_TIMEOUT_S,
    ) -> Tuple[Any, Optional[Exception]]:
        """
        Wait for and retrieve the result of a tool call.
        
        Returns (result, error) tuple.
        """
        deadline = time.monotonic() + timeout
        timeout_message = f"Tool call {tool_call_id} timed out after {timeout} seconds"

        while True:
            async with self._lock:
                call = self.pending_calls.get(tool_call_id)
                if call is None:
                    raise RuntimeError(f"Tool call {tool_call_id} is no longer pending")

                if call.completed:
                    self.pending_calls.pop(tool_call_id, None)
                    queue = self.agent_queues.get(call.agent_name)
                    if queue and tool_call_id in queue:
                        queue.remove(tool_call_id)
                    return call.result, call.error

                completion_event = call.completion_event

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timeout_error = asyncio.TimeoutError(timeout_message)
                await self.mark_tool_call_timeout(tool_call_id, timeout_error)
                raise timeout_error

            try:
                await asyncio.wait_for(completion_event.wait(), timeout=remaining)
            except asyncio.TimeoutError as exc:
                timeout_error = asyncio.TimeoutError(timeout_message)
                await self.mark_tool_call_timeout(tool_call_id, timeout_error)
                raise timeout_error from exc

    async def get_tool_call_metadata(self, tool_call_id: str) -> Optional[ToolCallMetadata]:
        """Return tool name, parsed arguments, and raw serialized arguments for a pending tool call."""
        async with self._lock:
            call = self.pending_calls.get(tool_call_id)
            if call is None:
                return None
            return ToolCallMetadata(
                tool_name=call.tool_name,
                arguments=dict(call.arguments),
                raw_arguments=str(call.raw_arguments),
                original_arguments=str(call.original_arguments),
            )
    
    async def get_agent_results(self, agent_name: str) -> List[Tuple[str, Any, Optional[Exception]]]:
        """
        Get all completed results for a specific agent.
        
        Returns list of (tool_call_id, result, error) tuples.
        """
        results = []
        
        async with self._lock:
            tool_call_ids = list(self.agent_queues.get(agent_name, []))
            
            for tool_call_id in tool_call_ids:
                if tool_call_id in self.pending_calls:
                    call = self.pending_calls[tool_call_id]
                    if call.completed:
                        results.append((tool_call_id, call.result, call.error))
                        self.pending_calls.pop(tool_call_id)
                        self.agent_queues[agent_name].remove(tool_call_id)
        
        return results
    
    async def _run_executor(self):
        """Background task that processes pending tool calls."""
        while self._running:
            try:
                self._sweep_active_tasks()

                # Get pending calls that need execution
                async with self._lock:
                    pending = [
                        call for call in self.pending_calls.values()
                        if not call.completed and not any(
                            task for task in self.active_tasks
                            if hasattr(task, '_tool_call_id') and task._tool_call_id == call.tool_call_id
                        )
                    ]
                
                # Execute pending calls
                for call in pending:
                    if len(self.active_tasks) >= self.max_concurrent_tools:
                        self._sweep_active_tasks(force=True)
                        
                        if len(self.active_tasks) >= self.max_concurrent_tools:
                            break
                    
                    # Create execution task
                    task = asyncio.create_task(self._execute_tool_call(call))
                    task._tool_call_id = call.tool_call_id  # type: ignore
                    self._register_active_task(task)
                
                # Brief sleep to avoid busy waiting
                await asyncio.sleep(0.01)

            except asyncio.CancelledError:
                logger.debug("Parallel tool executor task cancelled")
                break
                
            except Exception as e:
                logger.error(f"Error in parallel tool executor: {e}")
                await asyncio.sleep(0.1)
    
    async def _execute_tool_call(self, call: PendingToolCall):
        """Execute a single tool call."""
        async with self._semaphore:
            try:
                logger.debug(f"Executing tool {call.tool_name} (ID: {call.tool_call_id}) for {call.agent_name}")

                parse_error = None
                if not isinstance(call.arguments, dict):
                    parse_error = "tool_arguments_malformed_json: non-object tool arguments"
                else:
                    parse_marker = str(call.arguments.get("_parse_error", "") or "").strip().lower()
                    if parse_marker:
                        parse_error = f"tool_arguments_malformed_json: {parse_marker}"

                if parse_error:
                    raise ValueError(parse_error)
                
                # Execute the tool function
                result = await call.tool_function(call.context_wrapper, call.arguments)
                
                async with self._lock:
                    if call.tool_call_id in self.pending_calls:
                        call.result = result
                        call.completed = True
                        call.completion_event.set()
                        
                logger.debug(f"Completed tool {call.tool_name} (ID: {call.tool_call_id})")
                
            except Exception as e:
                logger.error(f"Error executing tool {call.tool_name}: {e}")
                async with self._lock:
                    if call.tool_call_id in self.pending_calls:
                        call.error = e
                        call.completed = True
                        call.completion_event.set()


# Global instance for shared tool execution
_global_executor: Optional[ParallelToolExecutor] = None


def get_parallel_tool_executor() -> ParallelToolExecutor:
    """Get or create the global parallel tool executor."""
    global _global_executor
    if _global_executor is None:
        _global_executor = ParallelToolExecutor()
    return _global_executor


async def ensure_executor_started():
    """Ensure the global executor is started."""
    executor = get_parallel_tool_executor()
    if executor._executor_task is None:
        await executor.start()


class ParallelToolMixin:
    """
    Mixin for agents to enable parallel tool execution.
    
    This allows agents to submit tool calls that execute immediately
    rather than waiting for the full LLM response cycle.
    """
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._parallel_executor = get_parallel_tool_executor()
        self._pending_parallel_calls: List[str] = []
    
    async def submit_parallel_tool(
        self,
        tool_name: str,
        tool_function: Callable,
        arguments: Dict[str, Any],
        context_wrapper: RunContextWrapper
    ) -> str:
        """Submit a tool for parallel execution."""
        await ensure_executor_started()
        
        tool_call_id = await self._parallel_executor.submit_tool_call(
            tool_name=tool_name,
            tool_function=tool_function,
            arguments=arguments,
            agent_name=getattr(self, 'name', 'unknown'),
            context_wrapper=context_wrapper
        )
        
        self._pending_parallel_calls.append(tool_call_id)
        return tool_call_id
    
    async def _collect_single_parallel_result(self, tool_call_id: str) -> Optional[ToolCallOutputItem]:
        """Collect one tool result with per-call error isolation for swarm-style MCP execution."""
        try:
            metadata = await self._parallel_executor.get_tool_call_metadata(tool_call_id)
            result, error = await self._parallel_executor.get_tool_result(
                tool_call_id,
                timeout=PARALLEL_TOOL_TIMEOUT_S,
            )

            if error:
                error_text = str(error)
                if "tool_arguments_malformed_json" in error_text.lower():
                    tool_name = metadata.tool_name if metadata else "parallel_tool"
                    raw_args = metadata.original_arguments if metadata else ""
                    output = {
                        "ok": False,
                        "error": "tool_arguments_malformed_json",
                        "tool": tool_name,
                        "message": (
                            "Malformed JSON detected in tool arguments. "
                            "Retry with a valid JSON object that satisfies the tool schema."
                        ),
                        "malformed_json": True,
                        "raw_input_preview": str(raw_args or "")[:800],
                    }
                else:
                    output = f"Error: {error_text}"
            else:
                output = result

            tool_name = metadata.tool_name if metadata else "parallel_tool"
            tool_arguments = metadata.arguments if metadata else None
            serialized_arguments = (
                metadata.original_arguments if metadata and metadata.original_arguments else (metadata.raw_arguments if metadata else "")
            )

            from openai.types.responses import ResponseFunctionToolCall

            mock_tool_call = ResponseFunctionToolCall(
                id=tool_call_id,
                call_id=tool_call_id[:40],
                type="function_call",
                name=tool_name,
                arguments=serialized_arguments,
            )

            raw_item = ItemHelpers.tool_call_output_item(mock_tool_call, output)
            raw_item["name"] = tool_name
            if serialized_arguments:
                raw_item["arguments"] = serialized_arguments
                raw_item["original_arguments"] = serialized_arguments
            if tool_arguments is not None:
                raw_item["parsed_arguments"] = tool_arguments

            return ToolCallOutputItem(
                output=output,
                raw_item=raw_item,
                agent=self,  # type: ignore
            )

        except asyncio.TimeoutError:
            logger.warning(
                "Parallel tool call %s timed out during result collection; marked failed and removed from pending queue",
                tool_call_id,
            )
            return None
        except Exception as e:
            logger.error("Error collecting parallel result for %s: %s", tool_call_id, e)
            return None
        finally:
            if tool_call_id in self._pending_parallel_calls:
                self._pending_parallel_calls.remove(tool_call_id)

    async def collect_parallel_results(self) -> List[ToolCallOutputItem]:
        """Collect results from parallel tool executions using concurrent gather and isolated failures."""
        pending_ids = self._pending_parallel_calls[:]
        if not pending_ids:
            return []

        collected = await asyncio.gather(
            *(self._collect_single_parallel_result(tool_call_id) for tool_call_id in pending_ids),
            return_exceptions=False,
        )
        return [item for item in collected if item is not None]