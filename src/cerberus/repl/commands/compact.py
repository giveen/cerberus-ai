"""REPL compact command — Context Distillation Engine.

Provides two lossless-critical compression modes for long agent conversations:

  summary  — async LLM call produces a "Current Progress / Pending Tasks"
             bullet summary; critical indicators are always preserved.
  buffer   — keep the last N turns verbatim; archive the rest via the memory
             system; critical indicators are injected as a Permanent Context
             block at position 0.

Registration::

    from cerberus.repl.commands.compact import COMPACT_COMMAND_INSTANCE

Usage::

    /compact                            # summary mode, interactive confirm
    /compact --mode summary --hard      # summary, no prompt
    /compact --mode buffer --turns 20   # keep last 20 turns
    /compact --model gpt-4o-mini        # one-shot model override
    /compact status                     # show settings
    /compact model gpt-4o-mini          # persist model
    /compact prompt "Focus on CVEs"     # persist prompt
"""

from __future__ import annotations

import datetime
import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from cerberus.repl.commands.base import (
    Command,
    CommandError,
    ValidationError,
    register_command,
)

console = Console()

# ---------------------------------------------------------------------------
# constants
# ---------------------------------------------------------------------------

_DEFAULT_SUMMARY_PROMPT = (
    "You are a precise conversation summarizer for a security-engineering assistant. "
    "Produce a concise Markdown summary with these sections:\n"
    "## Current Progress\n"
    "- Bullet list of completed steps and key findings.\n"
    "## Pending Tasks\n"
    "- Bullet list of open tasks and next actions.\n"
    "## Critical Findings\n"
    "- IPs, hostnames, CVEs, credentials, ports (preserve verbatim).\n"
    "Be terse; omit filler."
)

_CRITICAL_PATTERNS: List[Tuple[str, str]] = [
    # (label, regex)
    ("ip",         r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    ("cve",        r"\bCVE-\d{4}-\d{4,7}\b"),
    ("port",       r"\bport[s]?\s*:?\s*\d{1,5}\b"),
    ("credential", r"(?i)(?:password|passwd|secret|token|api[_\-]?key)\s*[:=]\s*\S+"),
    ("hash",       r"\b[0-9a-fA-F]{32,64}\b"),
]

_BUFFER_DEFAULT_TURNS = 20


# ---------------------------------------------------------------------------
# helper — token proxy
# ---------------------------------------------------------------------------

def _estimate_tokens(text: str) -> int:
    """Estimate token count.  Uses tiktoken when available, else char/4."""
    try:
        import tiktoken  # type: ignore[import-untyped]
        enc = tiktoken.get_encoding("cl100k_base")
        return len(enc.encode(text))
    except Exception:
        return max(1, len(text) // 4)


# ---------------------------------------------------------------------------
# helper — message text extraction
# ---------------------------------------------------------------------------

def _msg_text(msg: Any) -> str:
    """Return the string content of a message dict or object."""
    if isinstance(msg, dict):
        content = msg.get("content", "")
    else:
        content = getattr(msg, "content", "")
    if isinstance(content, list):
        # OpenAI multi-part content blocks
        return " ".join(
            p.get("text", "") if isinstance(p, dict) else getattr(p, "text", "")
            for p in content
        )
    return str(content or "")


# ---------------------------------------------------------------------------
# CompactCommand
# ---------------------------------------------------------------------------

class CompactCommand(Command):
    """Context Distillation Engine — compresses agent conversation history."""

    name = "/compact"
    description = "Compress conversation history (summary or buffer mode)"
    aliases = ["/cmp", "compact", "cmp", "/ctx", "ctx", "/compress", "compress"]

    def __init__(self) -> None:
        super().__init__(name=self.name, description=self.description, aliases=self.aliases)
        # Persist across invocations
        self.compact_model: Optional[str] = None
        self.custom_prompt: Optional[str] = None
        self.cached_model_numbers: Dict[str, str] = {}
        self._cached_model_numbers = self.cached_model_numbers

        # Register sub-commands with the legacy Command surface.
        self.add_subcommand("model", "Set/show model used for compaction", self.handle_model)
        self.add_subcommand("prompt", "Set/show custom summarisation prompt", self.handle_prompt)
        self.add_subcommand("status", "Show current compaction settings", self.handle_status)

    def handle(self, args: Optional[List[str]] = None) -> bool:  # type: ignore[override]
        try:
            clean = self.sanitize_args(args)
        except ValidationError as exc:
            console.print(f"[red]Input validation failed: {exc}[/red]")
            return False

        record = self._audit_before(clean)
        try:
            if not clean:
                result = self._perform_compaction(None, None)
            else:
                sub = clean[0].lower()
                registered = self.subcommands.get(sub)
                if registered and callable(registered.get("handler")):
                    result = bool(registered["handler"](clean[1:] or None))
                elif sub == "st":
                    result = self.handle_status(clean[1:] or None)
                else:
                    legacy_overrides = self._parse_legacy_overrides(clean)
                    if legacy_overrides is not None:
                        model_override, prompt_override = legacy_overrides
                        result = self._perform_compaction(model_override, prompt_override)
                    else:
                        result = self._run_execute(clean)
        except CommandError as exc:
            self._audit_after(record, success=False, error=str(exc))
            console.print(f"[red]{self.name}: {exc}[/red]")
            return False
        except Exception as exc:  # pylint: disable=broad-except
            self._audit_after(record, success=False, error=repr(exc))
            console.print(f"[red]{self.name}: unexpected error — {exc}[/red]")
            return False

        self._audit_after(record, success=bool(result))
        return bool(result)

    def _parse_legacy_overrides(self, args: List[str]) -> Optional[Tuple[Optional[str], Optional[str]]]:
        model_override: Optional[str] = None
        prompt_override: Optional[str] = None
        index = 0

        while index < len(args):
            token = args[index]
            if token == "--model" and index + 1 < len(args):
                model_override = args[index + 1]
                index += 2
                continue
            if token == "--prompt" and index + 1 < len(args):
                prompt_override = " ".join(args[index + 1:])
                return model_override, prompt_override
            return None

        return model_override, prompt_override

    def _perform_compaction(
        self,
        model_override: Optional[str] = None,
        prompt_override: Optional[str] = None,
    ) -> bool:
        args: List[str] = []
        if model_override is not None:
            args.extend(["--model", model_override])
        if prompt_override is not None:
            args.extend(["--prompt", prompt_override])
        return self._run_execute(args)

    def handle_model(self, args: Optional[List[str]] = None) -> bool:
        return self._sub_model(args)

    def handle_prompt(self, args: Optional[List[str]] = None) -> bool:
        return self._sub_prompt(args)

    def handle_status(self, args: Optional[List[str]] = None) -> bool:
        return self._sub_status(args)

    # ------------------------------------------------------------------ #
    # Mandatory contract                                                   #
    # ------------------------------------------------------------------ #

    @property
    def help(self) -> str:
        return (
            "Usage: /compact [--mode summary|buffer] [--turns N] [--model M]\n"
            "               [--prompt TEXT] [--hard] [--no-checkpoint]\n"
            "       /compact model [<name>|default]\n"
            "       /compact prompt [<text>|reset]\n"
            "       /compact status\n\n"
            "Modes:\n"
            "  summary  (default) — LLM produces a bullet summary; history replaced.\n"
            "  buffer             — keep last N turns; older turns archived to memory.\n\n"
            "Critical Indicators (IPs, CVEs, credentials, ports) are always preserved\n"
            "in a Permanent Context block and never discarded.\n\n"
            "WARNING: compaction is irreversible without the checkpoint file.\n"
            "         Checkpoints are written to the workspace directory."
        )

    async def execute(self, args: List[str]) -> bool:
        """Dispatch sub-commands or trigger compaction."""
        if not args:
            return await self._do_compact_interactive([])

        sub = args[0].lstrip("-").lower()

        if sub == "model":
            return self.handle_model(args[1:])
        if sub == "prompt":
            return self.handle_prompt(args[1:])
        if sub in ("status", "st"):
            return self.handle_status([])

        # Flag-style invocation: /compact --mode summary ...
        return await self._do_compact_interactive(args)

    # ------------------------------------------------------------------ #
    # Sub-command handlers                                                 #
    # ------------------------------------------------------------------ #

    def _sub_model(self, args: Optional[List[str]] = None) -> bool:
        """Set or list available models for compaction."""
        args = args or []
        if not args:
            self._show_model_table()
            return True

        model_arg = args[0]
        if model_arg.isdigit() and self.cached_model_numbers:
            model_name = self.cached_model_numbers.get(model_arg)
            if not model_name:
                console.print(f"[red]Invalid model number: {model_arg}[/red]")
                return True
        else:
            model_name = model_arg

        if model_name.lower() == "default":
            self.compact_model = None
            console.print("[green]Compaction model reset to current agent model[/green]")
        else:
            self.compact_model = model_name
            console.print(f"[green]Compaction model → {model_name}[/green]")
        return True

    def _sub_prompt(self, args: Optional[List[str]] = None) -> bool:
        """Set or show custom summarisation prompt."""
        args = args or []
        if not args:
            if self.custom_prompt:
                console.print(Panel(self.custom_prompt, title="Custom prompt", border_style="cyan"))
            else:
                console.print("[yellow]No custom prompt set; using default.[/yellow]")
            return True

        if args[0].lower() == "reset":
            self.custom_prompt = None
            console.print("[green]Custom prompt cleared; default will be used.[/green]")
        else:
            self.custom_prompt = " ".join(args)
            console.print(f"[green]Custom prompt set ({len(self.custom_prompt)} chars)[/green]")
        return True

    def _sub_status(self, _args: Optional[List[str]] = None) -> bool:
        """Print compaction settings."""
        from cerberus.sdk.agents.models.openai_chatcompletions import (  # type: ignore[import-untyped]
            get_current_active_model,
        )

        console.print("[bold cyan]Compaction Settings[/bold cyan]\n")
        current = get_current_active_model()
        console.print(f"  Compact model : {self.compact_model or '(use current agent model)'}")
        if current:
            console.print(f"  Current model : {current.model}")
        console.print(f"  Custom prompt : {'set' if self.custom_prompt else 'not set (default)'}")
        console.print(f"  Default turns : {_BUFFER_DEFAULT_TURNS} (buffer mode)")
        return True

    # ------------------------------------------------------------------ #
    # Core compaction flow                                                 #
    # ------------------------------------------------------------------ #

    async def _do_compact_interactive(self, args: List[str]) -> bool:
        """Parse flags, maybe ask for confirmation, then compact."""
        # --- parse flags ---------------------------------------------------
        mode = "summary"
        turns = _BUFFER_DEFAULT_TURNS
        model_override: Optional[str] = None
        prompt_override: Optional[str] = None
        hard = False
        checkpoint = True

        i = 0
        while i < len(args):
            tok = args[i].lstrip("-").lower()
            if tok == "mode" and i + 1 < len(args):
                mode = args[i + 1].lower(); i += 2
            elif tok == "turns" and i + 1 < len(args):
                try:
                    turns = int(args[i + 1]); i += 2
                except ValueError:
                    turns = _BUFFER_DEFAULT_TURNS; i += 2
            elif tok == "model" and i + 1 < len(args):
                model_override = args[i + 1]; i += 2
            elif tok == "prompt" and i + 1 < len(args):
                prompt_override = args[i + 1]; i += 2
            elif tok == "hard":
                hard = True; i += 1
            elif tok in ("no-checkpoint", "nocheckpoint"):
                checkpoint = False; i += 1
            else:
                i += 1

        if mode not in ("summary", "buffer"):
            console.print(f"[red]Unknown mode '{mode}'; choose 'summary' or 'buffer'.[/red]")
            return False

        # --- resolve agent + history ---------------------------------------
        agent_name, history = self._resolve_agent_history()
        if not history:
            console.print("[yellow]No conversation history to compact.[/yellow]")
            return True

        msg_count = len(history)
        tokens_before = sum(_estimate_tokens(_msg_text(m)) for m in history)

        # --- interactive confirm (unless --hard) ---------------------------
        if not hard:
            console.print(
                f"\n[cyan]Compact {msg_count} messages (~{tokens_before:,} tokens) "
                f"for agent [bold]{agent_name}[/bold] using mode=[bold]{mode}[/bold]?[/cyan]"
            )
            try:
                answer = console.input("[cyan]Proceed? (y/N): [/cyan]")
            except (EOFError, KeyboardInterrupt):
                console.print("[dim]Cancelled.[/dim]")
                return True
            if answer.strip().lower() != "y":
                console.print("[dim]Compaction cancelled.[/dim]")
                return True

        return await self._compact(
            agent_name=agent_name,
            history=history,
            mode=mode,
            turns=turns,
            model_override=model_override or self.compact_model,
            prompt_override=prompt_override or self.custom_prompt,
            write_checkpoint=checkpoint,
            tokens_before=tokens_before,
        )

    async def _compact(
        self,
        *,
        agent_name: str,
        history: List[Any],
        mode: str,
        turns: int,
        model_override: Optional[str],
        prompt_override: Optional[str],
        write_checkpoint: bool,
        tokens_before: int,
    ) -> bool:
        """Perform the actual compaction and post-hoc history replacement."""
        indicators = self._extract_critical_indicators(history)

        if mode == "summary":
            new_history = await self._compress_summary(
                history, agent_name, model_override, prompt_override, indicators
            )
        else:  # buffer
            new_history = self._compress_buffer(
                history, turns, indicators
            )

        tokens_after = sum(_estimate_tokens(_msg_text(m)) for m in new_history)
        saved = max(0, tokens_before - tokens_after)

        if write_checkpoint:
            self._write_checkpoint(agent_name, history, new_history)

        # Replace history in-place
        self._apply_history(agent_name, new_history)

        # Reset context-usage env var so the TUI gauge refreshes
        os.environ["CERBERUS_CONTEXT_USAGE"] = "0.0"

        console.print(
            f"\n[green]✓ Compaction complete[/green]  "
            f"({tokens_before:,} → {tokens_after:,} tokens, saved ~{saved:,})"
        )
        if indicators:
            console.print(
                f"[dim]  Preserved {len(indicators)} critical indicator(s) in Permanent Context block.[/dim]"
            )
        return True

    # ------------------------------------------------------------------ #
    # Compression strategies                                               #
    # ------------------------------------------------------------------ #

    async def _compress_summary(
        self,
        history: List[Any],
        agent_name: str,
        model_override: Optional[str],
        prompt_override: Optional[str],
        indicators: List[str],
    ) -> List[Any]:
        """Call an LLM to produce a compact bullet summary."""
        try:
            from cerberus.sdk.agents.models.openai_chatcompletions import (  # type: ignore[import-untyped]
                get_current_active_model,
            )

            # Build the conversation text block
            conv_text = "\n\n".join(
                f"[{_role(m)}] {_msg_text(m)}" for m in history
            )
            summary_prompt = prompt_override or _DEFAULT_SUMMARY_PROMPT

            summarizer_model = model_override
            if not summarizer_model:
                active = get_current_active_model()
                summarizer_model = active.model if active else "gpt-4o-mini"

            console.print(f"[dim]Summarising via {summarizer_model}…[/dim]")

            import openai  # type: ignore[import-untyped]
            client = openai.AsyncOpenAI()
            resp = await client.chat.completions.create(
                model=summarizer_model,
                messages=[
                    {"role": "system", "content": summary_prompt},
                    {"role": "user",   "content": conv_text},
                ],
                temperature=0.2,
                max_tokens=2048,
            )
            summary_text = resp.choices[0].message.content or ""

        except Exception as exc:  # pylint: disable=broad-except
            console.print(f"[yellow]LLM summary failed ({exc}); falling back to keyword extraction.[/yellow]")
            summary_text = self._fallback_summary(history)

        # Build replacement history: system → permanent-context → summary
        return self._build_replacement_history(history, summary_text, indicators)

    def _compress_buffer(
        self,
        history: List[Any],
        turns: int,
        indicators: List[str],
    ) -> List[Any]:
        """Keep last *turns* messages; archive the rest via memory system."""
        system_msgs: List[Any] = [m for m in history if _role(m) == "system"]
        non_system: List[Any] = [m for m in history if _role(m) != "system"]

        keep = non_system[-turns:] if len(non_system) > turns else non_system
        archived = non_system[:-turns] if len(non_system) > turns else []

        # Best-effort: archive older turns to memory
        if archived:
            self._archive_to_memory(archived)

        perm_block = self._permanent_context_block(indicators)
        result: List[Any] = []
        if system_msgs:
            result.extend(system_msgs)
        if perm_block:
            result.append({"role": "system", "content": perm_block})
        result.extend(keep)
        return result

    # ------------------------------------------------------------------ #
    # Critical Indicators                                                  #
    # ------------------------------------------------------------------ #

    def _extract_critical_indicators(self, history: List[Any]) -> List[str]:
        """Scan conversation text for IPs, CVEs, credentials, hashes, ports."""
        full_text = "\n".join(_msg_text(m) for m in history)
        found: List[str] = []
        for label, pattern in _CRITICAL_PATTERNS:
            hits = re.findall(pattern, full_text)
            for hit in set(hits):
                found.append(f"[{label}] {hit}")
        # Deduplicate preserving first-seen order
        seen: set = set()
        unique: List[str] = []
        for item in found:
            if item not in seen:
                seen.add(item)
                unique.append(item)
        return unique

    def _permanent_context_block(self, indicators: List[str]) -> str:
        if not indicators:
            return ""
        lines = "\n".join(f"  - {ind}" for ind in indicators)
        return (
            "## Permanent Context (DO NOT DISCARD)\n"
            "The following critical indicators were extracted from prior conversation "
            "and must never be deleted:\n"
            + lines
        )

    # ------------------------------------------------------------------ #
    # History utilities                                                    #
    # ------------------------------------------------------------------ #

    def _resolve_agent_history(self) -> Tuple[str, List[Any]]:
        """Return (agent_name, message_list) for the best available agent."""
        from cerberus.sdk.agents.simple_agent_manager import AGENT_MANAGER  # type: ignore[import-untyped]
        from cerberus.sdk.agents.models.openai_chatcompletions import (  # type: ignore[import-untyped]
            get_agent_message_history,
            get_all_agent_histories,
        )

        # 1. active agent
        active = AGENT_MANAGER.get_active_agent()
        if active:
            name = getattr(active, "name", None)
            if name:
                hist = get_agent_message_history(name)
                if hist:
                    return name, list(hist)

        # 2. any history with messages
        for name, hist in get_all_agent_histories().items():
            if hist:
                return name, list(hist)

        # 3. registered agents
        registered = AGENT_MANAGER.get_registered_agents()
        if registered:
            name = next(iter(registered))
            hist = get_agent_message_history(name)
            return name, list(hist) if hist else []

        # 4. env default
        agent_type = os.getenv("CERBERUS_AGENT_TYPE", "one_tool_agent")
        try:
            from cerberus.agents import get_available_agents  # type: ignore[import-untyped]
            agents = get_available_agents()
            if agent_type in agents:
                agent = agents[agent_type]
                name = getattr(agent, "name", agent_type)
                hist = get_agent_message_history(name)
                return name, list(hist) if hist else []
        except Exception:
            pass

        return "unknown", []

    def _apply_history(self, agent_name: str, new_history: List[Any]) -> None:
        """Replace the live agent history with *new_history*."""
        try:
            from cerberus.sdk.agents.simple_agent_manager import AGENT_MANAGER  # type: ignore[import-untyped]
            from cerberus.sdk.agents.models.openai_chatcompletions import (  # type: ignore[import-untyped]
                PERSISTENT_MESSAGE_HISTORIES,
            )

            AGENT_MANAGER.clear_history(agent_name)

            hist_ref = PERSISTENT_MESSAGE_HISTORIES.get(agent_name)
            if hist_ref is not None:
                hist_ref.clear()
                hist_ref.extend(new_history)

            active = AGENT_MANAGER.get_active_agent()
            if active and hasattr(active, "model") and hasattr(active.model, "message_history"):
                active.model.message_history.clear()
                active.model.message_history.extend(new_history)

        except Exception as exc:  # pylint: disable=broad-except
            console.print(f"[yellow]History replacement partial: {exc}[/yellow]")

    def _build_replacement_history(
        self,
        original: List[Any],
        summary_text: str,
        indicators: List[str],
    ) -> List[Any]:
        """Assemble the compact replacement history."""
        system_msgs = [m for m in original if _role(m) == "system"]
        result: List[Any] = list(system_msgs)

        perm = self._permanent_context_block(indicators)
        if perm:
            result.append({"role": "system", "content": perm})

        result.append({
            "role": "assistant",
            "content": (
                "## Compacted Conversation Summary\n\n"
                + summary_text
            ),
        })
        return result

    def _fallback_summary(self, history: List[Any]) -> str:
        """Keyword-extraction summary when LLM is unavailable."""
        lines: List[str] = []
        for msg in history[-20:]:
            text = _msg_text(msg)
            if text.strip():
                truncated = text[:200].replace("\n", " ")
                lines.append(f"- [{_role(msg)}] {truncated}…")
        return "## Conversation Excerpt (fallback summary)\n" + "\n".join(lines)

    def _archive_to_memory(self, archived: List[Any]) -> None:
        """Best-effort: save archived turns to the memory system."""
        try:
            from cerberus.repl.commands.memory import MEMORY_COMMAND_INSTANCE  # type: ignore[import-untyped]
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            name = f"compact_archive_{ts}"
            MEMORY_COMMAND_INSTANCE.handle_save([name], preserve_history=True)
        except Exception:
            pass  # archival is best-effort; do not disrupt the main flow

    # ------------------------------------------------------------------ #
    # Engagement Checkpoint                                                #
    # ------------------------------------------------------------------ #

    def _write_checkpoint(
        self,
        agent_name: str,
        original: List[Any],
        compacted: List[Any],
    ) -> None:
        """Write a timestamped checkpoint JSON to the workspace directory."""
        workspace_dir: Optional[str] = None

        # Try session workspace
        if self._session and self._session.workspace:
            ws = self._session.workspace
            workspace_dir = str(ws) if isinstance(ws, str) else getattr(ws, "path", None)

        if not workspace_dir:
            workspace_dir = os.getcwd()

        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name = re.sub(r"[^\w\-]", "_", agent_name)
        filename = os.path.join(workspace_dir, f"compact_checkpoint_{safe_name}_{ts}.json")

        try:
            payload: Dict[str, Any] = {
                "agent": agent_name,
                "timestamp": ts,
                "original_message_count": len(original),
                "compacted_message_count": len(compacted),
                "tokens_before": sum(_estimate_tokens(_msg_text(m)) for m in original),
                "tokens_after":  sum(_estimate_tokens(_msg_text(m)) for m in compacted),
                "original_history": [_serialise_msg(m) for m in original],
            }
            with open(filename, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2, ensure_ascii=False)
            console.print(f"[dim]Checkpoint saved → {filename}[/dim]")
        except OSError as exc:
            console.print(f"[yellow]Could not write checkpoint: {exc}[/yellow]")

    # ------------------------------------------------------------------ #
    # Model table (sub-command helper)                                     #
    # ------------------------------------------------------------------ #

    def _show_model_table(self) -> None:
        from cerberus.sdk.agents.models.openai_chatcompletions import (  # type: ignore[import-untyped]
            get_current_active_model,
        )
        try:
            from cerberus.tools.common.get_models import (  # type: ignore[import-untyped]
                get_predefined_model_categories,
                get_all_predefined_models,
            )
            ALL_MODELS = get_all_predefined_models()
        except Exception:
            ALL_MODELS = []

        current = get_current_active_model()
        info = self.compact_model or (current.model if current else "default")
        console.print(Panel(
            f"[bold cyan]Context Distillation Engine[/bold cyan]\n\n"
            f"Compaction model : [green]{info}[/green]\n"
            f"Custom prompt    : [green]{'set' if self.custom_prompt else 'using default'}[/green]",
            title="[bold yellow]Compact settings[/bold yellow]",
            border_style="cyan",
        ))

        if ALL_MODELS:
            tbl = Table(title="Available Models", show_header=True, header_style="bold magenta")
            for col in ("#", "Name", "Provider", "Category", "In $/1M", "Out $/1M", "Description"):
                tbl.add_column(col, overflow="fold")
            for idx, m in enumerate(ALL_MODELS, 1):
                in_cost  = f"${m['input_cost']:.2f}"  if m.get("input_cost")  is not None else "—"
                out_cost = f"${m['output_cost']:.2f}" if m.get("output_cost") is not None else "—"
                tbl.add_row(str(idx), m["name"], m["provider"],
                            m["category"], in_cost, out_cost, m["description"])
            console.print(tbl)
            self.cached_model_numbers = {str(i): m["name"] for i, m in enumerate(ALL_MODELS, 1)}
            self._cached_model_numbers = self.cached_model_numbers

        console.print("\n[cyan]Usage:[/cyan]  [bold]/compact model <name|number>[/bold]  or  [bold]/compact model default[/bold]")


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _role(msg: Any) -> str:
    if isinstance(msg, dict):
        return msg.get("role", "user")
    return getattr(msg, "role", "user")


def _serialise_msg(msg: Any) -> Dict[str, Any]:
    if isinstance(msg, dict):
        return msg
    return {"role": _role(msg), "content": _msg_text(msg)}


# ---------------------------------------------------------------------------
# Module globals (backward compat)
# ---------------------------------------------------------------------------

COMPACT_COMMAND_INSTANCE = CompactCommand()
register_command(COMPACT_COMMAND_INSTANCE)


def get_compact_model() -> Optional[str]:
    """Return the configured compaction model (None = use current agent model)."""
    return COMPACT_COMMAND_INSTANCE.compact_model


def get_custom_prompt() -> Optional[str]:
    """Return the custom summarisation prompt (None = use default)."""
    return COMPACT_COMMAND_INSTANCE.custom_prompt
