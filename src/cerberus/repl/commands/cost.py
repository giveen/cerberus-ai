"""Cost tracking and billing command for the Cerebro framework.

Public surface:
  - ``PriceTable``   — thread-safe registry mapping model names to per-token
                       rates (input, output) expressed as ``Decimal``.
  - ``UsageRecord``  — Pydantic v2 model describing a single charged API call.
  - ``UsageTracker`` — thread-safe in-process ledger; call ``record_usage()``
                       from model-layer hooks; query from the REPL command.
  - ``BudgetPolicy`` — Pydantic v2 model governing soft-lock threshold and
                       currency conversion.
  - ``CostCommand``  — ``FrameworkCommand`` subclass; sub-commands:
                       ``show``, ``agents``, ``models``, ``budget``,
                       ``export``, ``reset``.
  - ``USAGE_TRACKER`` — process-global ``UsageTracker`` singleton.
  - ``record_usage()`` — convenience helper for model-layer hooks.
"""

from __future__ import annotations

import csv
import json
import os
import shutil
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import ROUND_HALF_UP, Decimal
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, field_validator
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from cerberus.repl.commands.base import Command, CommandError, register_command
from cerberus.agents.global_usage_tracker import GLOBAL_USAGE_TRACKER
from cerberus.util import COST_TRACKER

__all__ = [
    "PriceTable",
    "UsageRecord",
    "UsageTracker",
    "BudgetPolicy",
    "CostCommand",
    "COST_TRACKER",
    "GLOBAL_USAGE_TRACKER",
    "USAGE_TRACKER",
    "record_usage",
]

console = Console()

# ---------------------------------------------------------------------------
# Decimal helpers
# ---------------------------------------------------------------------------

_QUANT = Decimal("0.0000000001")  # 10-dp internal precision


def _d(value: Any) -> Decimal:
    """Coerce *value* to ``Decimal``; return ``Decimal('0')`` on failure."""
    try:
        return Decimal(str(value)).quantize(_QUANT, rounding=ROUND_HALF_UP)
    except Exception:
        return Decimal("0")


def _fmt(value: Decimal, symbol: str = "$", dp: int = 6) -> str:
    """Format a ``Decimal`` as a human-readable currency string."""
    rounded = value.quantize(Decimal("0." + "0" * dp), rounding=ROUND_HALF_UP)
    return f"{symbol}{rounded}"


# ---------------------------------------------------------------------------
# Built-in price catalogue  (per *token*, not per thousand)
# Values are intentionally conservative and should be updated via
# ``PriceTable.update()`` or the ``pricing.json`` project file.
# ---------------------------------------------------------------------------

_BUILTIN_RATES: Dict[str, Tuple[str, str]] = {
    # (input_per_token, output_per_token)
    # OpenAI
    "gpt-4o":                      ("0.0000025", "0.00001"),
    "gpt-4o-mini":                 ("0.00000015", "0.0000006"),
    "gpt-4-turbo":                 ("0.00001",   "0.00003"),
    "gpt-4":                       ("0.00003",   "0.00006"),
    "gpt-3.5-turbo":               ("0.0000005", "0.0000015"),
    "o1":                          ("0.000015",  "0.00006"),
    "o1-mini":                     ("0.000003",  "0.000012"),
    "o3-mini":                     ("0.0000011", "0.0000044"),
    "o4-mini":                     ("0.0000011", "0.0000044"),
    # Anthropic
    "claude-3-5-sonnet-20241022":  ("0.000003",  "0.000015"),
    "claude-3-5-haiku-20241022":   ("0.0000008", "0.000004"),
    "claude-opus-4-5":             ("0.000015",  "0.000075"),
    "claude-sonnet-4-5":           ("0.000003",  "0.000015"),
    "claude-haiku-4-5":            ("0.0000008", "0.000004"),
    # Mistral / open-weight (estimate)
    "mistral-large-latest":        ("0.000002",  "0.000006"),
    "mistral-small-latest":        ("0.0000002", "0.0000006"),
    # Local / free
    "local":                       ("0", "0"),
    "ollama":                      ("0", "0"),
    "llama":                       ("0", "0"),
    "deepseek":                    ("0", "0"),
    "qwen":                        ("0", "0"),
    "reasoner":                    ("0", "0"),
}

# Default rate applied when a model is not in the catalogue.
_DEFAULT_RATE: Tuple[str, str] = ("0.000002", "0.000008")


# ---------------------------------------------------------------------------
# PriceTable
# ---------------------------------------------------------------------------

class PriceTable:
    """Thread-safe registry mapping model identifiers to per-token rates.

    Rates are stored as ``Decimal`` pairs ``(input_rate, output_rate)``.
    Model names are normalised to lowercase before lookup; an alias chain is
    tried so that ``gpt-4o-2024-08-06`` resolves to ``gpt-4o``.

    Usage::

        pt = PriceTable()
        in_rate, out_rate = pt.rate_for("gpt-4o")
        cost = pt.compute_cost("gpt-4o", input_tokens=1000, output_tokens=500)
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._table: Dict[str, Tuple[Decimal, Decimal]] = {}
        # Seed from built-in catalogue
        for model, (inp, out) in _BUILTIN_RATES.items():
            self._table[model] = (_d(inp), _d(out))
        # Optionally overlay from project pricing.json
        self._load_pricing_json()

    def _load_pricing_json(self) -> None:
        """Overlay rates from the project's ``pricing.json`` if present."""
        candidates = [
            Path.cwd() / "pricing.json",
            Path(os.environ.get("CERBERUS_PRICING_JSON", "")) if os.environ.get("CERBERUS_PRICING_JSON") else None,
        ]
        for path in candidates:
            if path and path.is_file():
                try:
                    with path.open() as fh:
                        data = json.load(fh)
                    for model, info in data.items():
                        if isinstance(info, dict):
                            inp = info.get("input_cost_per_token") or info.get("prompt_price")
                            out = info.get("output_cost_per_token") or info.get("completion_price")
                            if inp is not None and out is not None:
                                with self._lock:
                                    self._table[model.lower()] = (_d(inp), _d(out))
                except Exception:
                    pass

    def update(self, model: str, input_rate: Any, output_rate: Any) -> None:
        """Add or replace a model's per-token rates at runtime."""
        with self._lock:
            self._table[model.lower()] = (_d(input_rate), _d(output_rate))

    def rate_for(self, model: str) -> Tuple[Decimal, Decimal]:
        """Return ``(input_rate, output_rate)`` for *model*.

        Falls back to a default rate when the model is unknown.
        """
        key = model.lower()
        with self._lock:
            if key in self._table:
                return self._table[key]
            # Prefix / alias match: try progressively shorter prefixes
            for candidate in list(self._table):
                if key.startswith(candidate) or candidate.startswith(key):
                    return self._table[candidate]
            return (_d(_DEFAULT_RATE[0]), _d(_DEFAULT_RATE[1]))

    def compute_cost(
        self,
        model: str,
        input_tokens: int,
        output_tokens: int,
    ) -> Decimal:
        """Return the total cost for *input_tokens* + *output_tokens*."""
        in_rate, out_rate = self.rate_for(model)
        return in_rate * _d(input_tokens) + out_rate * _d(output_tokens)

    def list_models(self) -> List[str]:
        """Return a sorted list of known model names."""
        with self._lock:
            return sorted(self._table)


# ---------------------------------------------------------------------------
# Pydantic v2 data models
# ---------------------------------------------------------------------------

class UsageRecord(BaseModel):
    """Immutable record of a single charged API call."""

    record_id: str = ""
    agent_name: str = ""
    model: str = ""
    operation: str = ""          # free-form label, e.g. "tool_call", "chat"
    input_tokens: int = 0
    output_tokens: int = 0
    cost: Decimal = Decimal("0")
    timestamp: datetime = None   # type: ignore[assignment]
    session_id: str = ""

    model_config = {"arbitrary_types_allowed": True}

    def model_post_init(self, __context: Any) -> None:
        if not self.record_id:
            object.__setattr__(self, "record_id", str(uuid.uuid4())[:8])
        if self.timestamp is None:
            object.__setattr__(self, "timestamp", datetime.now(tz=timezone.utc))

    @field_validator("input_tokens", "output_tokens", mode="before")
    @classmethod
    def _non_negative_int(cls, v: Any) -> int:
        val = int(v)
        return max(0, val)

    @field_validator("cost", mode="before")
    @classmethod
    def _to_decimal(cls, v: Any) -> Decimal:
        return _d(v)

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_id":    self.record_id,
            "agent_name":   self.agent_name,
            "model":        self.model,
            "operation":    self.operation,
            "input_tokens": self.input_tokens,
            "output_tokens":self.output_tokens,
            "total_tokens": self.total_tokens,
            "cost":         str(self.cost),
            "timestamp":    self.timestamp.isoformat(),
            "session_id":   self.session_id,
        }


class BudgetPolicy(BaseModel):
    """Budget configuration for a session."""

    limit: Decimal = Decimal("0")        # 0 means no limit
    currency: str = "USD"
    conversion_rate: Decimal = Decimal("1")
    soft_lock: bool = True               # warn only; False → hard-stop

    model_config = {"arbitrary_types_allowed": True}

    @field_validator("limit", "conversion_rate", mode="before")
    @classmethod
    def _to_decimal(cls, v: Any) -> Decimal:
        return _d(v)

    @field_validator("currency", mode="before")
    @classmethod
    def _upper_currency(cls, v: str) -> str:
        return v.upper()

    @property
    def active(self) -> bool:
        return self.limit > Decimal("0")

    def display_symbol(self) -> str:
        return {"USD": "$", "EUR": "€", "GBP": "£", "JPY": "¥"}.get(self.currency, self.currency + " ")

    def convert(self, usd_amount: Decimal) -> Decimal:
        """Convert a USD amount to the configured currency."""
        return (usd_amount * self.conversion_rate).quantize(
            Decimal("0.000001"), rounding=ROUND_HALF_UP
        )


# ---------------------------------------------------------------------------
# UsageTracker
# ---------------------------------------------------------------------------

@dataclass
class _AgentSummary:
    """Accumulated totals for one agent within the current session."""
    name: str
    total_cost: Decimal = field(default_factory=lambda: Decimal("0"))
    input_tokens: int = 0
    output_tokens: int = 0
    call_count: int = 0

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


class UsageTracker:
    """Thread-safe in-process ledger for API usage charges.

    All monetary values use ``Decimal`` throughout so there are no
    floating-point rounding surprises on invoices.

    Background usage hook::

        from cerberus.repl.commands.cost import record_usage
        record_usage("web_pentester", "gpt-4o", input_tokens=800, output_tokens=200)

    Reading data from REPL command::

        tracker = USAGE_TRACKER
        total = tracker.session_total()
        by_agent = tracker.by_agent()
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: List[UsageRecord] = []
        self._price_table = PriceTable()
        self._budget = BudgetPolicy()
        self._session_id: str = str(uuid.uuid4())
        self._budget_exceeded: bool = False
        self._budget_notified: bool = False

    # -- write side ---------------------------------------------------------

    def record(
        self,
        agent_name: str,
        model: str,
        input_tokens: int,
        output_tokens: int,
        *,
        operation: str = "",
        cost: Optional[Decimal] = None,
    ) -> UsageRecord:
        """Append a new ``UsageRecord`` and return it.

        If *cost* is ``None`` the ``PriceTable`` is consulted automatically.
        Budget threshold is evaluated after every record.
        """
        if cost is None:
            cost = self._price_table.compute_cost(model, input_tokens, output_tokens)
        rec = UsageRecord(
            agent_name=agent_name,
            model=model,
            operation=operation,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost=cost,
            session_id=self._session_id,
        )
        with self._lock:
            self._records.append(rec)
        self._check_budget()
        return rec

    def set_budget(self, limit: Any, currency: str = "USD", *, soft_lock: bool = True) -> None:
        """Set or update the session budget threshold."""
        rate = self._budget.conversion_rate  # preserve existing rate
        with self._lock:
            self._budget = BudgetPolicy(
                limit=limit,
                currency=currency,
                conversion_rate=rate,
                soft_lock=soft_lock,
            )
            self._budget_exceeded = False
            self._budget_notified = False

    def set_conversion_rate(self, rate: Any) -> None:
        """Update the currency conversion rate (e.g. 0.92 for USD → EUR)."""
        with self._lock:
            self._budget = self._budget.model_copy(update={"conversion_rate": _d(rate)})

    def reset_session(self) -> None:
        """Clear all records for the current session and issue a new session ID."""
        with self._lock:
            self._records.clear()
            self._session_id = str(uuid.uuid4())
            self._budget_exceeded = False
            self._budget_notified = False

    # -- read side ----------------------------------------------------------

    def session_total(self) -> Decimal:
        """Return the total USD cost accumulated so far this session."""
        with self._lock:
            return sum((r.cost for r in self._records), Decimal("0"))

    def session_total_tokens(self) -> Tuple[int, int]:
        """Return ``(total_input_tokens, total_output_tokens)`` for the session."""
        with self._lock:
            inp = sum(r.input_tokens for r in self._records)
            out = sum(r.output_tokens for r in self._records)
            return inp, out

    def by_agent(self) -> Dict[str, _AgentSummary]:
        """Return a dict of ``_AgentSummary`` keyed by agent name."""
        summaries: Dict[str, _AgentSummary] = {}
        with self._lock:
            for r in self._records:
                key = r.agent_name or "(unknown)"
                if key not in summaries:
                    summaries[key] = _AgentSummary(name=key)
                s = summaries[key]
                s.total_cost += r.cost
                s.input_tokens += r.input_tokens
                s.output_tokens += r.output_tokens
                s.call_count += 1
        return summaries

    def by_model(self) -> Dict[str, _AgentSummary]:
        """Return a dict of ``_AgentSummary`` (re-used struct) keyed by model."""
        summaries: Dict[str, _AgentSummary] = {}
        with self._lock:
            for r in self._records:
                key = r.model or "(unknown)"
                if key not in summaries:
                    summaries[key] = _AgentSummary(name=key)
                s = summaries[key]
                s.total_cost += r.cost
                s.input_tokens += r.input_tokens
                s.output_tokens += r.output_tokens
                s.call_count += 1
        return summaries

    def last_operation(self) -> Optional[UsageRecord]:
        """Return the most recent ``UsageRecord`` or ``None``."""
        with self._lock:
            return self._records[-1] if self._records else None

    def all_records(self) -> List[UsageRecord]:
        """Return a snapshot of all records (thread-safe copy)."""
        with self._lock:
            return list(self._records)

    @property
    def budget(self) -> BudgetPolicy:
        with self._lock:
            return self._budget

    @property
    def budget_exceeded(self) -> bool:
        with self._lock:
            return self._budget_exceeded

    @property
    def price_table(self) -> PriceTable:
        return self._price_table

    # -- export -------------------------------------------------------------

    def export(self, fmt: str = "json", directory: Optional[Path] = None) -> Path:
        """Write a billing report to *directory* (default ``~/.cerberus/billing/``).

        *fmt* must be ``"json"`` or ``"csv"``.  Returns the ``Path`` of the
        written file.
        """
        fmt = fmt.lower().strip()
        if fmt not in ("json", "csv"):
            raise ValueError(f"Unsupported export format: {fmt!r}; choose 'json' or 'csv'")

        out_dir = directory or Path.home() / ".cerberus" / "billing"
        out_dir.mkdir(parents=True, exist_ok=True)

        stamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        filename = f"billing_{stamp}.{fmt}"
        out_path = out_dir / filename

        records = self.all_records()
        session_total = self.session_total()

        if fmt == "json":
            payload = {
                "generated_at": datetime.now(tz=timezone.utc).isoformat(),
                "session_id":   self._session_id,
                "session_total_usd": str(session_total),
                "record_count": len(records),
                "records":      [r.to_dict() for r in records],
            }
            out_path.write_text(json.dumps(payload, indent=2, default=str))

        else:  # csv
            fieldnames = [
                "record_id", "timestamp", "agent_name", "model",
                "operation", "input_tokens", "output_tokens", "total_tokens", "cost",
            ]
            with out_path.open("w", newline="") as fh:
                writer = csv.DictWriter(fh, fieldnames=fieldnames)
                writer.writeheader()
                for r in records:
                    row = r.to_dict()
                    writer.writerow({k: row[k] for k in fieldnames})

        return out_path

    # -- internal -----------------------------------------------------------

    def _check_budget(self) -> None:
        """Evaluate the budget policy; set the exceeded flag if needed."""
        with self._lock:
            pol = self._budget
            if not pol.active:
                return
            total = sum((r.cost for r in self._records), Decimal("0"))
            if total >= pol.limit and not self._budget_exceeded:
                self._budget_exceeded = True


# ---------------------------------------------------------------------------
# Process-global singleton  (created once on first import)
# ---------------------------------------------------------------------------

USAGE_TRACKER = UsageTracker()


# ---------------------------------------------------------------------------
# Convenience hook for model-layer callers
# ---------------------------------------------------------------------------

def record_usage(
    agent_name: str,
    model: str,
    input_tokens: int,
    output_tokens: int,
    *,
    operation: str = "",
    cost: Optional[float] = None,
) -> None:
    """Append a usage record to the process-global ``USAGE_TRACKER``.

    Designed to be called from model-layer hooks without importing the full
    ``CostCommand``;  it is a thin wrapper around ``USAGE_TRACKER.record()``.
    """
    USAGE_TRACKER.record(
        agent_name=agent_name,
        model=model,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        operation=operation,
        cost=_d(cost) if cost is not None else None,
    )


# ---------------------------------------------------------------------------
# CostCommand
# ---------------------------------------------------------------------------

class CostCommand(Command):
    """Display and manage API cost accounting for the current session.

    Sub-commands
    ------------
    show          — Session cost summary with per-agent breakdown  (default)
    agents        — Detailed per-agent cost table
    models        — Detailed per-model cost table
    budget <$>    — Set or show the session budget  (--currency EUR, --hard)
    export        — Write a billing report  (--format json|csv)
    reset         — Clear the in-process session ledger
    """

    name = "/cost"
    description = "View usage costs and statistics"
    aliases = ["/costs", "/usage"]

    def __init__(self) -> None:
        super().__init__(name=self.name, description=self.description, aliases=self.aliases)
        self._tracker: UsageTracker = USAGE_TRACKER
        self.add_subcommand("summary", "Session and global usage summary", self.handle_summary)
        self.add_subcommand("show",   "Session cost summary",              self.handle_show)
        self.add_subcommand("agents", "Per-agent cost breakdown",          self.handle_agents)
        self.add_subcommand("models", "Per-model cost breakdown",          self.handle_models)
        self.add_subcommand("daily",  "Daily usage statistics",            self.handle_daily)
        self.add_subcommand("sessions", "Recent usage sessions",           self.handle_sessions)
        self.add_subcommand("budget", "Set/show budget threshold",         self.handle_budget)
        self.add_subcommand("export", "Export billing report (JSON/CSV)",  self.handle_export)
        self.add_subcommand("reset",  "Reset usage tracking data",         self.handle_reset)

    def handle(self, args: Optional[List[str]] = None) -> bool:  # type: ignore[override]
        try:
            clean = self.sanitize_args(args)
        except Exception as exc:
            console.print(f"[red]Input validation failed: {exc}[/red]")
            return False

        record = self._audit_before(clean)
        try:
            if not clean:
                result = self.handle_summary()
            else:
                sub = clean[0]
                handler = None
                registered = self.subcommands.get(sub)
                if registered:
                    maybe_handler = registered.get("handler")
                    if callable(maybe_handler):
                        handler = maybe_handler
                if handler is None:
                    handler = getattr(self, f"handle_{sub}", None)
                if handler:
                    result = handler(clean[1:])
                else:
                    result = self.handle_unknown_subcommand(sub)
        except CommandError as exc:
            self._audit_after(record, success=False, error=str(exc))
            console.print(f"[red]{self.name}: {exc}[/red]")
            return False
        except Exception as exc:  # pylint: disable=broad-except
            self._audit_after(record, success=False, error=repr(exc))
            raise

        self._audit_after(record, success=bool(result))
        return bool(result)

    def handle_no_args(self) -> bool:  # type: ignore[override]
        return self.handle_summary()

    def _format_cost(self, value: Any, digits: int = 6) -> str:
        return f"${float(value or 0):.{digits}f}"

    def _get_session_summary(self) -> str:
        input_tokens = int(getattr(COST_TRACKER, "current_agent_input_tokens", 0) or 0)
        output_tokens = int(getattr(COST_TRACKER, "current_agent_output_tokens", 0) or 0)
        total_tokens = input_tokens + output_tokens
        return (
            f"Session total cost: {self._format_cost(getattr(COST_TRACKER, 'session_total_cost', 0.0))}\n"
            f"Current agent cost: {self._format_cost(getattr(COST_TRACKER, 'current_agent_total_cost', 0.0))}\n"
            f"Input tokens: {input_tokens:,}\n"
            f"Output tokens: {output_tokens:,}\n"
            f"Total tokens: {total_tokens:,}"
        )

    def _get_global_summary(self) -> str:
        if not getattr(GLOBAL_USAGE_TRACKER, "enabled", True):
            return (
                "Usage tracking is disabled. "
                "Set CERBERUS_DISABLE_USAGE_TRACKING=false to enable it."
            )

        summary = GLOBAL_USAGE_TRACKER.get_summary()
        totals = summary.get("global_totals", {})
        return (
            f"Global total cost: {self._format_cost(totals.get('total_cost', 0.0))}\n"
            f"Total requests: {int(totals.get('total_requests', 0) or 0):,}\n"
            f"Total sessions: {int(totals.get('total_sessions', 0) or 0):,}\n"
            f"Input tokens: {int(totals.get('total_input_tokens', 0) or 0):,}\n"
            f"Output tokens: {int(totals.get('total_output_tokens', 0) or 0):,}"
        )

    def _show_top_models_mini(self) -> None:
        if not getattr(GLOBAL_USAGE_TRACKER, "enabled", True):
            return

        summary = GLOBAL_USAGE_TRACKER.get_summary()
        top_models = summary.get("top_models", [])
        if not top_models:
            return

        console.print("[bold]Top Models by Cost[/bold]")
        for model_name, total_cost in top_models[:5]:
            console.print(f"{model_name}: {self._format_cost(total_cost, digits=4)}")

    def handle_summary(self, args: Optional[List[str]] = None) -> bool:
        del args
        console.print("[bold]Usage Cost Summary[/bold]")
        console.print(self._get_session_summary())
        console.print(self._get_global_summary())
        self._show_top_models_mini()
        return True

    def handle_show(self, args: Optional[List[str]] = None) -> bool:
        return self.handle_summary(args)

    def handle_agents(self, args: Optional[List[str]] = None) -> bool:
        return self._run_execute(["agents", *(args or [])])

    def handle_models(self, args: Optional[List[str]] = None) -> bool:
        del args
        if not getattr(GLOBAL_USAGE_TRACKER, "enabled", True):
            console.print("[yellow]Usage tracking is disabled[/yellow]")
            return True

        model_usage = getattr(GLOBAL_USAGE_TRACKER, "usage_data", {}).get("model_usage", {})
        console.print("[bold]Model Usage Statistics[/bold]")
        if not model_usage:
            console.print("[yellow]No model usage data available[/yellow]")
            return True

        table = Table(title="Model Usage Statistics", box=box.SIMPLE)
        table.add_column("Model")
        table.add_column("Cost", justify="right")
        table.add_column("Requests", justify="right")
        table.add_column("Input Tokens", justify="right")
        table.add_column("Output Tokens", justify="right")

        sorted_models = sorted(
            model_usage.items(),
            key=lambda item: float(item[1].get("total_cost", 0.0) or 0.0),
            reverse=True,
        )
        for model_name, stats in sorted_models:
            table.add_row(
                str(model_name),
                self._format_cost(stats.get("total_cost", 0.0)),
                f"{int(stats.get('total_requests', 0) or 0):,}",
                f"{int(stats.get('total_input_tokens', 0) or 0):,}",
                f"{int(stats.get('total_output_tokens', 0) or 0):,}",
            )

        console.print(table)
        return True

    def handle_daily(self, args: Optional[List[str]] = None) -> bool:
        del args
        if not getattr(GLOBAL_USAGE_TRACKER, "enabled", True):
            console.print("[yellow]Usage tracking is disabled[/yellow]")
            return True

        daily_usage = getattr(GLOBAL_USAGE_TRACKER, "usage_data", {}).get("daily_usage", {})
        console.print("[bold]Daily Usage Statistics[/bold]")
        if not daily_usage:
            console.print("[yellow]No daily usage data available[/yellow]")
            return True

        table = Table(title="Daily Usage Statistics", box=box.SIMPLE)
        table.add_column("Date")
        table.add_column("Cost", justify="right")
        table.add_column("Requests", justify="right")
        table.add_column("Input Tokens", justify="right")
        table.add_column("Output Tokens", justify="right")

        for day, stats in sorted(daily_usage.items(), reverse=True):
            table.add_row(
                str(day),
                self._format_cost(stats.get("total_cost", 0.0)),
                f"{int(stats.get('total_requests', 0) or 0):,}",
                f"{int(stats.get('total_input_tokens', 0) or 0):,}",
                f"{int(stats.get('total_output_tokens', 0) or 0):,}",
            )

        console.print(table)
        return True

    def handle_sessions(self, args: Optional[List[str]] = None) -> bool:
        if not getattr(GLOBAL_USAGE_TRACKER, "enabled", True):
            console.print("[yellow]Usage tracking is disabled[/yellow]")
            return True

        limit = 10
        if args:
            try:
                limit = max(1, int(args[0]))
            except (TypeError, ValueError):
                limit = 10

        sessions = list(getattr(GLOBAL_USAGE_TRACKER, "usage_data", {}).get("sessions", []))
        title = f"Recent {limit} Sessions" if args else "Recent Sessions"
        console.print(f"[bold]{title}[/bold]")
        if not sessions:
            console.print("[yellow]No session usage data available[/yellow]")
            return True

        table = Table(title=title, box=box.SIMPLE)
        table.add_column("Session")
        table.add_column("Status")
        table.add_column("Cost", justify="right")
        table.add_column("Requests", justify="right")
        table.add_column("Models")

        for session in reversed(sessions[-limit:]):
            table.add_row(
                str(session.get("session_id", "unknown")),
                "Active" if not session.get("end_time") else "Completed",
                self._format_cost(session.get("total_cost", 0.0)),
                f"{int(session.get('total_requests', 0) or 0):,}",
                ", ".join(session.get("models_used", [])) or "-",
            )

        console.print(table)
        return True

    def handle_budget(self, args: Optional[List[str]] = None) -> bool:
        return self._run_execute(["budget", *(args or [])])

    def handle_export(self, args: Optional[List[str]] = None) -> bool:
        return self._run_execute(["export", *(args or [])])

    def handle_reset(self, args: Optional[List[str]] = None) -> bool:
        del args
        if not getattr(GLOBAL_USAGE_TRACKER, "enabled", True):
            console.print("[yellow]Usage tracking is disabled[/yellow]")
            return True

        usage_file = Path(Path.home()) / ".cerberus" / "usage.json"
        if not usage_file.exists():
            console.print("[yellow]No usage data to reset[/yellow]")
            return True

        summary = GLOBAL_USAGE_TRACKER.get_summary()
        totals = summary.get("global_totals", {})
        console.print(
            "[red]This will delete tracked usage data "
            f"({int(totals.get('total_sessions', 0) or 0)} sessions, "
            f"{self._format_cost(totals.get('total_cost', 0.0))}).[/red]"
        )
        confirmation = console.input("Type RESET to confirm: ").strip()
        if confirmation != "RESET":
            console.print("[yellow]Reset cancelled[/yellow]")
            return True

        backup_file = usage_file.with_name(
            f"usage.backup.{datetime.now().strftime('%Y%m%d%H%M%S')}.json"
        )
        shutil.copy2(usage_file, backup_file)
        usage_file.unlink()

        if hasattr(GLOBAL_USAGE_TRACKER, "usage_data"):
            GLOBAL_USAGE_TRACKER.usage_data = {
                "global_totals": {},
                "model_usage": {},
                "daily_usage": {},
                "sessions": [],
            }

        console.print(f"[green]Usage tracking reset. Backup saved to {backup_file}[/green]")
        return True

    # -- mandatory contract ------------------------------------------------

    @property
    def help(self) -> str:
        return (
            "cost [sub-command] [options]\n\n"
            "Sub-commands:\n"
            "  show              — Live session summary (default)\n"
            "  agents            — Per-agent cost table\n"
            "  models            — Per-model cost table\n"
            "  budget <amount>   — Set session budget limit  [--currency USD|EUR|GBP]\n"
            "                     [--hard] for hard-stop instead of warning\n"
            "  export            — Write billing report to ~/.cerberus/billing/\n"
            "                     [--format json|csv]\n"
            "  reset             — Clear the in-process session cost ledger\n\n"
            "Budget alert: once the session total reaches the configured limit, all\n"
            "agent dispatches are soft-locked until the budget is raised or reset.\n"
            "Currency conversion is applied to displayed amounts only; all internal\n"
            "calculations remain in USD (Decimal) for accuracy.\n"
        )

    async def execute(self, args: List[str]) -> bool:
        if not args:
            return await self._sub_show([])

        sub = args[0].lower()
        handler = getattr(self, f"_sub_{sub}", None)
        if handler is None:
            console.print(f"[red]cost: unknown sub-command '{sub}'[/red]")
            console.print(self.help)
            return False
        return await handler(args[1:])

    # -- sub-commands -------------------------------------------------------

    async def _sub_show(self, args: List[str]) -> bool:
        """Session summary: totals + per-agent headline + budget status."""
        tr = self._tracker
        pol = tr.budget
        total_usd = tr.session_total()
        total_display = pol.convert(total_usd)
        sym = pol.display_symbol()

        inp_tok, out_tok = tr.session_total_tokens()
        total_tok = inp_tok + out_tok
        record_count = len(tr.all_records())
        last_op = tr.last_operation()

        # ── Header / budget status ────────────────────────────────────────
        if tr.budget_exceeded:
            console.print(
                Panel(
                    f"[bold red]SESSION BUDGET EXCEEDED[/bold red]\n"
                    f"Spent: {sym}{total_display}  /  Limit: {sym}{pol.convert(pol.limit)}\n"
                    f"{'Agents soft-locked until budget is raised or reset.' if pol.soft_lock else 'Hard-stop active.'}",
                    title="[red]Budget Alert[/red]",
                    border_style="red",
                )
            )
        elif pol.active:
            remaining = pol.limit - total_usd
            console.print(
                f"[dim]Budget: {sym}{pol.convert(total_usd)} used / "
                f"{sym}{pol.convert(pol.limit)} limit  "
                f"({sym}{pol.convert(remaining)} remaining)[/dim]"
            )

        # ── Totals panel ─────────────────────────────────────────────────
        lines = [
            f"[bold]Session total:[/bold]  [yellow]{sym}{total_display}[/yellow]",
            f"[bold]API calls:[/bold]      {record_count}",
            f"[bold]Input tokens:[/bold]   {inp_tok:,}",
            f"[bold]Output tokens:[/bold]  {out_tok:,}",
            f"[bold]Total tokens:[/bold]   {total_tok:,}",
        ]
        if last_op:
            lines.append(
                f"[bold]Last call:[/bold]      {last_op.agent_name or '—'} / "
                f"{last_op.model or '—'}  {sym}{pol.convert(last_op.cost)}"
            )
        console.print(
            Panel(
                "\n".join(lines),
                title="[cyan]Session Cost Summary[/cyan]",
                border_style="cyan",
                box=box.ROUNDED,
            )
        )

        # ── Per-agent headline ────────────────────────────────────────────
        by_agent = tr.by_agent()
        if by_agent:
            t = Table(box=box.SIMPLE, show_header=True, header_style="bold")
            t.add_column("Agent",        style="cyan")
            t.add_column("Cost",         style="yellow", justify="right")
            t.add_column("Calls",        style="white",  justify="right")
            t.add_column("Tokens",       style="blue",   justify="right")
            for name, s in sorted(by_agent.items(), key=lambda x: x[1].total_cost, reverse=True):
                t.add_row(
                    name,
                    f"{sym}{pol.convert(s.total_cost)}",
                    str(s.call_count),
                    f"{s.total_tokens:,}",
                )
            console.print(t)

        console.print(
            "[dim]cost agents | cost models | cost budget <$> | "
            "cost export | cost reset[/dim]"
        )
        return True

    async def _sub_agents(self, args: List[str]) -> bool:
        """Detailed per-agent cost table."""
        tr = self._tracker
        pol = tr.budget
        sym = pol.display_symbol()
        by_agent = tr.by_agent()

        if not by_agent:
            console.print("[yellow]cost agents: no usage recorded this session[/yellow]")
            return True

        session_total = tr.session_total()
        t = Table(
            title="Per-Agent Cost Breakdown",
            box=box.ROUNDED, show_header=True, header_style="bold",
        )
        t.add_column("Agent",          style="cyan")
        t.add_column("Cost",           style="yellow",  justify="right")
        t.add_column("% of session",   style="white",   justify="right")
        t.add_column("Calls",          style="white",   justify="right")
        t.add_column("Input tokens",   style="blue",    justify="right")
        t.add_column("Output tokens",  style="magenta", justify="right")
        t.add_column("Avg cost/call",  style="green",   justify="right")

        for name, s in sorted(by_agent.items(), key=lambda x: x[1].total_cost, reverse=True):
            pct = float(s.total_cost / session_total * 100) if session_total > 0 else 0.0
            avg = s.total_cost / s.call_count if s.call_count > 0 else Decimal("0")
            t.add_row(
                name,
                f"{sym}{pol.convert(s.total_cost)}",
                f"{pct:.1f}%",
                str(s.call_count),
                f"{s.input_tokens:,}",
                f"{s.output_tokens:,}",
                f"{sym}{pol.convert(avg)}",
            )

        t.add_section()
        t.add_row(
            "[bold]TOTAL[/bold]",
            f"[bold]{sym}{pol.convert(session_total)}[/bold]",
            "100%",
            str(sum(s.call_count for s in by_agent.values())),
            f"{sum(s.input_tokens for s in by_agent.values()):,}",
            f"{sum(s.output_tokens for s in by_agent.values()):,}",
            "",
        )
        console.print(t)
        return True

    async def _sub_models(self, args: List[str]) -> bool:
        """Detailed per-model cost table."""
        tr = self._tracker
        pol = tr.budget
        sym = pol.display_symbol()
        by_model = tr.by_model()

        if not by_model:
            console.print("[yellow]cost models: no usage recorded this session[/yellow]")
            return True

        session_total = tr.session_total()
        t = Table(
            title="Per-Model Cost Breakdown",
            box=box.ROUNDED, show_header=True, header_style="bold",
        )
        t.add_column("Model",          style="cyan")
        t.add_column("Cost",           style="yellow",  justify="right")
        t.add_column("% of session",   style="white",   justify="right")
        t.add_column("Calls",          style="white",   justify="right")
        t.add_column("Input tokens",   style="blue",    justify="right")
        t.add_column("Output tokens",  style="magenta", justify="right")
        t.add_column("Avg cost/call",  style="green",   justify="right")

        for name, s in sorted(by_model.items(), key=lambda x: x[1].total_cost, reverse=True):
            pct = float(s.total_cost / session_total * 100) if session_total > 0 else 0.0
            avg = s.total_cost / s.call_count if s.call_count > 0 else Decimal("0")
            t.add_row(
                name,
                f"{sym}{pol.convert(s.total_cost)}",
                f"{pct:.1f}%",
                str(s.call_count),
                f"{s.input_tokens:,}",
                f"{s.output_tokens:,}",
                f"{sym}{pol.convert(avg)}",
            )

        t.add_section()
        t.add_row(
            "[bold]TOTAL[/bold]",
            f"[bold]{sym}{pol.convert(session_total)}[/bold]",
            "100%",
            str(sum(s.call_count for s in by_model.values())),
            f"{sum(s.input_tokens for s in by_model.values()):,}",
            f"{sum(s.output_tokens for s in by_model.values()):,}",
            "",
        )
        console.print(t)
        return True

    async def _sub_budget(self, args: List[str]) -> bool:
        """Set or display the session budget.

        Usage:  cost budget <amount> [--currency USD|EUR|GBP] [--hard]
                cost budget             ← show current policy
        """
        if not args:
            pol = self._tracker.budget
            if pol.active:
                sym = pol.display_symbol()
                total = pol.convert(self._tracker.session_total())
                limit = pol.convert(pol.limit)
                console.print(
                    f"Budget: {sym}{total} used / {sym}{limit} limit  "
                    f"({'soft-lock' if pol.soft_lock else 'HARD-STOP'})  "
                    f"currency={pol.currency}"
                )
            else:
                console.print("[dim]No budget configured.  Use: cost budget <amount>[/dim]")
            return True

        # Parse amount (first positional non-flag arg)
        amount_str = None
        currency = "USD"
        hard = False
        i = 0
        while i < len(args):
            tok = args[i]
            if tok == "--currency" and i + 1 < len(args):
                currency = args[i + 1].upper()
                i += 2
            elif tok == "--hard":
                hard = True
                i += 1
            else:
                amount_str = tok
                i += 1

        if amount_str is None:
            console.print("[red]cost budget: usage: cost budget <amount> [--currency X][/red]")
            return False

        try:
            limit = _d(amount_str.lstrip("$€£¥"))
        except Exception:
            console.print(f"[red]cost budget: invalid amount '{amount_str}'[/red]")
            return False

        self._tracker.set_budget(limit, currency=currency, soft_lock=not hard)
        sym = self._tracker.budget.display_symbol()
        console.print(
            f"[green]Budget set:[/green] {sym}{limit} {currency}  "
            f"({'hard-stop' if hard else 'soft-lock'})"
        )
        return True

    async def _sub_export(self, args: List[str]) -> bool:
        """Export a billing report.

        Usage:  cost export [--format json|csv]
        """
        fmt = "json"
        i = 0
        while i < len(args):
            tok = args[i]
            if tok in ("--format", "-f") and i + 1 < len(args):
                fmt = args[i + 1].lower()
                i += 2
            else:
                fmt = tok.lstrip("-")
                i += 1

        try:
            path = self._tracker.export(fmt=fmt)
        except ValueError as exc:
            console.print(f"[red]cost export: {exc}[/red]")
            return False

        record_count = len(self._tracker.all_records())
        total = self._tracker.session_total()
        console.print(
            Panel(
                f"[green]Billing report exported[/green]\n"
                f"File:    {path}\n"
                f"Format:  {fmt.upper()}\n"
                f"Records: {record_count}\n"
                f"Total:   ${total}",
                title="[green]Export Complete[/green]",
                border_style="green",
                box=box.ROUNDED,
            )
        )
        return True

    async def _sub_reset(self, args: List[str]) -> bool:
        """Clear the in-process session cost ledger."""
        old_total = self._tracker.session_total()
        old_count = len(self._tracker.all_records())
        self._tracker.reset_session()
        console.print(
            f"[green]Session ledger reset.[/green]  "
            f"Cleared {old_count} records totalling ${old_total}."
        )
        return True


# ---------------------------------------------------------------------------
# Register
# ---------------------------------------------------------------------------

COST_COMMAND_INSTANCE = CostCommand()
register_command(COST_COMMAND_INSTANCE)
