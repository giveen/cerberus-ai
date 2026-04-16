"""Cerberus AI performance and safety utility core.

This module intentionally centralizes low-level helpers used across the CLI,
agents, tools, and diagnostics workflows. Implementations are designed to be
small, testable, and defensive.
"""

from __future__ import annotations

import asyncio
import importlib.resources
import json
import os
import re
import threading
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any, Awaitable, Callable, Iterable, Mapping, MutableMapping, Sequence, TypeVar

try:
    from mako.template import Template  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    Template = None


# Allow ``cerberus.util`` to expose submodules from ``src/cerberus/util/`` while keeping
# backward compatibility with the existing ``src/cerberus/util.py`` module API.
_UTIL_SUBMODULE_DIR = Path(__file__).with_suffix("")
if _UTIL_SUBMODULE_DIR.is_dir():
    __path__ = [str(_UTIL_SUBMODULE_DIR)]


# ---------------------------------------------------------------------------
# Runtime and telemetry constants
# ---------------------------------------------------------------------------

START_TIME = time.time()

_ANSI_ESCAPE_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
_JSON_CODEBLOCK_RE = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL | re.IGNORECASE)
_TRAILING_COMMA_RE = re.compile(r",\s*([}\]])")

# Global state containers retained for compatibility with existing callers.
_LIVE_STREAMING_PANELS: dict[str, Any] = {}
_CLAUDE_THINKING_PANELS: dict[str, dict[str, Any]] = {}

_active_timer_start: float | None = None
_idle_timer_start: float | None = START_TIME
_active_time_total = 0.0
_idle_time_total = 0.0
_timer_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Parsing and sanitization
# ---------------------------------------------------------------------------

def strip_ansi(text: str | None) -> str:
    """Remove ANSI escape sequences from terminal text."""
    if not text:
        return ""
    return _ANSI_ESCAPE_RE.sub("", text)


def _extract_balanced_json(text: str) -> str | None:
    """Extract the first balanced JSON object/array from mixed text."""
    start = -1
    opener = ""
    for i, ch in enumerate(text):
        if ch in "[{":
            start = i
            opener = ch
            break
    if start < 0:
        return None

    closer = "}" if opener == "{" else "]"
    depth = 0
    in_string = False
    escaped = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_string:
            if escaped:
                escaped = False
                continue
            if ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue

        if ch == '"':
            in_string = True
            continue
        if ch == opener:
            depth += 1
        elif ch == closer:
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return None


def sanitize_json_text(raw: Any, default: Any = None) -> Any:
    """Parse JSON from malformed LLM output using layered repair heuristics.

    The function accepts plain JSON, markdown code blocks, and mixed prose.
    It applies small repairs (trailing commas, smart quote normalization,
    Python literals) and returns `default` when parsing remains impossible.
    """
    if raw is None:
        return default
    if isinstance(raw, (dict, list)):
        return raw

    text = strip_ansi(str(raw)).strip()
    if not text:
        return default

    candidates: list[str] = [text]
    for match in _JSON_CODEBLOCK_RE.finditer(text):
        candidates.append(match.group(1).strip())
    extracted = _extract_balanced_json(text)
    if extracted:
        candidates.append(extracted.strip())

    seen: set[str] = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        try:
            return json.loads(candidate)
        except Exception:
            pass

        repaired = candidate.replace("\u201c", '"').replace("\u201d", '"')
        repaired = repaired.replace("\u2018", "'").replace("\u2019", "'")
        repaired = _TRAILING_COMMA_RE.sub(r"\\1", repaired)
        repaired = repaired.replace("\n", "\\n") if "\\" not in repaired else repaired
        repaired = re.sub(r"\bTrue\b", "true", repaired)
        repaired = re.sub(r"\bFalse\b", "false", repaired)
        repaired = re.sub(r"\bNone\b", "null", repaired)

        try:
            return json.loads(repaired)
        except Exception:
            continue

    return default


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------

class CerebroFormatter:
    """Formatting helpers for operator-facing logs and dashboards."""

    _SIZE_UNITS = ("B", "KB", "MB", "GB", "TB", "PB")

    @staticmethod
    def human_size(num_bytes: int | float, precision: int = 2) -> str:
        """Convert a byte count into a human-readable unit string."""
        value = float(max(0.0, num_bytes))
        unit_idx = 0
        while value >= 1024.0 and unit_idx < len(CerebroFormatter._SIZE_UNITS) - 1:
            value /= 1024.0
            unit_idx += 1
        return f"{value:.{precision}f} {CerebroFormatter._SIZE_UNITS[unit_idx]}"

    @staticmethod
    def duration_hms(seconds: int | float) -> str:
        """Format seconds as HH:MM:SS."""
        sec = int(max(0, seconds))
        hours, rem = divmod(sec, 3600)
        minutes, secs = divmod(rem, 60)
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"


def format_time(seconds: int | float) -> str:
    """Backward-compatible wrapper around duration formatting."""
    return CerebroFormatter.duration_hms(seconds)


def safe_duration_to_float(time_val: Any) -> float:
    """Convert duration-like values to seconds without raising.

    Supports numeric values, HH:MM:SS / MM:SS strings, and common
    unit-suffixed forms like "1h 2m 3s".
    """
    if time_val is None:
        return 0.0

    if isinstance(time_val, (int, float)):
        return float(time_val)

    value = str(time_val).strip()
    if not value:
        return 0.0

    try:
        return float(value)
    except (TypeError, ValueError):
        pass

    if ":" in value:
        parts = value.split(":")
        if 2 <= len(parts) <= 3:
            try:
                total = 0.0
                for part in parts:
                    total = (total * 60.0) + float(part.strip())
                return max(0.0, total)
            except (TypeError, ValueError):
                return 0.0

    unit_match = re.fullmatch(
        r"\s*(?:(?P<hours>\d+(?:\.\d+)?)\s*h)?\s*"
        r"(?:(?P<minutes>\d+(?:\.\d+)?)\s*m)?\s*"
        r"(?:(?P<seconds>\d+(?:\.\d+)?)\s*s)?\s*",
        value,
        flags=re.IGNORECASE,
    )
    if unit_match and unit_match.group(0).strip():
        hours = float(unit_match.group("hours") or 0.0)
        minutes = float(unit_match.group("minutes") or 0.0)
        seconds = float(unit_match.group("seconds") or 0.0)
        return max(0.0, (hours * 3600.0) + (minutes * 60.0) + seconds)

    return 0.0


# ---------------------------------------------------------------------------
# Async reliability helpers
# ---------------------------------------------------------------------------

T = TypeVar("T")


def async_retry(
    *,
    attempts: int = 3,
    base_delay: float = 0.4,
    max_delay: float = 8.0,
    retry_on: tuple[type[BaseException], ...] = (Exception,),
) -> Callable[[Callable[..., Awaitable[T]]], Callable[..., Awaitable[T]]]:
    """Decorate an async callable with exponential backoff retries."""

    def decorator(fn: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
        async def wrapped(*args: Any, **kwargs: Any) -> T:
            last_error: BaseException | None = None
            for attempt in range(1, max(1, attempts) + 1):
                try:
                    return await fn(*args, **kwargs)
                except retry_on as exc:
                    last_error = exc
                    if attempt >= attempts:
                        break
                    delay = min(max_delay, base_delay * (2 ** (attempt - 1)))
                    await asyncio.sleep(delay)
            assert last_error is not None
            raise last_error

        return wrapped

    return decorator


@asynccontextmanager
async def async_timeout(seconds: float):
    """Context manager that enforces an async operation timeout."""
    async with asyncio.timeout(seconds):
        yield


async def run_with_timeout(awaitable: Awaitable[T], *, seconds: float) -> T:
    """Execute an awaitable with a strict timeout boundary."""
    return await asyncio.wait_for(awaitable, timeout=seconds)


# ---------------------------------------------------------------------------
# Fuzzy matching and path safety
# ---------------------------------------------------------------------------

def _tokenize(value: str) -> list[str]:
    return [t for t in re.split(r"[^a-z0-9]+", value.lower()) if t]


def fuzzy_match(query: str, choices: Sequence[str], limit: int = 5) -> list[tuple[str, float]]:
    """Return best fuzzy matches scored in range [0, 1]."""
    q = query.strip().lower()
    if not q:
        return []

    scored: list[tuple[str, float]] = []
    q_tokens = set(_tokenize(q))
    for choice in choices:
        c = choice.lower()
        ratio = SequenceMatcher(None, q, c).ratio()
        c_tokens = set(_tokenize(c))
        token_overlap = (len(q_tokens & c_tokens) / len(q_tokens | c_tokens)) if (q_tokens or c_tokens) else 0.0
        score = (ratio * 0.75) + (token_overlap * 0.25)
        scored.append((choice, score))

    scored.sort(key=lambda item: item[1], reverse=True)
    return scored[: max(1, limit)]


def normalize_workspace_path(path_value: str | os.PathLike[str], workspace_root: str | os.PathLike[str]) -> Path:
    """Resolve and validate a path within a workspace sandbox."""
    root = Path(workspace_root).expanduser().resolve()
    target = Path(path_value).expanduser()
    if not target.is_absolute():
        target = root / target
    resolved = target.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"Path escapes workspace sandbox: {path_value}") from exc
    return resolved


# ---------------------------------------------------------------------------
# System diagnostics
# ---------------------------------------------------------------------------

def _linux_memory_snapshot() -> tuple[int, int] | None:
    meminfo = Path("/proc/meminfo")
    if not meminfo.exists():
        return None
    total_kb = 0
    available_kb = 0
    for line in meminfo.read_text(encoding="utf-8", errors="ignore").splitlines():
        if line.startswith("MemTotal:"):
            total_kb = int(line.split()[1])
        elif line.startswith("MemAvailable:"):
            available_kb = int(line.split()[1])
    if total_kb <= 0:
        return None
    return total_kb * 1024, available_kb * 1024


def get_system_telemetry() -> dict[str, Any]:
    """Return lightweight CPU and memory telemetry for status UIs."""
    cpu_load = None
    try:
        cpu_load = os.getloadavg()[0]
    except Exception:
        cpu_load = None

    memory_total = None
    memory_available = None

    try:
        import psutil  # type: ignore

        vm = psutil.virtual_memory()
        memory_total = int(vm.total)
        memory_available = int(vm.available)
    except Exception:
        snapshot = _linux_memory_snapshot()
        if snapshot:
            memory_total, memory_available = snapshot

    memory_used_pct = None
    if memory_total and memory_available is not None and memory_total > 0:
        memory_used_pct = round((1 - (memory_available / memory_total)) * 100, 2)

    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "cpu_load_1m": cpu_load,
        "memory_total": memory_total,
        "memory_available": memory_available,
        "memory_used_percent": memory_used_pct,
    }


# ---------------------------------------------------------------------------
# Prompt template helpers
# ---------------------------------------------------------------------------

def load_prompt_template(template_path: str) -> str:
    """Load a prompt template from filesystem or package resources."""
    candidate = Path(template_path)
    if candidate.exists():
        return candidate.read_text(encoding="utf-8")

    base = Path(__file__).resolve().parents[1]
    alt = (base / template_path).resolve()
    if alt.exists():
        return alt.read_text(encoding="utf-8")

    try:
        resource = importlib.resources.files("cerberus") / template_path
        if resource.is_file():
            return resource.read_text(encoding="utf-8")
    except Exception:
        pass

    raise FileNotFoundError(f"Template not found: {template_path}")


_THINK_JSON_OUTPUT_CONTRACT = (
    "\n\n## RESPONSE CONTRACT\n"
    "When the task requires a JSON action, emit exactly one COMMITTING_JSON line immediately before the final JSON object.\n"
    "Do not wrap the action in markdown fences or add extra prose around the JSON.\n"
    "If a required field is unknown, return an explicit error JSON instead of empty arguments.\n"
    "If no JSON action is required, follow the base instructions normally.\n"
)


def _with_think_json_contract(base_instructions: str) -> str:
    """Attach strict think/JSON contract once, unless already present."""
    text = base_instructions or ""
    lowered = text.lower()
    if "<think>" in lowered and "valid json" in lowered:
        return text
    return f"{text.rstrip()}{_THINK_JSON_OUTPUT_CONTRACT}"


def _resolve_dynamic_system_prompt_override() -> str | None:
    """Load dynamic system prompt override when dispatcher selects a persona."""
    prompt_path = str(os.getenv("CERBERUS_DYNAMIC_PERSONA_PROMPT_PATH", "") or "").strip()
    if not prompt_path:
        return None
    try:
        return load_prompt_template(prompt_path)
    except Exception:
        return None


def create_system_prompt_renderer(base_instructions: str) -> Callable[..., str]:
    """Return a renderer that applies contextual variables to prompt templates.

    Agent system prompts may contain bash-style default-value expansions such as
    ``${WORKSPACE:-$(pwd)/foo}`` inside shell code blocks.  Mako's lexer would
    attempt to evaluate the content of ``${…}`` as a Python expression, which
    raises a ``SyntaxException`` for bash-specific syntax like ``:-``.

    To handle this robustly, the function first attempts to compile the prompt
    text as a Mako template.  If compilation fails, it falls back to a simple
    renderer that returns the raw prompt string, optionally applying Python
    ``.format()`` substitutions if keyword arguments are provided.
    """
    dynamic_override = _resolve_dynamic_system_prompt_override()
    effective_instructions = dynamic_override if dynamic_override else base_instructions
    enriched_instructions = _with_think_json_contract(effective_instructions)

    if Template is not None:
        try:
            template = Template(enriched_instructions)

            def _render_mako(*args: Any, **kwargs: Any) -> str:
                if args:
                    kwargs.setdefault("run_context", args[0])
                if len(args) > 1:
                    kwargs.setdefault("agent", args[1])
                rendered = template.render(**kwargs)
                return rendered.decode("utf-8", errors="replace") if isinstance(rendered, bytes) else str(rendered)

            return _render_mako
        except Exception:
            # Prompt contains bash-style ${VAR:-default} or other Mako-
            # incompatible syntax — fall through to the plain renderer.
            pass

    def _fallback(*args: Any, **kwargs: Any) -> str:
        if args:
            kwargs.setdefault("run_context", args[0])
        if len(args) > 1:
            kwargs.setdefault("agent", args[1])
        try:
            return enriched_instructions.format(**kwargs)
        except Exception:
            return enriched_instructions

    return _fallback


def append_instructions(agent: Any, additional_instructions: str) -> str:
    """Append guidance to an agent instruction field and return merged text."""
    existing = getattr(agent, "instructions", "") or ""
    merged = f"{existing}\n\n{additional_instructions}".strip()
    try:
        setattr(agent, "instructions", merged)
    except Exception:
        pass
    return merged


# ---------------------------------------------------------------------------
# Cost tracking and pricing
# ---------------------------------------------------------------------------

@dataclass
class CostTracker:
    """Session-level cost and token tracker used by CLI/TUI surfaces."""

    session_total_cost: float = 0.0
    current_agent_total_cost: float = 0.0
    current_agent_input_tokens: int = 0
    current_agent_output_tokens: int = 0
    current_agent_reasoning_tokens: int = 0

    interaction_cost: float = 0.0
    last_interaction_cost: float = 0.0
    last_total_cost: float = 0.0

    model_pricing_cache: dict[str, tuple[float, float]] = field(default_factory=dict)

    def _normalize_model(self, model: Any) -> str:
        return get_model_name(model).strip()

    def _pricing_files(self) -> list[Path]:
        candidates = [Path.cwd() / "pricing.json"]
        override = os.getenv("CERBERUS_PRICING_JSON", "").strip()
        if override:
            candidates.append(Path(override))
        return candidates

    def _is_local_model(self, model_name: str) -> bool:
        lower = model_name.lower()
        if lower.startswith("ollama/"):
            return True
        if any(k in lower for k in ("gpt-", "claude", "gemini", "deepseek-chat", "o1", "o3", "o4")):
            return False
        if ":" in model_name:
            return True
        return False

    def _read_local_pricing(self, model_name: str) -> tuple[float, float] | None:
        for pricing_path in self._pricing_files():
            if not pricing_path.exists():
                continue
            try:
                with pricing_path.open("r", encoding="utf-8") as handle:
                    payload = json.load(handle)
            except Exception:
                continue
            if not isinstance(payload, Mapping):
                continue
            if model_name in payload and isinstance(payload[model_name], Mapping):
                entry = payload[model_name]
                return (
                    float(entry.get("input_cost_per_token", 0.0) or 0.0),
                    float(entry.get("output_cost_per_token", 0.0) or 0.0),
                )
        return None

    def _read_remote_pricing(self, model_name: str) -> tuple[float, float] | None:
        if os.getenv("CERBERUS_ENABLE_REMOTE_PRICING", "").strip().lower() in {"0", "false", "no", "off"}:
            return None

        url = os.getenv(
            "CERBERUS_LITELLM_PRICING_URL",
            "https://raw.githubusercontent.com/BerriAI/litellm/main/model_prices_and_context_window.json",
        ).strip()
        if not url:
            return None
        try:
            import requests

            response = requests.get(url, timeout=4)
            if response.status_code != 200:
                return None
            data = response.json()
        except Exception:
            return None

        if not isinstance(data, Mapping):
            return None

        entry = data.get(model_name)
        if entry is None:
            lower_name = model_name.lower()
            for key, value in data.items():
                if isinstance(key, str) and key.lower() == lower_name:
                    entry = value
                    break
        if not isinstance(entry, Mapping):
            return None

        return (
            float(entry.get("input_cost_per_token", 0.0) or 0.0),
            float(entry.get("output_cost_per_token", 0.0) or 0.0),
        )

    def get_model_pricing(self, model_name: Any) -> tuple[float, float]:
        """Resolve per-token input/output pricing for a model."""
        model_key = self._normalize_model(model_name)
        if not model_key:
            return (0.0, 0.0)

        if model_key in self.model_pricing_cache:
            return self.model_pricing_cache[model_key]

        local = self._read_local_pricing(model_key)
        if local is not None:
            self.model_pricing_cache[model_key] = local
            return local

        remote = self._read_remote_pricing(model_key)
        if remote is not None:
            self.model_pricing_cache[model_key] = remote
            return remote

        fallback = (0.0, 0.0) if self._is_local_model(model_key) else (0.0, 0.0)
        self.model_pricing_cache[model_key] = fallback
        return fallback

    def calculate_cost(
        self,
        model: Any,
        input_tokens: int | float,
        output_tokens: int | float,
        *,
        label: str | None = None,
    ) -> float:
        """Compute request cost from token counts and configured pricing."""
        in_price, out_price = self.get_model_pricing(model)
        cost = (float(input_tokens) * in_price) + (float(output_tokens) * out_price)
        return float(max(0.0, cost))

    def process_interaction_cost(
        self,
        model: Any,
        input_tokens: int | float,
        output_tokens: int | float,
        *,
        reasoning_tokens: int | float = 0,
        label: str | None = None,
    ) -> float:
        """Update latest interaction statistics and return current interaction cost."""
        self.current_agent_input_tokens = int(input_tokens)
        self.current_agent_output_tokens = int(output_tokens)
        self.current_agent_reasoning_tokens = int(reasoning_tokens)
        current = self.calculate_cost(model, input_tokens, output_tokens, label=label)
        self.interaction_cost = current
        self.last_interaction_cost = current
        return current

    def process_total_cost(self, interaction_cost: float, *, label: str | None = None) -> float:
        """Accumulate interaction cost into the session total."""
        self.session_total_cost += float(interaction_cost)
        self.current_agent_total_cost += float(interaction_cost)
        self.last_total_cost = self.session_total_cost
        return self.session_total_cost

    def check_price_limit(self, estimated_cost: float) -> None:
        """Raise if session cost plus estimate exceeds configured budget."""
        raw_limit = os.getenv("CERBERUS_MAX_USD", "").strip()
        if not raw_limit:
            return
        try:
            max_budget = float(raw_limit)
        except ValueError:
            return
        if max_budget <= 0:
            return
        projected = self.session_total_cost + float(estimated_cost)
        if projected > max_budget:
            raise RuntimeError(f"Price limit exceeded: projected ${projected:.4f} > budget ${max_budget:.4f}")

    def reset_cost_for_local_model(self, model_name: Any) -> bool:
        """Reset pricing to free-tier if the model resolves to zero cost."""
        in_price, out_price = self.get_model_pricing(model_name)
        is_free = in_price == 0.0 and out_price == 0.0
        if is_free:
            self.model_pricing_cache[self._normalize_model(model_name)] = (0.0, 0.0)
        return is_free

    def log_final_cost(self) -> None:
        """Finalization hook retained for API compatibility."""
        return


COST_TRACKER = CostTracker()


def get_model_name(model: Any) -> str:
    """Extract a canonical model name from strings or model objects."""
    if model is None:
        return ""
    if isinstance(model, str):
        return model
    for attr in ("model", "name", "id"):
        value = getattr(model, attr, None)
        if isinstance(value, str) and value:
            return value
    return str(model)


def get_model_input_tokens(model: Any) -> int:
    """Estimate model context window from naming hints."""
    model_name = get_model_name(model).lower()
    explicit_ctx = re.search(r"ctx[-_]?([0-9]{4,6})", model_name)
    if explicit_ctx:
        return int(explicit_ctx.group(1))
    if "128k" in model_name:
        return 128000
    if "200k" in model_name:
        return 200000
    if any(tag in model_name for tag in ("gpt-4o", "gpt-4.1", "claude-3", "o3", "o4")):
        return 128000
    return int(os.getenv("CERBERUS_DEFAULT_CONTEXT_WINDOW", "32768"))


def get_ollama_api_base() -> str:
    """Resolve Ollama API base URL from environment."""
    return os.getenv("OLLAMA_API_BASE") or os.getenv("OLLAMA_BASE_URL") or "http://127.0.0.1:11434"


def get_ollama_auth_headers() -> dict[str, str]:
    """Build auth headers for Ollama-compatible backends."""
    token = os.getenv("OLLAMA_API_KEY", "").strip()
    if not token:
        return {}
    return {"Authorization": f"Bearer {token}"}


def get_model_pricing(model_name: Any) -> tuple[float, float]:
    """Module-level pricing helper."""
    return COST_TRACKER.get_model_pricing(model_name)


def calculate_model_cost(model: Any, input_tokens: int | float, output_tokens: int | float) -> float:
    """Module-level cost helper."""
    return COST_TRACKER.calculate_cost(model, input_tokens, output_tokens)


# ---------------------------------------------------------------------------
# Timing helpers
# ---------------------------------------------------------------------------

def start_active_timer() -> None:
    """Transition timers into active state."""
    global _active_timer_start, _idle_timer_start, _idle_time_total
    with _timer_lock:
        now = time.time()
        if _idle_timer_start is not None:
            _idle_time_total += now - _idle_timer_start
            _idle_timer_start = None
        if _active_timer_start is None:
            _active_timer_start = now


def stop_active_timer() -> None:
    """Pause active timer and resume idle timer."""
    global _active_timer_start, _idle_timer_start, _active_time_total
    with _timer_lock:
        now = time.time()
        if _active_timer_start is not None:
            _active_time_total += now - _active_timer_start
            _active_timer_start = None
        if _idle_timer_start is None:
            _idle_timer_start = now


def start_idle_timer() -> None:
    """Transition timers into idle state."""
    stop_active_timer()


def stop_idle_timer() -> None:
    """Pause idle timer and resume active timer."""
    global _active_timer_start, _idle_timer_start, _idle_time_total
    with _timer_lock:
        now = time.time()
        if _idle_timer_start is not None:
            _idle_time_total += now - _idle_timer_start
            _idle_timer_start = None
        if _active_timer_start is None:
            _active_timer_start = now


def get_active_time_seconds() -> float:
    """Return cumulative active time in seconds."""
    with _timer_lock:
        total = _active_time_total
        if _active_timer_start is not None:
            total += time.time() - _active_timer_start
    return max(0.0, total)


def get_idle_time_seconds() -> float:
    """Return cumulative idle time in seconds."""
    with _timer_lock:
        total = _idle_time_total
        if _idle_timer_start is not None:
            total += time.time() - _idle_timer_start
    return max(0.0, total)


def get_active_time() -> str:
    """Return formatted active time."""
    return format_time(get_active_time_seconds())


def get_idle_time() -> str:
    """Return formatted idle time."""
    return format_time(get_idle_time_seconds())


# ---------------------------------------------------------------------------
# Message and output helpers
# ---------------------------------------------------------------------------

def _json_dumps_compact(value: Any) -> str:
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=True)
    except Exception:
        return str(value)


def _tool_key(tool_name: str, args: Any, token_info: Mapping[str, Any] | None = None) -> str:
    command = ""
    if isinstance(args, Mapping):
        command = str(args.get("command", ""))
    scope = ""
    if token_info:
        scope = str(token_info.get("agent_id") or token_info.get("agent_name") or "")
    return f"{scope}:{tool_name}:{command or _json_dumps_compact(args)}"


def cli_print_tool_call(tool_name: str = "", args: Any = "", output: Any = "", prefix: str = "  ", **_: Any) -> None:
    """Print a concise tool invocation line."""
    print(f"{prefix}[tool] {tool_name} args={_json_dumps_compact(args)}")


def cli_print_tool_output(
    tool_name: str = "",
    args: Any = "",
    output: Any = "",
    prefix: str = "  ",
    streaming: bool = False,
    execution_info: Mapping[str, Any] | None = None,
    token_info: Mapping[str, Any] | None = None,
    **_: Any,
) -> None:
    """Print tool output with duplicate suppression guards.

    Deduplication behavior:
    - `CERBERUS_STREAM=true`: suppress repeated command keys for the whole session.
    - `CERBERUS_STREAM=false`: suppress repeated command keys within 0.5 seconds.
    """
    text_output = "" if output is None else str(output)
    if not text_output.strip():
        return

    if not hasattr(cli_print_tool_output, "_displayed_commands"):
        cli_print_tool_output._displayed_commands = set()  # type: ignore[attr-defined]
    if not hasattr(cli_print_tool_output, "_command_display_times"):
        cli_print_tool_output._command_display_times = {}  # type: ignore[attr-defined]
    if not hasattr(cli_print_tool_output, "_seen_calls"):
        cli_print_tool_output._seen_calls = set()  # type: ignore[attr-defined]
    if not hasattr(cli_print_tool_output, "_streaming_sessions"):
        cli_print_tool_output._streaming_sessions = {}  # type: ignore[attr-defined]

    now = time.time()
    key = _tool_key(tool_name, args, token_info)
    display_times: MutableMapping[str, float] = cli_print_tool_output._command_display_times  # type: ignore[attr-defined]
    streaming_enabled = os.getenv("CERBERUS_STREAM", "false").strip().lower() == "true"

    if streaming_enabled:
        if key in cli_print_tool_output._displayed_commands:  # type: ignore[attr-defined]
            return
        cli_print_tool_output._displayed_commands.add(key)  # type: ignore[attr-defined]
    else:
        last_display = display_times.get(key)
        if last_display is not None and (now - last_display) < 0.5:
            return

    display_times[key] = now
    print(f"{prefix}{tool_name}: {text_output}")


def cli_print_agent_messages(messages: Sequence[Mapping[str, Any]], *, title: str | None = None, **_: Any) -> None:
    """Render agent messages in plain text for debugging."""
    if title:
        print(f"== {title} ==")
    for idx, msg in enumerate(messages):
        role = msg.get("role", "unknown")
        content = msg.get("content", "")
        print(f"[{idx}] {role}: {content}")


def parse_message_content(message: Mapping[str, Any]) -> str:
    """Extract content string from normalized message payload."""
    content = message.get("content", "")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(str(item.get("text", item)) for item in content)
    return str(content)


def parse_message_tool_call(message: Mapping[str, Any], tool_output: Any = None) -> dict[str, Any]:
    """Normalize tool call metadata from a message."""
    calls = message.get("tool_calls") or []
    if not calls:
        return {}
    first = calls[0]
    function = first.get("function", {}) if isinstance(first, Mapping) else {}
    return {
        "id": first.get("id"),
        "name": function.get("name") if isinstance(function, Mapping) else None,
        "arguments": function.get("arguments") if isinstance(function, Mapping) else None,
        "output": tool_output,
    }


def is_tool_output_message(message: Mapping[str, Any]) -> bool:
    """Return True when a message is a tool role output."""
    return str(message.get("role", "")).lower() == "tool"


def print_message_history(messages: Sequence[Mapping[str, Any]], title: str = "Message History") -> None:
    """Print a compact message transcript."""
    print(f"== {title} ==")
    for idx, msg in enumerate(messages):
        role = msg.get("role", "unknown")
        content = parse_message_content(msg)
        print(f"{idx:03d} {role}: {content[:240]}")


def fix_message_list(messages: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Repair message sequences by filling missing tool result messages."""
    fixed: list[dict[str, Any]] = []
    pending: list[str] = []

    for raw in messages:
        msg = dict(raw)
        role = msg.get("role")

        if role != "tool" and pending:
            for call_id in pending:
                fixed.append(
                    {
                        "role": "tool",
                        "tool_call_id": call_id,
                        "content": "Operation interrupted or missing tool output.",
                    }
                )
            pending.clear()

        if role == "assistant":
            tool_calls = msg.get("tool_calls")
            if isinstance(tool_calls, list):
                for call in tool_calls:
                    if isinstance(call, Mapping):
                        call_id = str(call.get("id", "")).strip()
                        if call_id:
                            pending.append(call_id)

        if role == "tool":
            tool_call_id = str(msg.get("tool_call_id", "")).strip()
            if tool_call_id and tool_call_id in pending:
                pending.remove(tool_call_id)

        fixed.append(msg)

    for call_id in pending:
        fixed.append(
            {
                "role": "tool",
                "tool_call_id": call_id,
                "content": "Operation interrupted or missing tool output.",
            }
        )

    return fixed


# ---------------------------------------------------------------------------
# Streaming compatibility helpers
# ---------------------------------------------------------------------------

class _NullLive:
    """Minimal live-panel stand-in used by compatibility shims."""

    def update(self, *_: Any, **__: Any) -> None:
        return

    def stop(self) -> None:
        return


def create_agent_streaming_context(agent_name: str, counter: int, model: Any) -> dict[str, Any]:
    """Create a lightweight streaming context for an agent response."""
    context = {
        "id": f"{agent_name}:{counter}:{uuid.uuid4().hex[:8]}",
        "agent_name": agent_name,
        "counter": counter,
        "model": get_model_name(model),
        "content": "",
        "live": _NullLive(),
        "is_started": True,
        "start_time": time.time(),
    }
    if not hasattr(create_agent_streaming_context, "_active_streaming"):
        create_agent_streaming_context._active_streaming = {}  # type: ignore[attr-defined]
    create_agent_streaming_context._active_streaming[context["id"]] = context  # type: ignore[attr-defined]
    return context


def update_agent_streaming_content(
    context: MutableMapping[str, Any], text_delta: str, token_stats: Mapping[str, Any] | None = None
) -> None:
    """Update in-memory streaming text buffer."""
    context["content"] = f"{context.get('content', '')}{text_delta}"


def finish_agent_streaming(context: MutableMapping[str, Any], final_stats: Mapping[str, Any] | None = None) -> None:
    """Finalize streaming context and cleanup active registry."""
    context["is_started"] = False
    live = context.get("live")
    stop = getattr(live, "stop", None)
    if callable(stop):
        stop()
    active = getattr(create_agent_streaming_context, "_active_streaming", None)
    if isinstance(active, MutableMapping):
        active.pop(context.get("id"), None)


def start_tool_streaming(
    tool_name: str,
    args: Any,
    call_id: str | None = None,
    token_info: Mapping[str, Any] | None = None,
) -> str:
    """Start a tool streaming session and return call identifier."""
    call_id = call_id or uuid.uuid4().hex
    if not hasattr(cli_print_tool_output, "_streaming_sessions"):
        cli_print_tool_output._streaming_sessions = {}  # type: ignore[attr-defined]
    cli_print_tool_output._streaming_sessions[call_id] = {  # type: ignore[attr-defined]
        "tool_name": tool_name,
        "args": args,
        "current_output": "",
        "is_complete": False,
        "agent_name": (token_info or {}).get("agent_name"),
    }
    _LIVE_STREAMING_PANELS[call_id] = {"type": "static", "tool_name": tool_name}
    return call_id


def update_tool_streaming(
    tool_name: str,
    args: Any,
    output: Any,
    call_id: str,
    token_info: Mapping[str, Any] | None = None,
) -> None:
    """Update buffered output for an active tool streaming session."""
    sessions = getattr(cli_print_tool_output, "_streaming_sessions", {})
    if call_id in sessions:
        sessions[call_id]["current_output"] = "" if output is None else str(output)


def finish_tool_streaming(
    tool_name: str,
    args: Any,
    output: Any,
    call_id: str,
    execution_info: Mapping[str, Any] | None = None,
    token_info: Mapping[str, Any] | None = None,
) -> None:
    """Finalize tool streaming and emit final output."""
    sessions = getattr(cli_print_tool_output, "_streaming_sessions", {})
    if call_id in sessions:
        sessions[call_id]["is_complete"] = True
    _LIVE_STREAMING_PANELS.pop(call_id, None)
    cli_print_tool_output(
        tool_name=tool_name,
        args=args,
        output=output,
        streaming=False,
        execution_info=execution_info,
        token_info=token_info,
    )


def cleanup_all_streaming_resources() -> None:
    """Reset in-memory streaming registries."""
    _LIVE_STREAMING_PANELS.clear()
    _CLAUDE_THINKING_PANELS.clear()
    if hasattr(cli_print_tool_output, "_streaming_sessions"):
        cli_print_tool_output._streaming_sessions.clear()  # type: ignore[attr-defined]


def cleanup_agent_streaming_resources(agent_name: str) -> None:
    """Remove active streaming sessions for a specific agent."""
    sessions = getattr(cli_print_tool_output, "_streaming_sessions", {})
    drop_ids = [sid for sid, data in sessions.items() if data.get("agent_name") == agent_name]
    for sid in drop_ids:
        sessions.pop(sid, None)
        _LIVE_STREAMING_PANELS.pop(sid, None)


# ---------------------------------------------------------------------------
# Claude/deep reasoning display compatibility
# ---------------------------------------------------------------------------

def create_claude_thinking_context(agent_name: str, counter: int, model: Any) -> dict[str, Any]:
    """Create a context used to capture reasoning stream snippets."""
    context = {
        "id": f"thinking:{agent_name}:{counter}:{uuid.uuid4().hex[:6]}",
        "agent_name": agent_name,
        "counter": counter,
        "model": get_model_name(model),
        "buffer": [],
        "live": _NullLive(),
        "is_started": True,
    }
    _CLAUDE_THINKING_PANELS[context["id"]] = context
    return context


def update_claude_thinking_content(context: MutableMapping[str, Any], thinking_delta: str) -> None:
    """Append model reasoning text to the active thinking context."""
    buffer = context.setdefault("buffer", [])
    if isinstance(buffer, list):
        buffer.append(thinking_delta)


def finish_claude_thinking_display(context: MutableMapping[str, Any]) -> None:
    """Finalize thinking display and emit a compact debug trace."""
    context["is_started"] = False
    context_id = str(context.get("id", ""))
    _CLAUDE_THINKING_PANELS.pop(context_id, None)


def detect_claude_thinking_in_stream(model_name: str) -> bool:
    """Detect whether a model is expected to stream reasoning text."""
    lower = str(model_name).lower()
    return "claude" in lower or "deepseek" in lower


def print_claude_reasoning_simple(reasoning_content: str, agent_name: str, model_name: str) -> None:
    """Fallback reasoning logger for non-rich environments."""
    print(f"[thinking:{agent_name}:{model_name}] {reasoning_content}")


def start_claude_thinking_if_applicable(model_name: str, agent_name: str, counter: int) -> dict[str, Any] | None:
    """Create reasoning context only for supported models in streaming mode."""
    if os.getenv("CERBERUS_STREAM", "false").strip().lower() != "true":
        return None
    if not detect_claude_thinking_in_stream(model_name):
        return None
    return create_claude_thinking_context(agent_name, counter, model_name)


# ---------------------------------------------------------------------------
# Convenience helpers and compatibility stubs
# ---------------------------------------------------------------------------

def get_language_from_code_block(lang_identifier: str | None) -> str:
    """Normalize markdown code block language identifiers."""
    if not lang_identifier:
        return "text"
    normalized = re.sub(r"[^a-zA-Z0-9_+-]", "", lang_identifier).lower()
    return normalized or "text"


def check_flag(output: str, ctf: Any, challenge: Any = None) -> bool:
    """Compatibility stub used by CTF helpers."""
    candidate = str(output or "")
    return "flag{" in candidate.lower()


def setup_ctf() -> dict[str, Any]:
    """Compatibility stub for legacy CTF setup flows."""
    return {"status": "ready"}


# Aliases kept for old call patterns.
def signal_handler(signum: int, frame: Any) -> None:  # pragma: no cover - signal callback
    """Signal handler compatibility wrapper."""
    cleanup_all_streaming_resources()
    raise KeyboardInterrupt()

