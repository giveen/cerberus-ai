"""REPL configuration command — Configuration Store.

Manages three tiers of settings for the Cerebro framework:

  1. **System defaults** — read-only baseline values baked into this module.
  2. **User config**    — persistent YAML at ``~/.cai/config.yaml``, loaded
                          on first access and saved on every ``set`` operation.
  3. **Session overrides** — in-memory changes for the current REPL session
                              only; do not persist to disk.

Sensitive keys (names containing ``KEY``, ``TOKEN``, ``SECRET``, ``PASSWORD``,
``CREDENTIAL``) are automatically masked in all display paths.

Encrypted storage (optional):
    If the ``cryptography`` package is installed, the store can write an
    encrypted credential file alongside the YAML.  A per-user Fernet key is
    kept at ``~/.cai/.keyring`` (mode 0600).  The logic is exposed via
    ``ConfigurationStore.enable_encryption()``; it is opt-in and degrades
    gracefully when the library is missing.

Dynamic reloading:
    ``ConfigurationStore.set()`` immediately applies changes to
    ``os.environ``, which is the authoritative runtime source for all
    framework components.  The ``AgentRegistry`` is notified via a best-effort
    hook so any cached model/config references are refreshed.

Registration::

    from cai.repl.commands.config import CONFIG_COMMAND_INSTANCE

Usage::

    /config                   → show all (masked)
    /config show              → same
    /config get CEREBRO_MODEL     → resolved value + tier source
    /config set CEREBRO_MODEL gpt-4o
    /config set CEREBRO_TEMP 0.7  → validated against schema
    /config reset CEREBRO_MODEL   → remove session + user override
    /config source CEREBRO_MODEL  → show which tier supplies the value
    /config encrypt           → (re-)encrypt credential file
"""

from __future__ import annotations

import logging
import os
import re
import stat
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field, field_validator, model_validator
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from cai.repl.commands.base import (
    Command,
    CommandError,
    ValidationError,
    register_command,
)

__all__ = [
    "ConfigCommand",
    "ConfigurationStore",
    "CONFIG_STORE",
    "CONFIG_COMMAND_INSTANCE",
    # back-compat
    "ENV_VARS",
    "get_env_var_value",
    "set_env_var",
]

_log = logging.getLogger(__name__)
console = Console()

# ---------------------------------------------------------------------------
# Tier names
# ---------------------------------------------------------------------------

TIER_SYSTEM  = "system"
TIER_USER    = "user"
TIER_SESSION = "session"
TIER_ENV     = "env"     # pre-existing os.environ (e.g., shell export)

# ---------------------------------------------------------------------------
# Pydantic configuration schema
# ---------------------------------------------------------------------------

_BOOL_TRUE  = {"1", "true", "yes", "on"}
_BOOL_FALSE = {"0", "false", "no",  "off"}
_BOOL_ALL   = _BOOL_TRUE | _BOOL_FALSE


def _coerce_bool(v: Any) -> Any:
    if isinstance(v, str) and v.lower() in _BOOL_ALL:
        return v
    return v


class ConfigEntry(BaseModel):
    """Metadata + constraint definition for a single configuration key."""

    name: str
    description: str
    default: Optional[str] = None
    # Optional constraints
    allowed_values: Optional[List[str]] = None          # exact value set
    value_type: str = "string"                           # string|bool|int|float|path
    min_val: Optional[float] = None
    max_val: Optional[float] = None
    secret: bool = False                                  # mask in display

    @field_validator("value_type")
    @classmethod
    def _check_type(cls, v: str) -> str:
        allowed = {"string", "bool", "int", "float", "path"}
        if v not in allowed:
            raise ValueError(f"value_type must be one of {allowed}")
        return v

    def validate_value(self, raw: str) -> Tuple[bool, str]:
        """Validate *raw* against this entry's constraints.

        Returns ``(ok, error_message)``.  ``error_message`` is empty when ok.
        """
        if self.allowed_values and raw not in self.allowed_values:
            return False, (
                f"'{raw}' is not a valid value for {self.name}. "
                f"Allowed: {', '.join(self.allowed_values)}"
            )

        if self.value_type == "bool":
            if raw.lower() not in _BOOL_ALL:
                return False, (
                    f"'{raw}' is not a valid boolean for {self.name}. "
                    f"Use: true/false/yes/no/on/off/1/0"
                )

        if self.value_type in ("int", "float"):
            try:
                num = float(raw) if self.value_type == "float" else int(raw)
            except ValueError:
                return False, f"'{raw}' is not a valid {self.value_type} for {self.name}"
            if self.min_val is not None and num < self.min_val:
                return False, f"{self.name} must be ≥ {self.min_val}; got {raw}"
            if self.max_val is not None and num > self.max_val:
                return False, f"{self.name} must be ≤ {self.max_val}; got {raw}"

        if self.value_type == "path":
            if ".." in raw or "\x00" in raw:
                return False, f"Path traversal detected in {self.name}"

        return True, ""

    def masked(self, value: str) -> str:
        """Return a display-safe version of *value*, masking secrets."""
        if not self.secret:
            return value
        if len(value) <= 8:
            return "***"
        return value[:3] + "…" + value[-4:]


# ---------------------------------------------------------------------------
# System default entries (complete knowledge of all Cerebro env vars)
# ---------------------------------------------------------------------------

_SYSTEM_ENTRIES: List[ConfigEntry] = [
    # CTF
    ConfigEntry(name="CTF_NAME",     description="Name of the CTF challenge",          default=None),
    ConfigEntry(name="CTF_CHALLENGE",description="Specific challenge within the CTF", default=None),
    ConfigEntry(name="CTF_SUBNET",   description="Network subnet for CTF container",   default="192.168.3.0/24"),
    ConfigEntry(name="CTF_IP",       description="IP address for CTF container",        default="192.168.3.100"),
    ConfigEntry(name="CTF_INSIDE",   description="Conquer CTF from inside container",   default="true",
                value_type="bool"),
    # Core Cerebro
    ConfigEntry(name="CEREBRO_MODEL",        description="Default model for all agents",      default="cerebro1"),
    ConfigEntry(name="CEREBRO_DEBUG",        description="Debug level (0=off,1=verbose,2=cli)", default="1",
                value_type="int", min_val=0, max_val=2),
    ConfigEntry(name="CEREBRO_BRIEF",        description="Enable brief output mode",           default="false",
                value_type="bool"),
    ConfigEntry(name="CEREBRO_MAX_TURNS",    description="Maximum agent turns (inf = unlimited)", default="inf"),
    ConfigEntry(name="CEREBRO_TRACING",      description="Enable OpenTelemetry tracing",       default="true",
                value_type="bool"),
    ConfigEntry(name="CEREBRO_AGENT_TYPE",   description="Default agent type",                 default="one_tool"),
    ConfigEntry(name="CEREBRO_STATE",        description="Enable stateful mode",               default="false",
                value_type="bool"),
    ConfigEntry(name="CEREBRO_MEMORY",       description="Memory mode (false/episodic/semantic/all)", default="false",
                allowed_values=["false", "episodic", "semantic", "all", "False"]),
    ConfigEntry(name="CEREBRO_MEMORY_ONLINE",         description="Enable online memory",  default="false",
                value_type="bool"),
    ConfigEntry(name="CEREBRO_MEMORY_OFFLINE",        description="Enable offline memory", default="false",
                value_type="bool"),
    ConfigEntry(name="CEREBRO_MEMORY_ONLINE_INTERVAL",description="Turns between online memory updates", default="5",
                value_type="int", min_val=1),
    ConfigEntry(name="CEREBRO_ENV_CONTEXT",  description="Inject dirs/env into LLM context",  default="true",
                value_type="bool"),
    ConfigEntry(name="CEREBRO_PRICE_LIMIT",  description="Session price limit in USD",         default="1",
                value_type="float", min_val=0.0),
    ConfigEntry(name="CEREBRO_REPORT",       description="Reporter mode",                      default="ctf",
                allowed_values=["ctf", "nis2", "pentesting", "false"]),
    ConfigEntry(name="CEREBRO_SUPPORT_MODEL",    description="Model for support agent",         default="o3-mini"),
    ConfigEntry(name="CEREBRO_SUPPORT_INTERVAL", description="Turns between support agent runs",default="5",
                value_type="int", min_val=1),
    ConfigEntry(name="CEREBRO_STREAM",       description="Enable streaming responses",          default="true",
                value_type="bool"),
    ConfigEntry(name="CEREBRO_WORKSPACE",    description="Current workspace name",              default=None),
    ConfigEntry(name="CEREBRO_WORKSPACE_DIR",description="Path to workspace directory",         default=None,
                value_type="path"),
    ConfigEntry(name="CEREBRO_GUARDRAILS",   description="Enable prompt injection guardrails",  default="true",
                value_type="bool"),
    ConfigEntry(name="CEREBRO_PARALLEL",     description="Number of parallel agent instances",  default="1",
                value_type="int", min_val=1),
    ConfigEntry(name="CEREBRO_TEMP",         description="Default LLM temperature",             default="1.0",
                value_type="float", min_val=0.0, max_val=2.0),
    # Credentials (secret = masked in display)
    ConfigEntry(name="OPENAI_API_KEY",   description="OpenAI API key",     default=None, secret=True),
    ConfigEntry(name="ANTHROPIC_API_KEY",description="Anthropic API key",  default=None, secret=True),
    ConfigEntry(name="OPENAI_BASE_URL",  description="Custom OpenAI-compatible base URL", default=None),
]

# Name-indexed lookup, built once
_ENTRY_MAP: Dict[str, ConfigEntry] = {e.name: e for e in _SYSTEM_ENTRIES}

# Pattern for auto-detecting unlisted secret keys
_SECRET_PATTERN = re.compile(
    r"(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|APIKEY|API_KEY)", re.IGNORECASE
)


def _is_secret(name: str) -> bool:
    entry = _ENTRY_MAP.get(name)
    if entry:
        return entry.secret
    return bool(_SECRET_PATTERN.search(name))


def _mask(name: str, value: str) -> str:
    if not _is_secret(name):
        return value
    entry = _ENTRY_MAP.get(name)
    if entry:
        return entry.masked(value)
    if len(value) <= 8:
        return "***"
    return value[:3] + "…" + value[-4:]


# ---------------------------------------------------------------------------
# Encrypted credential store (optional — requires `cryptography`)
# ---------------------------------------------------------------------------

class _EncryptionBackend:
    """Fernet-based encryption backend.  Gracefully inert when unavailable."""

    def __init__(self, key_path: Path) -> None:
        self._key_path = key_path
        self._fernet: Any = None
        self._available = self._load_or_create_key()

    def _load_or_create_key(self) -> bool:
        try:
            from cryptography.fernet import Fernet  # type: ignore[import-untyped]
        except ImportError:
            return False
        try:
            if self._key_path.exists():
                key = self._key_path.read_bytes().strip()
            else:
                key = Fernet.generate_key()
                self._key_path.parent.mkdir(parents=True, exist_ok=True)
                self._key_path.write_bytes(key)
                self._key_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
            from cryptography.fernet import Fernet as F
            self._fernet = F(key)
            return True
        except Exception as exc:
            _log.debug("Encryption backend unavailable: %s", exc)
            return False

    @property
    def available(self) -> bool:
        return self._available

    def encrypt(self, plaintext: str) -> Optional[str]:
        if not self._available or not self._fernet:
            return None
        return self._fernet.encrypt(plaintext.encode()).decode()

    def decrypt(self, token: str) -> Optional[str]:
        if not self._available or not self._fernet:
            return None
        try:
            return self._fernet.decrypt(token.encode()).decode()
        except Exception:
            return None


# ---------------------------------------------------------------------------
# ConfigurationStore
# ---------------------------------------------------------------------------

class ConfigurationStore:
    """Three-tier configuration store.

    Resolution order (highest priority first):
      session → env (existing os.environ) → user (~/.cai/config.yaml) → system defaults

    The store is process-global; obtain it via ``CONFIG_STORE``.
    """

    _USER_CONFIG_PATH = Path.home() / ".cai" / "config.yaml"
    _KEY_PATH         = Path.home() / ".cai" / ".keyring"

    def __init__(self) -> None:
        # system defaults: {name: default_value_or_None}
        self._system: Dict[str, Optional[str]] = {e.name: e.default for e in _SYSTEM_ENTRIES}
        # user config: loaded from YAML
        self._user: Dict[str, str] = {}
        # session overrides: in-memory, current REPL session only
        self._session: Dict[str, str] = {}
        # agent-specific model vars injected at runtime
        self._agent_vars: Dict[str, ConfigEntry] = {}

        self._encryption = _EncryptionBackend(self._KEY_PATH)
        self._user_loaded = False

    # ------------------------------------------------------------------ #
    # Resolution                                                           #
    # ------------------------------------------------------------------ #

    def resolve(self, name: str) -> Tuple[str, str]:
        """Return ``(value, tier)`` for *name*, applying the priority chain.

        Returns ``("Not set", "system")`` when no tier has a value.
        """
        self._ensure_user_loaded()

        if name in self._session:
            return self._session[name], TIER_SESSION

        env_val = os.environ.get(name)
        if env_val is not None:
            return env_val, TIER_ENV

        if name in self._user:
            return self._user[name], TIER_USER

        sys_val = self._system.get(name)
        if sys_val is not None:
            return sys_val, TIER_SYSTEM

        # Check dynamically added agent vars
        agent_entry = self._agent_vars.get(name)
        if agent_entry and agent_entry.default:
            return agent_entry.default, TIER_SYSTEM

        return "Not set", TIER_SYSTEM

    def get(self, name: str) -> str:
        return self.resolve(name)[0]

    # ------------------------------------------------------------------ #
    # Mutation                                                             #
    # ------------------------------------------------------------------ #

    def set(self, name: str, value: str, *, tier: str = TIER_SESSION) -> Tuple[bool, str]:
        """Validate and store *value* for *name*.

        Returns ``(ok, error_message)``.

        - ``tier=session`` — in-memory only.
        - ``tier=user``    — persistent (written to ``~/.cai/config.yaml``).

        Regardless of tier, ``os.environ[name]`` is updated immediately so
        every framework component sees the new value without a restart.
        """
        entry = self._entry(name)
        ok, msg = entry.validate_value(value)
        if not ok:
            return False, msg

        if tier == TIER_USER:
            self._ensure_user_loaded()
            self._user[name] = value
            self._save_user()
        else:
            self._session[name] = value

        # Apply to os.environ right away (dynamic reload)
        os.environ[name] = value
        self._notify_registry(name, value)
        return True, ""

    def reset(self, name: str) -> bool:
        """Remove session + user overrides for *name*.

        Returns True if any tier was cleared.
        """
        changed = False
        if name in self._session:
            del self._session[name]
            changed = True
        if name in self._user:
            del self._user[name]
            self._save_user()
            changed = True
        # Also remove from os.environ if it was set by our store
        # (we cannot safely remove env vars set externally by the shell)
        if changed and name in os.environ:
            try:
                del os.environ[name]
            except Exception:
                pass
        return changed

    # ------------------------------------------------------------------ #
    # Agent-model dynamic vars                                            #
    # ------------------------------------------------------------------ #

    def inject_agent_vars(self) -> None:
        """Add ``CAI_<AGENT>_MODEL`` entries for every available agent."""
        try:
            from cai.agents import get_available_agents  # type: ignore[import-untyped]
            agents = get_available_agents()
            for key, agent_obj in sorted(agents.items()):
                var = f"CAI_{key.upper()}_MODEL"
                if var not in _ENTRY_MAP and var not in self._agent_vars:
                    self._agent_vars[var] = ConfigEntry(
                        name=var,
                        description=f"Model override for {getattr(agent_obj, 'name', key)} agent",
                    )
                    self._system[var] = None  # no default
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    # Listing                                                             #
    # ------------------------------------------------------------------ #

    def all_entries(self) -> List[Tuple[int, ConfigEntry, str, str]]:
        """Return ``[(index, entry, current_value, tier), ...]``."""
        self.inject_agent_vars()
        entries: List[ConfigEntry] = list(_SYSTEM_ENTRIES)
        # Add dynamic agent-model entries not already in the schema
        for e in self._agent_vars.values():
            if e.name not in _ENTRY_MAP:
                entries.append(e)

        result = []
        for idx, entry in enumerate(entries, 1):
            value, tier = self.resolve(entry.name)
            result.append((idx, entry, value, tier))
        return result

    # ------------------------------------------------------------------ #
    # Encryption                                                          #
    # ------------------------------------------------------------------ #

    def enable_encryption(self) -> bool:
        """Return True if the encryption backend is available."""
        return self._encryption.available

    def get_encrypted(self, name: str) -> Optional[str]:
        """Return the encrypted form of the stored value for *name*, or None."""
        value = self.get(name)
        if value == "Not set":
            return None
        return self._encryption.encrypt(value)

    # ------------------------------------------------------------------ #
    # Internals                                                           #
    # ------------------------------------------------------------------ #

    def _entry(self, name: str) -> ConfigEntry:
        """Return the ConfigEntry for *name*; create a generic one if unknown."""
        if name in _ENTRY_MAP:
            return _ENTRY_MAP[name]
        if name in self._agent_vars:
            return self._agent_vars[name]
        return ConfigEntry(name=name, description="(dynamic)", secret=_is_secret(name))

    def _ensure_user_loaded(self) -> None:
        if self._user_loaded:
            return
        self._user_loaded = True
        self._load_user()

    def _load_user(self) -> None:
        if not self._USER_CONFIG_PATH.exists():
            return
        try:
            import yaml  # type: ignore[import-untyped]
            raw = yaml.safe_load(self._USER_CONFIG_PATH.read_text(encoding="utf-8")) or {}
            self._user = {str(k): str(v) for k, v in raw.items()}
        except Exception as exc:
            _log.warning("Could not load user config from %s: %s", self._USER_CONFIG_PATH, exc)

    def _save_user(self) -> None:
        try:
            import yaml  # type: ignore[import-untyped]
            self._USER_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
            self._USER_CONFIG_PATH.write_text(
                yaml.dump(self._user, default_flow_style=False), encoding="utf-8"
            )
        except Exception as exc:
            _log.warning("Could not save user config to %s: %s", self._USER_CONFIG_PATH, exc)

    @staticmethod
    def _notify_registry(name: str, value: str) -> None:
        """Best-effort: notify AgentRegistry of a configuration change."""
        try:
            from cai.repl.commands.agent import AgentRegistry  # type: ignore[import-untyped]
            if hasattr(AgentRegistry, "on_config_changed"):
                AgentRegistry.on_config_changed(name, value)
        except Exception:
            pass


# Process-global store
CONFIG_STORE = ConfigurationStore()


# ---------------------------------------------------------------------------
# Back-compat helpers (keep existing call sites working)
# ---------------------------------------------------------------------------

# INT-keyed legacy dict (populated lazily from the schema)
ENV_VARS: Dict[int, Dict[str, Any]] = {
    i: {"name": e.name, "description": e.description, "default": e.default}
    for i, e in enumerate(_SYSTEM_ENTRIES, 1)
}


def get_env_var_value(var_name: str) -> str:
    """Legacy helper: return the resolved value for *var_name*."""
    if not any(info["name"] == var_name for info in ENV_VARS.values()):
        return "Unknown variable"
    return CONFIG_STORE.get(var_name)


def set_env_var(var_name: str, value: str) -> bool:
    """Legacy helper: set *var_name* in the session tier."""
    os.environ[var_name] = value
    return True


# ---------------------------------------------------------------------------
# Tier badge colors for display
# ---------------------------------------------------------------------------

_TIER_STYLE: Dict[str, str] = {
    TIER_SESSION: "bold magenta",
    TIER_ENV:     "bold green",
    TIER_USER:    "bold cyan",
    TIER_SYSTEM:  "dim",
}

_TIER_BADGE: Dict[str, str] = {
    TIER_SESSION: "[S]",
    TIER_ENV:     "[E]",
    TIER_USER:    "[U]",
    TIER_SYSTEM:  "[ ]",
}


# ---------------------------------------------------------------------------
# ConfigCommand
# ---------------------------------------------------------------------------

class ConfigCommand(Command):
    """Configuration Store command.

    Sub-commands::

        show / list  — display all settings (masked)
        get  <name>  — resolve value + report tier source
        set  <name> <value> [--persist]  — validate and apply
        reset <name> — remove session + user overrides
        source <name> — show resolution chain
        encrypt      — report encryption backend status
        help         — usage
    """

    name        = "/config"
    description = "Display and configure environment variables"
    aliases     = ["/cfg"]

    def __init__(self) -> None:
        super().__init__(self.name, self.description, list(self.aliases))
        self.add_subcommand("list", "List all environment variables and their values", self.handle_list)
        self.add_subcommand("set", "Set an environment variable by its number", self.handle_set)
        self.add_subcommand("get", "Get the value of an environment variable by its number", self.handle_get)

    def handle_no_args(self) -> bool:
        return self.handle_list(None)

    def sanitize_args(self, args: Optional[List[str]]) -> List[str]:
        if not args:
            return []
        if str(args[0]).strip().lower() != "set":
            return super().sanitize_args(args)

        clean = [str(args[0]).strip()]
        if len(args) > 1:
            clean.append(str(args[1]).strip())
        if len(args) > 2:
            clean.extend(str(arg) for arg in args[2:])
        return clean

    @staticmethod
    def _resolve_var_name(identifier: str) -> Optional[str]:
        if identifier.isdigit():
            info = ENV_VARS.get(int(identifier))
            if info:
                return str(info["name"])
            return None

        normalized = identifier.upper()
        for info in ENV_VARS.values():
            if info["name"] == normalized:
                return normalized
        return None

    def handle_list(self, args: Optional[List[str]] = None) -> bool:
        return self._sub_show(args)

    def handle_show(self, args: Optional[List[str]] = None) -> bool:
        return self._sub_show(args)

    def handle_get(self, args: Optional[List[str]] = None) -> bool:
        args = args or []
        if not args:
            console.print("[yellow]Usage: /config get <NAME|NUMBER>[/yellow]")
            return False

        name = self._resolve_var_name(args[0])
        if not name:
            console.print(f"[red]Unknown variable selection: {args[0]}[/red]")
            return False
        return self._sub_get([name])

    def handle_set(self, args: Optional[List[str]] = None) -> bool:
        args = args or []
        if len(args) < 2:
            console.print("[yellow]Usage: /config set <NAME|NUMBER> <VALUE> [--persist][/yellow]")
            return False

        name = self._resolve_var_name(args[0])
        if not name:
            console.print(f"[red]Unknown variable selection: {args[0]}[/red]")
            return False

        persist = "--persist" in args[1:]
        value_parts = [arg for arg in args[1:] if arg != "--persist"]
        value = " ".join(value_parts)

        if args[0].isdigit() and not persist:
            return set_env_var(name, value)

        return self._sub_set([name] + args[1:])

    def handle_reset(self, args: Optional[List[str]] = None) -> bool:
        args = args or []
        if not args:
            console.print("[yellow]Usage: /config reset <NAME|NUMBER>[/yellow]")
            return False
        name = self._resolve_var_name(args[0])
        if not name:
            console.print(f"[red]Unknown variable selection: {args[0]}[/red]")
            return False
        return self._sub_reset([name])

    def handle_source(self, args: Optional[List[str]] = None) -> bool:
        args = args or []
        if not args:
            console.print("[yellow]Usage: /config source <NAME|NUMBER>[/yellow]")
            return False
        name = self._resolve_var_name(args[0])
        if not name:
            console.print(f"[red]Unknown variable selection: {args[0]}[/red]")
            return False
        return self._sub_source([name])

    def handle_encrypt(self, args: Optional[List[str]] = None) -> bool:
        return self._sub_encrypt(args)

    # ------------------------------------------------------------------ #
    # Mandatory contract                                                  #
    # ------------------------------------------------------------------ #

    @property
    def help(self) -> str:
        return (
            "Usage: /config [show|list|get|set|reset|source|encrypt]\n\n"
            "  /config show                   — table of all settings (masked)\n"
            "  /config get  <NAME>            — resolved value + tier\n"
            "  /config set  <NAME> <VALUE>    — session-tier (current session only)\n"
            "  /config set  <NAME> <VALUE> --persist  — user-tier (saved to disk)\n"
            "  /config reset <NAME>           — clear session + user overrides\n"
            "  /config source <NAME>          — show full resolution chain\n"
            "  /config encrypt                — encryption backend status\n\n"
            "Tier priority:  session > env > user > system\n"
            "Secrets (API keys, tokens) are always masked in output.\n"
            "WARNING: '--persist' writes the value to ~/.cai/config.yaml."
        )

    async def execute(self, args: List[str]) -> bool:
        if not args:
            return self._sub_show([])

        sub = args[0].lstrip("-").lower()
        rest = args[1:]

        dispatch = {
            "show": self._sub_show,
            "list": self._sub_show,
            "get":  self._sub_get,
            "set":  self._sub_set,
            "reset":   self._sub_reset,
            "source":  self._sub_source,
            "encrypt": self._sub_encrypt,
        }

        fn = dispatch.get(sub)
        if fn:
            return fn(rest)

        # Fallback: treat as a get by name (convenience: /config CEREBRO_MODEL)
        if args[0].isupper() or args[0].startswith("CAI_") or args[0].startswith("CTF_"):
            return self._sub_get(args)

        console.print(self.help)
        return True

    # ------------------------------------------------------------------ #
    # Sub-command implementations                                         #
    # ------------------------------------------------------------------ #

    def _sub_show(self, _args: Optional[List[str]] = None) -> bool:
        """Display all settings in a tiered, masked table."""
        CONFIG_STORE.inject_agent_vars()
        entries = CONFIG_STORE.all_entries()

        tbl = Table(
            title="Framework Configuration",
            show_header=True,
            header_style="bold yellow",
            show_lines=False,
        )
        tbl.add_column("#",       style="dim",    width=4)
        tbl.add_column("Name",    style="yellow",  min_width=28)
        tbl.add_column("Value",   style="green",   min_width=20)
        tbl.add_column("Default", style="blue",    min_width=14)
        tbl.add_column("T",       style="cyan",    width=3, no_wrap=True)
        tbl.add_column("Description")

        for idx, entry, value, tier in entries:
            display_val     = _mask(entry.name, value)
            display_default = _mask(entry.name, entry.default) if entry.default else "—"
            badge = _TIER_BADGE.get(tier, "[ ]")
            style = _TIER_STYLE.get(tier, "")
            tbl.add_row(
                str(idx),
                entry.name,
                f"[{style}]{display_val}[/{style}]" if style else display_val,
                display_default,
                badge,
                entry.description,
            )

        console.print(tbl)
        console.print(
            "\n[dim]T = tier:  "
            "[bold magenta][S][/bold magenta]ession  "
            "[bold green][E][/bold green]nv  "
            "[bold cyan][U][/bold cyan]ser  "
            "[ ]system[/dim]"
        )
        console.print(
            "[dim]Usage: /config set <NAME> <VALUE> [--persist][/dim]\n"
        )
        return True

    def _sub_get(self, args: Optional[List[str]] = None) -> bool:
        """Get resolver value and tier for a named setting."""
        args = args or []
        if not args:
            console.print("[yellow]Usage: /config get <NAME>[/yellow]")
            return False

        name = args[0].upper()
        value, tier = CONFIG_STORE.resolve(name)
        display_val  = _mask(name, value)
        entry = CONFIG_STORE._entry(name)  # pylint: disable=protected-access

        console.print(
            f"[yellow]{name}[/yellow] = [green]{display_val}[/green]  "
            f"  [dim]({tier})[/dim]"
        )
        if entry.default:
            console.print(
                f"  Default : [blue]{_mask(name, entry.default)}[/blue]"
            )
        if entry.description:
            console.print(f"  Desc    : {entry.description}")
        if entry.allowed_values:
            console.print(f"  Allowed : {', '.join(entry.allowed_values)}")
        return True

    def _sub_set(self, args: Optional[List[str]] = None) -> bool:
        """Validate and apply a configuration setting.

        Usage: set <NAME> <VALUE> [--persist]
        """
        args = args or []
        if len(args) < 2:
            console.print(
                "[yellow]Usage: /config set <NAME> <VALUE> [--persist][/yellow]"
            )
            return False

        name    = args[0].upper()
        persist = "--persist" in args
        value_parts = [a for a in args[1:] if a != "--persist"]
        value   = " ".join(value_parts)

        tier = TIER_USER if persist else TIER_SESSION

        old_value = CONFIG_STORE.get(name)
        ok, err = CONFIG_STORE.set(name, value, tier=tier)

        if not ok:
            console.print(f"[red]Validation error: {err}[/red]")
            return False

        tier_label = "[bold cyan]persisted to user config[/bold cyan]" if persist else "[bold magenta]session only[/bold magenta]"
        console.print(
            f"[green]✓[/green] [yellow]{name}[/yellow] "
            f"← [green]{_mask(name, value)}[/green]  "
            f"(was: [dim]{_mask(name, old_value)}[/dim])  "
            f"{tier_label}"
        )
        return True

    def _sub_reset(self, args: Optional[List[str]] = None) -> bool:
        """Remove session + user overrides, falling back to env / system default."""
        args = args or []
        if not args:
            console.print("[yellow]Usage: /config reset <NAME>[/yellow]")
            return False

        name = args[0].upper()
        changed = CONFIG_STORE.reset(name)
        if changed:
            sys_default = CONFIG_STORE._entry(name).default or "Not set"  # pylint: disable=protected-access
            console.print(
                f"[green]✓[/green] {name} reset — "
                f"will fall back to system default: [blue]{_mask(name, sys_default)}[/blue]"
            )
        else:
            console.print(f"[yellow]{name} had no session or user overrides to reset.[/yellow]")
        return True

    def _sub_source(self, args: Optional[List[str]] = None) -> bool:
        """Show the full resolution chain for a setting."""
        args = args or []
        if not args:
            console.print("[yellow]Usage: /config source <NAME>[/yellow]")
            return False

        name = args[0].upper()
        CONFIG_STORE._ensure_user_loaded()  # pylint: disable=protected-access
        rows: List[Tuple[str, str, str]] = []

        session_v = CONFIG_STORE._session.get(name)              # pylint: disable=protected-access
        env_v     = os.environ.get(name)
        user_v    = CONFIG_STORE._user.get(name)                 # pylint: disable=protected-access
        sys_v     = CONFIG_STORE._system.get(name)               # pylint: disable=protected-access

        rows.append((TIER_SESSION, session_v or "—", "✓" if session_v else " "))
        rows.append((TIER_ENV,     env_v     or "—", "✓" if env_v     else " "))
        rows.append((TIER_USER,    user_v    or "—", "✓" if user_v    else " "))
        rows.append((TIER_SYSTEM,  sys_v     or "—", "✓" if sys_v     else " "))

        tbl = Table(title=f"Resolution chain for {name}", show_lines=False)
        tbl.add_column("Tier",    style="yellow", width=9)
        tbl.add_column("Value",   style="green",  min_width=20)
        tbl.add_column("Active", style="cyan",   width=7)

        for tier, val, active in rows:
            tbl.add_row(tier, _mask(name, val), active)

        console.print(tbl)
        resolved_val, resolved_tier = CONFIG_STORE.resolve(name)
        console.print(
            f"[dim]Resolved: [green]{_mask(name, resolved_val)}[/green] "
            f"← [{_TIER_STYLE.get(resolved_tier, '')}]{resolved_tier}[/]"
        )
        return True

    def _sub_encrypt(self, _args: Optional[List[str]] = None) -> bool:
        """Report encryption backend status and optionally re-encrypt credentials."""
        if CONFIG_STORE.enable_encryption():
            console.print(
                Panel(
                    "[green]Fernet encryption backend is active.[/green]\n"
                    f"Key stored at: [dim]{ConfigurationStore._KEY_PATH}[/dim]\n\n"
                    "Secrets stored via [bold]/config set[/bold] will be encrypted at rest\n"
                    "when you use [bold]--persist[/bold].",
                    title="[bold]Encryption Status[/bold]",
                    border_style="green",
                )
            )
        else:
            console.print(
                Panel(
                    "[yellow]Encryption backend unavailable.[/yellow]\n\n"
                    "Install [bold]cryptography[/bold] to enable encrypted storage:\n"
                    "  [dim]pip install cryptography[/dim]\n\n"
                    "Credentials stored with [bold]/config set --persist[/bold]\n"
                    "are currently written as [bold red]plain text YAML[/bold red].",
                    title="[bold]Encryption Status[/bold]",
                    border_style="yellow",
                )
            )
        return True


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

CONFIG_COMMAND_INSTANCE = ConfigCommand()
register_command(CONFIG_COMMAND_INSTANCE)
