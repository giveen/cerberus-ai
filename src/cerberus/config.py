from __future__ import annotations

from copy import deepcopy
from functools import lru_cache
from typing import Any

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from cerberus.mcp_bootstrap import ManagedMCPServerSettings, default_managed_mcp_servers


_DEFAULT_SAST_PHASE_RULES: dict[str, list[dict[str, Any]]] = {
    "config_review": [
        {
            "name": "Cleartext Allowed",
            "pattern": r"cleartextTrafficPermitted\s*=\s*\"?true\"?",
            "cwe": "CWE-319",
            "owasp": "M3: Insecure Communication",
            "impact": 8.0,
            "category": "Config",
        },
        {
            "name": "Debuggable Build",
            "pattern": r"android:debuggable\s*=\s*\"true\"",
            "cwe": "CWE-489",
            "owasp": "M8: Security Misconfiguration",
            "impact": 7.0,
            "category": "Config",
        },
    ],
    "crypto_check": [
        {
            "name": "Weak Hash",
            "pattern": r"MessageDigest\.getInstance\(\s*\"(?:MD5|SHA1?)\"\s*\)",
            "cwe": "CWE-327",
            "owasp": "M5: Insufficient Cryptography",
            "impact": 8.0,
            "category": "Crypto",
        },
        {
            "name": "Hardcoded Key",
            "pattern": r"(?:secret|api|token|key)[a-zA-Z0-9_\-]*\s*=\s*\"[A-Za-z0-9_\-+/=]{12,}\"",
            "cwe": "CWE-321",
            "owasp": "M5: Insufficient Cryptography",
            "impact": 9.0,
            "category": "Crypto",
        },
    ],
    "data_flow": [
        {
            "name": "Sensitive Logging",
            "pattern": r"Log\.(?:d|i|w|e)\([^\)]*(?:password|token|secret|session)",
            "cwe": "CWE-532",
            "owasp": "M2: Insecure Data Storage",
            "impact": 7.0,
            "category": "Flow",
        },
        {
            "name": "External Storage Sensitive",
            "pattern": r"getExternalStorageDirectory\(\)|MODE_WORLD_READABLE",
            "cwe": "CWE-312",
            "owasp": "M2: Insecure Data Storage",
            "impact": 8.0,
            "category": "Flow",
        },
    ],
    "permission_audit": [
        {
            "name": "High-Risk Permission",
            "pattern": r"android\.permission\.(?:READ_SMS|READ_CONTACTS|RECORD_AUDIO|READ_CALL_LOG)",
            "cwe": "CWE-250",
            "owasp": "M6: Insecure Authorization",
            "impact": 6.0,
            "category": "Permission",
        },
        {
            "name": "Broad Storage Access",
            "pattern": r"android\.permission\.(?:MANAGE_EXTERNAL_STORAGE|WRITE_EXTERNAL_STORAGE)",
            "cwe": "CWE-284",
            "owasp": "M8: Security Misconfiguration",
            "impact": 6.5,
            "category": "Permission",
        },
    ],
}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Model/runtime context controls.
    max_token_window: int = Field(
        default=4096,
        validation_alias=AliasChoices("CERBERUS_MAX_TOKEN_WINDOW", "CERBERUS_MAX_CONTEXT_TOKENS"),
    )

    # Tier policy thresholds.
    risk_tier_min: int = 1
    risk_tier_max: int = 4
    auto_approve_max_tier: int = 2
    elevated_logged_min_tier: int = 3
    manual_approval_tier: int = 4
    tier4_tool_names: tuple[str, ...] = (
        "generic_linux_command",
        "run_metasploit",
        "nmap_scan",
        "nmap",
    )

    # CASA/SAST phase rule catalog.
    sast_phase_rules: dict[str, list[dict[str, Any]]] = Field(default_factory=lambda: deepcopy(_DEFAULT_SAST_PHASE_RULES))

    # Infrastructure/runtime environment mappings.
    redis_url: str = Field(default="redis://localhost:6379", validation_alias=AliasChoices("REDIS_URL", "CERBERUS_REDIS_URL"))
    active_container: str = Field(default="", validation_alias=AliasChoices("CERBERUS_ACTIVE_CONTAINER", "CEREBRO_ACTIVE_CONTAINER"))
    log_level: str = Field(default="INFO", validation_alias=AliasChoices("LOG_LEVEL", "CERBERUS_LOG_LEVEL"))
    mcp_autoload_enabled: bool = Field(
        default=False,
        validation_alias=AliasChoices("CERBERUS_MCP_AUTOLOAD_ENABLED", "CEREBRO_MCP_AUTOLOAD_ENABLED"),
    )
    mcp_bootstrap_root: str = Field(
        default="",
        validation_alias=AliasChoices("CERBERUS_MCP_BOOTSTRAP_ROOT", "CEREBRO_MCP_BOOTSTRAP_ROOT"),
    )
    mcp_managed_servers: list[ManagedMCPServerSettings] = Field(
        default_factory=default_managed_mcp_servers,
        validation_alias=AliasChoices("CERBERUS_MCP_SERVERS", "CEREBRO_MCP_SERVERS"),
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
