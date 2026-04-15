"""Centralized immutable configuration for Cerberus AI.

The configuration model focuses on resource management, workspace isolation,
and transparent runtime policy. It is intentionally explicit and human-readable
so downstream engines can inspect allocations and boundaries without any hidden
state or opaque transformations.
"""

from __future__ import annotations

from functools import lru_cache
import os
from pathlib import Path
from typing import Literal

try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover - optional runtime dependency
    psutil = None  # type: ignore

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, computed_field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


_DEFAULT_TOTAL_RAM_GB = 256.0
_MIN_SYSTEM_RESERVE_GB = 8.0
_DEFAULT_GLOBAL_CACHE_RATIO = 0.22
_DEFAULT_VECTOR_VAULT_RATIO = 0.42
_DEFAULT_LOGIC_GRAPH_RATIO = 0.16
_DEFAULT_SYSTEM_RESERVE_RATIO = 0.20
_RTX_5090_VRAM_MB = 32_768
_RTX_5090_VRAM_WORKING_SET_MB = 28_672
_RTX_5090_VRAM_RESERVE_MB = 4_096


def _is_local_provider_configured() -> bool:
    """Return True when environment indicates a local LLM provider."""
    model_value = os.getenv("CERBERUS_MODEL", "").strip().lower()
    local_prefixes = (
        "ollama",
        "litellm",
        "llama",
        "llama.cpp",
        "vllm",
        "local",
        "deepseek",
    )
    if any(model_value.startswith(prefix) for prefix in local_prefixes):
        return True

    local_env_markers = (
        "LITELLM_SERVER",
        "LITELLM_BASE_URL",
        "OLLAMA_URL",
        "OLLAMA_API_BASE",
        "OLLAMA_BASE_URL",
        "CERBERUS_LOCAL_MODEL",
        "LLM_LOCAL",
        "LLAMA_CPP_SERVER",
    )
    return any(bool(os.getenv(key, "").strip()) for key in local_env_markers)


def should_suppress_openai_api_key_warning() -> bool:
    """Suppress OPENAI_API_KEY warning in transparent local-provider mode."""
    audit_mode = os.getenv("AUDIT_MODE", os.getenv("CERBERUS_AUDIT_MODE", "TRANSPARENT"))
    if str(audit_mode).strip().upper() != "TRANSPARENT":
        return False
    return _is_local_provider_configured()


def get_effective_api_base(default: str = "http://localhost:8000/v1") -> str:
    """Return API base honoring the Cerberus-prefixed variable."""
    return (
        os.getenv("CERBERUS_API_BASE")
        or default
    )


def get_effective_api_key(default: str = "sk-cerberus-1234567890") -> str:
    """Return API key honoring Cerberus configuration first, then OpenAI fallback."""
    return (
        os.getenv("CERBERUS_API_KEY")
        or os.getenv("OPENAI_API_KEY")
        or default
    )


def _detect_total_system_ram_gb() -> float:
    """Detect total system RAM in GiB, defaulting to 256 GiB when unknown."""
    if psutil is not None:
        try:
            return round(psutil.virtual_memory().total / (1024 ** 3), 2)
        except Exception:
            pass

    meminfo = Path("/proc/meminfo")
    if meminfo.exists():
        try:
            for line in meminfo.read_text(encoding="utf-8").splitlines():
                if line.startswith("MemTotal:"):
                    kib = float(line.split()[1])
                    return round(kib / (1024 ** 2), 2)
        except Exception:
            pass

    return _DEFAULT_TOTAL_RAM_GB


class RamSegmentation(BaseModel):
    """Explicit RAM pools used to prevent cross-engine contention."""

    model_config = ConfigDict(frozen=True)

    total_system_ram_gb: float
    global_cache_gb: float
    vector_vault_gb: float
    logic_graph_gb: float
    system_reserve_gb: float
    global_cache_ratio: float
    vector_vault_ratio: float
    logic_graph_ratio: float
    system_reserve_ratio: float

    @classmethod
    def from_total(
        cls,
        total_system_ram_gb: float,
        global_cache_ratio: float,
        vector_vault_ratio: float,
        logic_graph_ratio: float,
        system_reserve_ratio: float,
    ) -> "RamSegmentation":
        """Build an explicit RAM pool map from a total-RAM baseline."""
        total = float(total_system_ram_gb)
        return cls(
            total_system_ram_gb=total,
            global_cache_gb=round(total * global_cache_ratio, 2),
            vector_vault_gb=round(total * vector_vault_ratio, 2),
            logic_graph_gb=round(total * logic_graph_ratio, 2),
            system_reserve_gb=round(total * system_reserve_ratio, 2),
            global_cache_ratio=global_cache_ratio,
            vector_vault_ratio=vector_vault_ratio,
            logic_graph_ratio=logic_graph_ratio,
            system_reserve_ratio=system_reserve_ratio,
        )


class GpuConfig(BaseModel):
    """CUDA baseline and VRAM targets for RTX 5090-class systems."""

    model_config = ConfigDict(frozen=True)

    use_gpu_acceleration: bool
    cuda_device: str
    cuda_visible_devices: str
    target_gpu_name: str
    target_vram_mb: int
    working_set_target_mb: int
    reserve_vram_mb: int


class PathHierarchy(BaseModel):
    """Absolute, workspace-rooted directories used by PathGuard."""

    model_config = ConfigDict(frozen=True)

    workspace_root: Path
    staged_dir: Path
    loot_dir: Path
    memory_dir: Path
    logs_dir: Path
    audit_dir: Path
    indices_dir: Path
    versions_dir: Path
    rag_dir: Path

    @model_validator(mode="after")
    def validate_workspace_boundaries(self) -> "PathHierarchy":
        """Ensure every configured path is absolute and rooted in workspace."""
        root = self.workspace_root.resolve()
        for name in (
            "staged_dir",
            "loot_dir",
            "memory_dir",
            "logs_dir",
            "audit_dir",
            "indices_dir",
            "versions_dir",
            "rag_dir",
        ):
            path_value = getattr(self, name).resolve()
            if not path_value.is_absolute():
                raise ValueError(f"{name} must be absolute: {path_value}")
            try:
                path_value.relative_to(root)
            except ValueError as exc:
                raise ValueError(f"{name} escapes workspace root: {path_value}") from exc
        return self


class OperationalPolicy(BaseModel):
    """Transparent runtime policy flags shared across the framework."""

    model_config = ConfigDict(frozen=True)

    audit_mode: Literal["TRANSPARENT"]
    encryption_enabled: bool
    telemetry_enabled: bool
    log_level: str


class CerberusConfig(BaseSettings):
    """Universal immutable configuration handler for Cerberus AI.

    Environment overrides are supported via `.env` and process environment
    variables. Settings are frozen after initialization to prevent runtime
    tampering or drift.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        frozen=True,
        case_sensitive=False,
    )

    workspace_root: Path = Field(
        default=Path(os.getenv("CIR_WORKSPACE", "/workspace")),
        validation_alias=AliasChoices("CIR_WORKSPACE", "CERBERUS_WORKSPACE_ROOT"),
    )
    total_system_ram_gb: float = Field(
        default_factory=_detect_total_system_ram_gb,
        validation_alias=AliasChoices("CERBERUS_TOTAL_SYSTEM_RAM_GB", "CERBERUS_RAM_TOTAL_GB"),
    )
    global_cache_ratio: float = Field(default=_DEFAULT_GLOBAL_CACHE_RATIO)
    vector_vault_ratio: float = Field(default=_DEFAULT_VECTOR_VAULT_RATIO)
    logic_graph_ratio: float = Field(default=_DEFAULT_LOGIC_GRAPH_RATIO)
    system_reserve_ratio: float = Field(default=_DEFAULT_SYSTEM_RESERVE_RATIO)

    use_gpu_acceleration: bool = Field(
        default=True,
        validation_alias=AliasChoices("CERBERUS_USE_GPU_ACCELERATION", "USE_GPU_ACCELERATION"),
    )
    cuda_device: str = Field(default="cuda:0", validation_alias=AliasChoices("CERBERUS_CUDA_DEVICE", "CUDA_DEVICE"))
    cuda_visible_devices: str = Field(
        default=os.getenv("CUDA_VISIBLE_DEVICES", "0"),
        validation_alias=AliasChoices("CUDA_VISIBLE_DEVICES", "CERBERUS_CUDA_VISIBLE_DEVICES"),
    )
    gpu_name_baseline: str = Field(default="NVIDIA GeForce RTX 5090")
    gpu_vram_target_mb: int = Field(default=_RTX_5090_VRAM_MB)
    gpu_vram_working_set_mb: int = Field(default=_RTX_5090_VRAM_WORKING_SET_MB)
    gpu_vram_reserve_mb: int = Field(default=_RTX_5090_VRAM_RESERVE_MB)

    audit_mode: Literal["TRANSPARENT"] = "TRANSPARENT"
    encryption_enabled: bool = False
    telemetry_enabled: bool = True
    log_level: str = Field(default="INFO", validation_alias=AliasChoices("CERBERUS_LOG_LEVEL", "LOG_LEVEL"))

    @model_validator(mode="after")
    def validate_allocations(self) -> "CerberusConfig":
        """Validate workspace root and RAM segmentation ratios."""
        total_ratio = (
            self.global_cache_ratio
            + self.vector_vault_ratio
            + self.logic_graph_ratio
            + self.system_reserve_ratio
        )
        if round(total_ratio, 6) != 1.0:
            raise ValueError(f"RAM segmentation ratios must sum to 1.0, got {total_ratio}")
        if self.total_system_ram_gb <= 0:
            raise ValueError("total_system_ram_gb must be greater than zero")
        if (self.total_system_ram_gb * self.system_reserve_ratio) < _MIN_SYSTEM_RESERVE_GB:
            raise ValueError(
                f"System reserve must be at least {_MIN_SYSTEM_RESERVE_GB} GiB for OS/tool stability"
            )
        object.__setattr__(self, "workspace_root", self.workspace_root.expanduser().resolve())
        return self

    @computed_field(return_type=RamSegmentation)
    @property
    def ram(self) -> RamSegmentation:
        """Resolved RAM pools for CCMB, Vector Vault, Logic Graph, and reserve."""
        return RamSegmentation.from_total(
            total_system_ram_gb=self.total_system_ram_gb,
            global_cache_ratio=self.global_cache_ratio,
            vector_vault_ratio=self.vector_vault_ratio,
            logic_graph_ratio=self.logic_graph_ratio,
            system_reserve_ratio=self.system_reserve_ratio,
        )

    @computed_field(return_type=GpuConfig)
    @property
    def gpu(self) -> GpuConfig:
        """Resolved GPU toggles and VRAM targets for downstream tensor engines."""
        return GpuConfig(
            use_gpu_acceleration=self.use_gpu_acceleration,
            cuda_device=self.cuda_device,
            cuda_visible_devices=self.cuda_visible_devices,
            target_gpu_name=self.gpu_name_baseline,
            target_vram_mb=self.gpu_vram_target_mb,
            working_set_target_mb=self.gpu_vram_working_set_mb,
            reserve_vram_mb=self.gpu_vram_reserve_mb,
        )

    @computed_field(return_type=PathHierarchy)
    @property
    def paths(self) -> PathHierarchy:
        """Workspace-standardized absolute paths for PathGuard isolation."""
        root = self.workspace_root
        return PathHierarchy(
            workspace_root=root,
            staged_dir=(root / "staged").resolve(),
            loot_dir=(root / "loot").resolve(),
            memory_dir=(root / "memory").resolve(),
            logs_dir=(root / "logs").resolve(),
            audit_dir=(root / ".cerberus" / "audit").resolve(),
            indices_dir=(root / "memory" / "indices").resolve(),
            versions_dir=(root / "memory" / "versions").resolve(),
            rag_dir=(root / "memory" / "rag").resolve(),
        )

    @computed_field(return_type=OperationalPolicy)
    @property
    def policy(self) -> OperationalPolicy:
        """Transparent operational flags for logging and persistence."""
        return OperationalPolicy(
            audit_mode=self.audit_mode,
            encryption_enabled=self.encryption_enabled,
            telemetry_enabled=self.telemetry_enabled,
            log_level=self.log_level,
        )

    def ensure_workspace_dirs(self) -> None:
        """Create the standardized workspace directory hierarchy."""
        for path_value in (
            self.paths.workspace_root,
            self.paths.staged_dir,
            self.paths.loot_dir,
            self.paths.memory_dir,
            self.paths.logs_dir,
            self.paths.audit_dir,
            self.paths.indices_dir,
            self.paths.versions_dir,
            self.paths.rag_dir,
        ):
            path_value.mkdir(parents=True, exist_ok=True)

    def as_environment(self) -> dict[str, str]:
        """Render the core configuration as environment variables."""
        return {
            "CIR_WORKSPACE": str(self.workspace_root),
            "CUDA_VISIBLE_DEVICES": self.cuda_visible_devices,
            "CERBERUS_USE_GPU_ACCELERATION": str(self.use_gpu_acceleration).lower(),
            "CERBERUS_TOTAL_SYSTEM_RAM_GB": str(self.total_system_ram_gb),
            "CERBERUS_LOG_LEVEL": self.log_level,
        }


@lru_cache(maxsize=1)
def get_cerberus_config() -> CerberusConfig:
    """Return the process-wide immutable Cerberus configuration singleton."""
    return CerberusConfig()


__all__ = [
    "CerberusConfig",
    "GpuConfig",
    "OperationalPolicy",
    "PathHierarchy",
    "RamSegmentation",
    "get_cerberus_config",
    "should_suppress_openai_api_key_warning",
]