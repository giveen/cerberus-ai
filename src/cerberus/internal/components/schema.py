"""Universal data contract for Cerberus AI internal component exchange.

This module defines the audit-ready schemas used to exchange mission scope,
findings, tool execution state, logical dependencies, and system heartbeat
telemetry across the multi-agent swarm.
"""

from __future__ import annotations

from datetime import UTC, datetime
import json
import os
from pathlib import Path
from typing import Any, Dict, Iterable, List, Literal, Optional
import uuid

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


_DEFAULT_WORKSPACE = Path(os.getenv("CIR_WORKSPACE", "/workspace")).resolve()


class CerberusSchemaModel(BaseModel):
    """Frozen base model with fast Markdown and JSONL serialization helpers."""

    model_config = ConfigDict(frozen=True)

    def to_jsonl(self) -> str:
        """Return one newline-free JSON object suitable for JSONL persistence."""
        return json.dumps(self.model_dump(mode="json"), ensure_ascii=True, default=str)

    def to_markdown(self, title: Optional[str] = None) -> str:
        """Render the model as a compact audit-ready Markdown block."""
        heading = title or self.__class__.__name__
        lines = [f"## {heading}"]
        payload = self.model_dump(mode="json")
        lines.extend(_markdown_lines(payload))
        return "\n".join(lines) + "\n"


def _markdown_lines(payload: Any, *, prefix: str = "") -> List[str]:
    """Render nested values into flat Markdown list lines."""
    if isinstance(payload, dict):
        lines: List[str] = []
        for key, value in payload.items():
            label = f"{prefix}{key}"
            if isinstance(value, (dict, list)):
                lines.append(f"- **{label}**:")
                lines.extend(_markdown_lines(value, prefix=f"{label}."))
            else:
                lines.append(f"- **{label}**: {value}")
        return lines
    if isinstance(payload, list):
        lines = []
        for index, value in enumerate(payload):
            label = f"{prefix}{index}"
            if isinstance(value, (dict, list)):
                lines.append(f"- **{label}**:")
                lines.extend(_markdown_lines(value, prefix=f"{label}."))
            else:
                lines.append(f"- **{label}**: {value}")
        return lines
    return [f"- **{prefix.rstrip('.')}**: {payload}"]


class ValidationStatus(str):
    """Allowed audit validation states for findings."""

    UNVERIFIED = "Unverified"
    CONFIRMED = "Confirmed"
    FALSE_POSITIVE = "False Positive"


class AuditDepth(str):
    """Mission scope depth for agent action planning."""

    SHALLOW = "shallow"
    STANDARD = "standard"
    DEEP = "deep"
    EXHAUSTIVE = "exhaustive"


class CredentialLoot(CerberusSchemaModel):
    """Credential material extracted during audit operations."""

    username: str = Field(min_length=1)
    secret: str = Field(min_length=1)
    secret_type: Literal["password", "hash", "token", "key"] = "password"
    source: str = Field(default="unknown")


class FileLoot(CerberusSchemaModel):
    """Configuration or document artifact extracted from the target."""

    file_name: str = Field(min_length=1)
    file_path: Path
    description: str = Field(default="")

    @field_validator("file_path")
    @classmethod
    def _validate_file_path(cls, value: Path) -> Path:
        resolved = value.expanduser().resolve()
        return resolved


class HashLoot(CerberusSchemaModel):
    """Hash material extracted from the target or supporting artifacts."""

    principal: str = Field(min_length=1)
    hash_value: str = Field(min_length=1)
    algorithm: str = Field(default="unknown")


class ExtractedLoot(CerberusSchemaModel):
    """Structured loot bundle associated with a finding."""

    credentials: List[CredentialLoot] = Field(default_factory=list)
    config_files: List[FileLoot] = Field(default_factory=list)
    hashes: List[HashLoot] = Field(default_factory=list)
    notes: List[str] = Field(default_factory=list)


class VulnerabilityDetails(CerberusSchemaModel):
    """Explicit vulnerability metadata attached to a finding."""

    cve: Optional[str] = None
    severity: Literal["Info", "Low", "Medium", "High", "Critical"] = "Info"
    title: str = Field(min_length=1)
    summary: str = Field(min_length=1)
    cvss_score: Optional[float] = Field(default=None, ge=0.0, le=10.0)
    references: List[str] = Field(default_factory=list)


class CerberusFinding(CerberusSchemaModel):
    """Universal audit finding schema for mission intelligence exchange."""

    finding_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
    target_id: str = Field(min_length=1)
    service_vector: str = Field(min_length=1)
    vulnerability_details: VulnerabilityDetails
    extracted_loot: ExtractedLoot = Field(default_factory=ExtractedLoot)
    evidence_pointer: Path
    validation_status: Literal["Unverified", "Confirmed", "False Positive"] = "Unverified"
    tags: List[str] = Field(default_factory=list)

    @field_validator("evidence_pointer")
    @classmethod
    def _validate_evidence_pointer(cls, value: Path) -> Path:
        resolved = value.expanduser().resolve()
        try:
            resolved.relative_to(_DEFAULT_WORKSPACE / "loot")
        except ValueError as exc:
            raise ValueError(f"evidence_pointer must be rooted in {_DEFAULT_WORKSPACE / 'loot'}") from exc
        return resolved


class CerberusLogicNode(CerberusSchemaModel):
    """State-machine node exchanged with the CCSM dependency graph."""

    node_id: str = Field(min_length=1)
    prerequisites: List[str] = Field(default_factory=list)
    discovery_agent: str = Field(min_length=1)
    logical_consequence: str = Field(min_length=1)
    state_value: Optional[str] = None
    stale: bool = False
    updated_at: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))


class ExecutionTelemetry(CerberusSchemaModel):
    """Runtime telemetry sampled during tool execution."""

    sampled_at: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
    ram_used_gb: float = Field(ge=0.0)
    ram_total_gb: float = Field(ge=0.0)
    ram_pct: float = Field(ge=0.0, le=100.0)
    vram_used_mb: float = Field(ge=0.0)
    vram_total_mb: float = Field(ge=0.0)
    vram_pct: float = Field(ge=0.0, le=100.0)
    gpu_name: str = Field(default="unknown")


class ToolRequest(CerberusSchemaModel):
    """Normalized tool invocation contract."""

    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tool_name: str = Field(min_length=1)
    parameters: Dict[str, Any] = Field(default_factory=dict)
    requester_agent: str = Field(min_length=1)
    target_id: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
    timeout_seconds: Optional[float] = Field(default=None, gt=0.0)


class CommandInvocation(CerberusSchemaModel):
    """Normalized command invocation contract for REPL dispatch."""

    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    command: str = Field(min_length=1)
    args: List[str] = Field(default_factory=list)
    force: bool = False
    help_requested: bool = False
    help_target: Optional[str] = None
    user: str = Field(default="unknown")


class ToolResult(CerberusSchemaModel):
    """Standardized tool execution result with explicit telemetry."""

    request_id: str = Field(min_length=1)
    tool_name: str = Field(min_length=1)
    stdout: str = Field(default="")
    stderr: str = Field(default="")
    exit_code: int
    telemetry: ExecutionTelemetry
    completed_at: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
    artifacts: Dict[str, Any] = Field(default_factory=dict)


class MissionScope(CerberusSchemaModel):
    """Strict mission boundary contract for COSE and downstream agents."""

    scope_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    authorized_targets: List[str] = Field(default_factory=list)
    exclusion_list: List[str] = Field(default_factory=list)
    authorized_ports: List[int] = Field(default_factory=list)
    audit_depth: Literal["shallow", "standard", "deep", "exhaustive"] = "standard"
    loaded_at: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))

    @field_validator("authorized_ports")
    @classmethod
    def _validate_ports(cls, value: List[int]) -> List[int]:
        for port in value:
            if port < 1 or port > 65535:
                raise ValueError(f"authorized_ports contains invalid port: {port}")
        return value


class EngineHealth(CerberusSchemaModel):
    """Per-engine liveness and saturation state."""

    engine_name: str = Field(min_length=1)
    status: Literal["pending", "ready", "degraded", "fault", "offline"]
    detail: str = Field(default="")
    queue_depth: int = Field(default=0, ge=0)
    last_heartbeat_at: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))


class RamSegmentHeartbeat(CerberusSchemaModel):
    """Assigned RAM pool saturation sample."""

    segment_name: Literal["global_cache", "vector_vault", "logic_graph", "system_reserve"]
    allocated_gb: float = Field(ge=0.0)
    used_gb: float = Field(ge=0.0)
    saturation_pct: float = Field(ge=0.0, le=100.0)

    @model_validator(mode="after")
    def _validate_usage(self) -> "RamSegmentHeartbeat":
        if self.used_gb > self.allocated_gb and self.allocated_gb > 0:
            raise ValueError(
                f"used_gb exceeds allocated_gb for segment {self.segment_name}: {self.used_gb} > {self.allocated_gb}"
            )
        return self


class SystemHeartbeat(CerberusSchemaModel):
    """Unified heartbeat for engine health and RAM segment saturation."""

    heartbeat_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
    session_id: str = Field(min_length=1)
    engine_health: List[EngineHealth] = Field(default_factory=list)
    ram_segments: List[RamSegmentHeartbeat] = Field(default_factory=list)
    gpu_telemetry: Optional[ExecutionTelemetry] = None
    active_mission_scope_id: Optional[str] = None


class JsonlBatch(CerberusSchemaModel):
    """High-velocity container for batched JSONL persistence."""

    records: List[Dict[str, Any]] = Field(default_factory=list)

    @classmethod
    def from_models(cls, models: Iterable[CerberusSchemaModel]) -> "JsonlBatch":
        """Build a batch container from any iterable of schema models."""
        return cls(records=[model.model_dump(mode="json") for model in models])

    def to_jsonl(self) -> str:
        """Serialize the full batch as newline-delimited JSON."""
        return "\n".join(json.dumps(record, ensure_ascii=True, default=str) for record in self.records)


__all__ = [
    "AuditDepth",
    "CerberusFinding",
    "CerberusLogicNode",
    "CerberusSchemaModel",
    "CommandInvocation",
    "CredentialLoot",
    "EngineHealth",
    "ExecutionTelemetry",
    "ExtractedLoot",
    "FileLoot",
    "HashLoot",
    "JsonlBatch",
    "MissionScope",
    "RamSegmentHeartbeat",
    "SystemHeartbeat",
    "ToolRequest",
    "ToolResult",
    "ValidationStatus",
    "VulnerabilityDetails",
]