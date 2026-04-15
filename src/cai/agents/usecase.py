"""Cerebro Operational Scoping Engine (COSE).

Mission initialization, boundary enforcement, authorization verification, and
engagement audit bootstrap for Cerberus AI operations.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Mapping, Optional, Sequence

from cai.agents.guardrails import CerebroGuardrailEngine
from cai.tools.reconnaissance.filesystem import PathGuard as FilesystemPathGuard
from cai.tools.workspace import get_project_space


_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$")
_AGGRESSION_VALUES = {"stealth", "standard", "full-auto"}


class ScopeValidationError(ValueError):
    """Raised when mission scope inputs fail syntactic validation."""


@dataclass
class AuthorizedSurface:
    ips: List[str] = field(default_factory=list)
    cidr_ranges: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)


@dataclass
class AggressionProfile:
    level: str
    scan_requires_manual_approval: bool
    max_parallel_actions: int
    opsec_bias: str


@dataclass
class ResourceReservation:
    total_ram_gb: int
    reserved_ram_gb: int
    cfma_ram_gb: int
    cpie_ram_gb: int
    free_buffer_gb: int


@dataclass
class MissionProfile:
    mission_id: str
    operator: str
    created_at: str
    objective: str
    authorized_surface: AuthorizedSurface
    allowlist: List[str]
    blocklist: List[str]
    aggression: AggressionProfile
    resource_reservation: ResourceReservation
    notes: List[str] = field(default_factory=list)


class CerebroFileWriter:
    """PathGuard-backed writer with mission profile lock support."""

    def __init__(self, workspace_root: Path) -> None:
        self.workspace_root = workspace_root.resolve()
        self._guard = FilesystemPathGuard(self.workspace_root, self._audit)

    def write_text(self, relative_path: str, content: str, *, encoding: str = "utf-8") -> Dict[str, Any]:
        resolved = self._guard.validate_path(relative_path, action="cose_write", mode="write")
        resolved.parent.mkdir(parents=True, exist_ok=True)
        resolved.write_text(content, encoding=encoding)
        return {
            "ok": True,
            "path": str(resolved),
            "bytes_written": len(content.encode(encoding, errors="ignore")),
        }

    def write_json(self, relative_path: str, payload: Mapping[str, Any]) -> Dict[str, Any]:
        return self.write_text(relative_path, json.dumps(dict(payload), ensure_ascii=True, indent=2))

    def lock_json(self, relative_path: str, payload: Mapping[str, Any], signer: str) -> Dict[str, Any]:
        write_result = self.write_json(relative_path, payload)
        resolved = Path(str(write_result["path"]))

        digest = hashlib.sha256(json.dumps(dict(payload), ensure_ascii=True, sort_keys=True).encode("utf-8")).hexdigest()
        lock_payload = {
            "locked": True,
            "locked_at": datetime.now(tz=UTC).isoformat(),
            "locked_by": signer,
            "sha256": digest,
            "target": str(resolved),
        }
        self.write_json(f"{relative_path}.lock.json", lock_payload)

        try:
            os.chmod(resolved, 0o444)
        except OSError:
            # Best effort lock where filesystem permissions are limited.
            pass

        return {"ok": True, "path": str(resolved), "sha256": digest, "locked": True}

    @staticmethod
    def _audit(_event: str, _payload: Dict[str, Any]) -> None:
        return


class CerebroScopingEngine:
    """COSE mission scoping, boundary control, and authorization verifier."""

    def __init__(self, *, workspace_root: Optional[str] = None, total_ram_gb: int = 256) -> None:
        self.workspace_root = self._resolve_workspace(workspace_root)
        self.missions_root = (self.workspace_root / "missions").resolve()
        self.missions_root.mkdir(parents=True, exist_ok=True)

        self.writer = CerebroFileWriter(self.workspace_root)
        self.total_ram_gb = max(64, int(total_ram_gb))
        self._active_profile: Optional[MissionProfile] = None
        self._guardrail_engine = CerebroGuardrailEngine(workspace_root=str(self.workspace_root))

    def initialize_mission(self, requirements: Mapping[str, Any]) -> Dict[str, Any]:
        operator = str(requirements.get("operator") or os.getenv("USER") or "unknown-operator").strip()
        objective = str(requirements.get("objective") or "Undefined mission objective").strip()
        aggression_level = self._normalize_aggression(requirements.get("aggression_level", "standard"))

        raw_surface = dict(requirements.get("authorized_surface") or {})
        raw_allowlist = list(requirements.get("allowlist") or [])
        raw_blocklist = list(requirements.get("blocklist") or [])

        surface = self._build_authorized_surface(raw_surface)
        allowlist = self._build_filter_list(raw_allowlist)
        blocklist = self._build_filter_list(raw_blocklist)

        self._validate_filter_conflicts(allowlist=allowlist, blocklist=blocklist)
        aggression = self._aggression_profile(aggression_level)
        reservation = self._allocate_resources(surface)

        mission_id = self._new_mission_id(operator=operator)
        profile = MissionProfile(
            mission_id=mission_id,
            operator=operator,
            created_at=datetime.now(tz=UTC).isoformat(),
            objective=objective,
            authorized_surface=surface,
            allowlist=allowlist,
            blocklist=blocklist,
            aggression=aggression,
            resource_reservation=reservation,
            notes=self._scope_notes(surface=surface, aggression=aggression),
        )

        self._sync_guardrail_scope(profile)
        self._active_profile = profile

        mission_rel_root = f"missions/{mission_id}"
        mission_profile_rel = f"{mission_rel_root}/mission_profile.json"
        locked = self.writer.lock_json(mission_profile_rel, self._profile_dict(profile), signer=operator)

        engagement = self._create_engagement_log(profile)
        self.writer.write_json(f"{mission_rel_root}/engagement_log.json", engagement)

        return {
            "ok": True,
            "mission_id": mission_id,
            "mission_root": str((self.missions_root / mission_id).resolve()),
            "mission_profile_path": locked.get("path"),
            "engagement_log_signature": engagement.get("signature"),
            "aggression_level": profile.aggression.level,
            "resource_reservation": asdict(profile.resource_reservation),
            "authorized_surface": asdict(profile.authorized_surface),
        }

    def authorize_agent_request(self, *, proposed_action: str, actor: str, metadata: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        if self._active_profile is None:
            return {
                "ok": False,
                "allowed": False,
                "reason": "No active mission profile. Initialize mission before request validation.",
            }

        violations = self._check_surface_boundary(proposed_action)
        filter_hit = self._check_filter_boundary(proposed_action)

        if filter_hit.get("blocked"):
            return {
                "ok": True,
                "allowed": False,
                "reason": filter_hit.get("reason"),
                "boundary_violations": violations,
                "guardrail": None,
            }

        if violations:
            return {
                "ok": True,
                "allowed": False,
                "reason": "Action targets out-of-scope assets.",
                "boundary_violations": violations,
                "guardrail": None,
            }

        assessment = self._guardrail_engine.evaluate_preflight(
            proposed_action=proposed_action,
            actor=actor,
            metadata=dict(metadata or {}),
        )

        return {
            "ok": True,
            "allowed": bool(assessment.allowed),
            "blocked": bool(assessment.blocked),
            "requires_override": bool(assessment.requires_override),
            "reason": assessment.reason,
            "boundary_violations": violations,
            "guardrail": asdict(assessment),
        }

    def get_active_mission_profile(self) -> Dict[str, Any]:
        if self._active_profile is None:
            return {"ok": False, "message": "No active mission profile."}
        return {"ok": True, "profile": self._profile_dict(self._active_profile)}

    def _build_authorized_surface(self, raw_surface: Mapping[str, Any]) -> AuthorizedSurface:
        ip_values = self._normalize_list(raw_surface.get("ips"))
        cidr_values = self._normalize_list(raw_surface.get("cidr_ranges"))
        domain_values = self._normalize_list(raw_surface.get("domains"))

        ips = [self._validate_ip(item) for item in ip_values]
        cidrs = [self._validate_cidr(item) for item in cidr_values]
        domains = [self._validate_domain(item) for item in domain_values]

        return AuthorizedSurface(
            ips=sorted(set(ips)),
            cidr_ranges=sorted(set(cidrs)),
            domains=sorted(set(domains)),
        )

    def _build_filter_list(self, values: Sequence[Any]) -> List[str]:
        out: List[str] = []
        for raw in values:
            token = str(raw).strip().lower()
            if not token:
                continue
            out.append(token)
        return sorted(set(out))

    @staticmethod
    def _validate_filter_conflicts(*, allowlist: Sequence[str], blocklist: Sequence[str]) -> None:
        overlap = sorted(set(allowlist).intersection(set(blocklist)))
        if overlap:
            raise ScopeValidationError(f"Allowlist/blocklist conflict detected: {', '.join(overlap[:8])}")

    @staticmethod
    def _normalize_list(value: Any) -> List[str]:
        if value is None:
            return []
        if isinstance(value, str):
            items = [x.strip() for x in value.split(",")]
            return [x for x in items if x]
        if isinstance(value, Sequence):
            return [str(x).strip() for x in value if str(x).strip()]
        return []

    @staticmethod
    def _validate_ip(value: str) -> str:
        try:
            return str(ipaddress.ip_address(value.strip()))
        except ValueError as exc:
            raise ScopeValidationError(f"Invalid IPv4/IPv6 address: {value}") from exc

    @staticmethod
    def _validate_cidr(value: str) -> str:
        try:
            return str(ipaddress.ip_network(value.strip(), strict=False))
        except ValueError as exc:
            raise ScopeValidationError(f"Invalid CIDR range: {value}") from exc

    @staticmethod
    def _validate_domain(value: str) -> str:
        domain = value.strip().lower().rstrip(".")
        if not _DOMAIN_RE.fullmatch(domain):
            raise ScopeValidationError(f"Invalid domain target: {value}")
        return domain

    @staticmethod
    def _normalize_aggression(value: Any) -> str:
        normalized = str(value or "standard").strip().lower().replace("_", "-")
        if normalized not in _AGGRESSION_VALUES:
            raise ScopeValidationError("Aggression level must be one of: stealth, standard, full-auto")
        return normalized

    @staticmethod
    def _aggression_profile(level: str) -> AggressionProfile:
        if level == "stealth":
            return AggressionProfile(
                level="stealth",
                scan_requires_manual_approval=True,
                max_parallel_actions=1,
                opsec_bias="low-noise",
            )
        if level == "full-auto":
            return AggressionProfile(
                level="full-auto",
                scan_requires_manual_approval=False,
                max_parallel_actions=24,
                opsec_bias="max-velocity-rtx5090",
            )
        return AggressionProfile(
            level="standard",
            scan_requires_manual_approval=False,
            max_parallel_actions=8,
            opsec_bias="professional-audit",
        )

    def _allocate_resources(self, surface: AuthorizedSurface) -> ResourceReservation:
        scope_units = len(surface.ips) + (2 * len(surface.cidr_ranges)) + len(surface.domains)
        pressure = max(1.0, min(4.0, float(scope_units) / 8.0))

        base_cfma = 28
        base_cpie = 24
        cfma = min(96, int(round(base_cfma * pressure)))
        cpie = min(96, int(round(base_cpie * pressure)))
        reserved = min(self.total_ram_gb - 16, cfma + cpie + 24)
        free_buffer = max(8, self.total_ram_gb - reserved)

        return ResourceReservation(
            total_ram_gb=self.total_ram_gb,
            reserved_ram_gb=reserved,
            cfma_ram_gb=cfma,
            cpie_ram_gb=cpie,
            free_buffer_gb=free_buffer,
        )

    def _sync_guardrail_scope(self, profile: MissionProfile) -> None:
        self._guardrail_engine.ingest_authorization(
            standing_authorization={
                "statement": "Mission-specific authorization enforced by COSE.",
                "authorized_networks": [*profile.authorized_surface.ips, *profile.authorized_surface.cidr_ranges],
                "authorized_domains": profile.authorized_surface.domains,
                "red_team_mode": profile.aggression.level == "full-auto",
            },
            engagement_scope={
                "authorized_ips": profile.authorized_surface.ips,
                "authorized_networks": profile.authorized_surface.cidr_ranges,
                "authorized_domains": profile.authorized_surface.domains,
            },
        )

    def _check_surface_boundary(self, proposed_action: str) -> List[str]:
        if self._active_profile is None:
            return ["No active mission profile"]

        violations: List[str] = []
        surface = self._active_profile.authorized_surface
        text = str(proposed_action or "")

        ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
        for raw_ip in ips:
            if not self._ip_in_scope(raw_ip, surface):
                violations.append(f"IP out of scope: {raw_ip}")

        domains = re.findall(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}\b", text)
        for raw_domain in domains:
            domain = raw_domain.lower().rstrip(".")
            if not self._domain_in_scope(domain, surface):
                violations.append(f"Domain out of scope: {domain}")

        return sorted(set(violations))

    def _check_filter_boundary(self, proposed_action: str) -> Dict[str, Any]:
        if self._active_profile is None:
            return {"blocked": True, "reason": "No active mission profile"}

        action = str(proposed_action or "").lower()
        profile = self._active_profile

        for deny in profile.blocklist:
            if deny and deny in action:
                return {"blocked": True, "reason": f"Blocklist token matched: {deny}"}

        if profile.allowlist:
            allowed = any(token and token in action for token in profile.allowlist)
            if not allowed:
                return {"blocked": True, "reason": "No allowlist token matched in proposed action."}

        return {"blocked": False, "reason": "Allowlist/blocklist checks passed."}

    @staticmethod
    def _ip_in_scope(value: str, surface: AuthorizedSurface) -> bool:
        try:
            addr = ipaddress.ip_address(value)
        except ValueError:
            return False

        if value in surface.ips:
            return True

        for item in surface.cidr_ranges:
            try:
                if addr in ipaddress.ip_network(item, strict=False):
                    return True
            except ValueError:
                continue
        return False

    @staticmethod
    def _domain_in_scope(value: str, surface: AuthorizedSurface) -> bool:
        domain = value.lower().rstrip(".")
        for allowed in surface.domains:
            if domain == allowed or domain.endswith(f".{allowed}"):
                return True
        return False

    def _create_engagement_log(self, profile: MissionProfile) -> Dict[str, Any]:
        mission_payload = {
            "mission_id": profile.mission_id,
            "operator": profile.operator,
            "started_at": profile.created_at,
            "objective": profile.objective,
            "aggression_level": profile.aggression.level,
            "authorized_surface": asdict(profile.authorized_surface),
        }
        canonical = json.dumps(mission_payload, ensure_ascii=True, sort_keys=True).encode("utf-8")
        key = self._signing_key(profile.operator)
        signature = hmac.new(key, canonical, hashlib.sha256).hexdigest()
        return {
            "payload": mission_payload,
            "signature_alg": "hmac-sha256",
            "signature": signature,
        }

    @staticmethod
    def _signing_key(operator: str) -> bytes:
        configured = os.getenv("CEREBRO_ENGAGEMENT_SIGNING_KEY", "").strip()
        if configured:
            return configured.encode("utf-8")
        fallback = f"cose:{operator}:default-signing-key"
        return fallback.encode("utf-8")

    @staticmethod
    def _scope_notes(surface: AuthorizedSurface, aggression: AggressionProfile) -> List[str]:
        notes = [
            f"Scope assets: ips={len(surface.ips)} cidr_ranges={len(surface.cidr_ranges)} domains={len(surface.domains)}",
            f"Aggression mode: {aggression.level}",
        ]
        if aggression.scan_requires_manual_approval:
            notes.append("Stealth mode requires manual scan approval.")
        return notes

    @staticmethod
    def _profile_dict(profile: MissionProfile) -> Dict[str, Any]:
        return asdict(profile)

    @staticmethod
    def _new_mission_id(operator: str) -> str:
        stamp = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%SZ")
        nonce = hashlib.sha256(f"{operator}:{stamp}".encode("utf-8")).hexdigest()[:8]
        return f"COSE-{stamp}-{nonce}"

    @staticmethod
    def _resolve_workspace(workspace_root: Optional[str]) -> Path:
        if workspace_root:
            return Path(workspace_root).expanduser().resolve()
        try:
            return get_project_space().ensure_initialized().resolve()
        except Exception:
            return Path.cwd().resolve()


__all__ = [
    "ScopeValidationError",
    "AuthorizedSurface",
    "AggressionProfile",
    "ResourceReservation",
    "MissionProfile",
    "CerebroFileWriter",
    "CerebroScopingEngine",
]

