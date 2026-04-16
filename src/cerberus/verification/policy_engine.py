from __future__ import annotations

import ipaddress
import json
import os
import re
import shlex
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cerberus.parsers import parse_json_lenient


_DANGEROUS_COMMAND_PATTERNS = (
    re.compile(r"\brm\s+-[^\n]*\b(?:rf|fr)\b", re.IGNORECASE),
    re.compile(r"\bchmod\s+777\b", re.IGNORECASE),
    re.compile(r"\bmkfs(?:\.[A-Za-z0-9_+-]+)?\b", re.IGNORECASE),
    re.compile(r"\bdd\s+if=", re.IGNORECASE),
    re.compile(r"\b(?:shutdown|reboot|poweroff|halt)\b", re.IGNORECASE),
    re.compile(r"\b(?:wipefs|fdisk|parted)\b", re.IGNORECASE),
    re.compile(r"\b(?:userdel|deluser)\s+-r\b", re.IGNORECASE),
    re.compile(r"\b(?:iptables|ufw)\b[^\n]*\b(?:flush|disable)\b", re.IGNORECASE),
    re.compile(r"\b(?:curl|wget)\b[^\n]*\|\s*(?:sh|bash)\b", re.IGNORECASE),
)

_DANGEROUS_COMMAND_KEYWORDS = {
    "mkfs",
    "wipefs",
    "fdisk",
    "parted",
    "poweroff",
    "reboot",
    "shutdown",
}

_HIGH_NOISE_MARKERS = (
    "nmap",
    "masscan",
    "ffuf",
    "hydra",
    "nikto",
    "dirb",
)

_PLATFORM_TOOL_NAMES = {
    "computer_use",
    "computer_call",
    "web_search_call",
    "file_search_call",
    "run_supervised_prompt",
}

_BINARY_DEPENDENCY_HINTS: dict[str, tuple[str, ...]] = {
    "nmap": ("nmap",),
    "sqlmap": ("sqlmap",),
    "masscan": ("masscan",),
    "nikto": ("nikto",),
    "ffuf": ("ffuf",),
    "hydra": ("hydra",),
    "curl": ("curl",),
    "wget": ("wget",),
    "tcpdump": ("tcpdump",),
    "ssh": ("ssh",),
    "netcat": ("nc", "netcat"),
    "nc": ("nc", "netcat"),
}

_PATH_KEYWORDS = ("path", "file", "dir", "workspace", "destination")
_COMMAND_TOOL_MARKERS = (
    "command",
    "shell",
    "exec",
    "bash",
    "terminal",
    "cli",
    "script",
    "runner",
    "linux",
    "powershell",
)
_WRITE_TOOL_MARKERS = ("write", "save", "create", "mkdir", "touch", "delete", "remove")
_MUTATING_COMMANDS = {
    "chmod",
    "chown",
    "cp",
    "dd",
    "install",
    "mkdir",
    "mktemp",
    "mv",
    "rm",
    "rmdir",
    "tee",
    "touch",
    "truncate",
}
_URL_RE = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s'\"`]+")
_NETWORK_TOKEN_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")


def is_path_contained(workspace_root: str | Path, suspicious_path: str | Path) -> bool:
    """Return True when suspicious_path resolves within workspace_root.

    Uses resolve(strict=False) to preserve the legacy os.path.realpath behavior
    for non-existent paths.
    """
    resolved_root = Path(workspace_root).resolve(strict=False)
    resolved_candidate = Path(suspicious_path).resolve(strict=False)
    try:
        resolved_candidate.relative_to(resolved_root)
        return True
    except ValueError:
        return False


@dataclass
class PolicyFinding:
    tier: int
    code: str
    level: str
    message: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class PolicyReport:
    findings: list[PolicyFinding] = field(default_factory=list)
    risk_score: int = 0
    manual_approval_required: bool = False

    @property
    def blocked(self) -> bool:
        return any(f.level == "block" for f in self.findings)

    @property
    def requires_approval(self) -> bool:
        return self.manual_approval_required

    @property
    def status(self) -> str:
        if self.manual_approval_required:
            return "REVIEW"
        if self.blocked:
            return "FAIL"
        if self.findings:
            return "OPTIMIZE"
        return "PASS"

    @property
    def risk_level(self) -> str:
        if self.risk_score >= 70:
            return "HIGH"
        if self.risk_score >= 30:
            return "MEDIUM"
        return "LOW"

    @property
    def primary_finding(self) -> PolicyFinding | None:
        if not self.findings:
            return None
        for finding in self.findings:
            if finding.level == "block":
                return finding
        return self.findings[0]

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "manual_approval_required": self.manual_approval_required,
            "requires_approval": self.requires_approval,
            "findings": [
                {
                    "tier": finding.tier,
                    "code": finding.code,
                    "level": finding.level,
                    "message": finding.message,
                    "details": finding.details,
                }
                for finding in self.findings
            ],
        }


class PolicyEngine:
    """Policy checks that move static verifier logic out of prompts and into code."""

    def __init__(self, *, workspace_dir: str | None = None, project_id: str | None = None) -> None:
        workspace = (workspace_dir or os.getenv("CERBERUS_WORKSPACE_ACTIVE_ROOT") or os.getcwd()).strip()
        self.workspace_root = Path(workspace).resolve(strict=False)
        self.project_id = self._normalize_project_id(project_id or os.getenv("CERBERUS_PROJECT_ID") or "")
        self.workspaces_root = self._resolve_workspaces_root(self.workspace_root)
        self.project_root = (
            (self.workspaces_root / self.project_id).resolve(strict=False)
            if self.project_id
            else self.workspaces_root.resolve(strict=False)
        )

    def verify(self, action: dict[str, Any]) -> PolicyReport:
        """Evaluate a proposed action against the four-tier policy engine."""
        planned_call = self._coerce_action_to_call(action)
        chat_history = action.get("chat_history", [])
        manual_approval_granted = bool(action.get("manual_approval_granted"))
        system_state = self._state_signature(action.get("system_state"))
        available_tools = self._resolve_available_tools(action.get("available_tools"))
        allowed_targets = self._resolve_allowed_targets(action)

        findings: list[PolicyFinding] = []
        findings.extend(self.check_tier_1(proposed_call=planned_call, available_tools=available_tools))
        findings.extend(self.check_tier_2_boundaries(planned_calls=[planned_call], allowed_targets=allowed_targets))
        findings.extend(
            self.check_tier_3(
                proposed_call=planned_call,
                chat_history=chat_history,
                system_state=system_state,
            )
        )
        risk_findings, risk_score, approval_required = self.check_tier_4_risk(
            planned_calls=[planned_call],
            manual_approval_granted=manual_approval_granted,
        )
        findings.extend(risk_findings)

        return PolicyReport(
            findings=findings,
            risk_score=risk_score,
            manual_approval_required=approval_required and not manual_approval_granted,
        )

    def run_preflight(
        self,
        *,
        input_items: list[Any],
        available_tools: list[str],
    ) -> PolicyReport:
        findings = self.check_tier_1_facts(
            input_items=input_items,
            available_tools=available_tools,
            planned_calls=[],
        )
        return PolicyReport(findings=findings, risk_score=0)

    def run_post_audit(
        self,
        *,
        planned_calls: list[dict[str, Any]],
        available_tools: list[str],
        previous_signature: tuple[str, str] | None = None,
    ) -> PolicyReport:
        normalized_calls = [self._normalize_planned_call(call) for call in planned_calls]
        findings: list[PolicyFinding] = []
        findings.extend(
            self.check_tier_1_facts(
                input_items=[],
                available_tools=available_tools,
                planned_calls=normalized_calls,
            )
        )
        findings.extend(self.check_tier_2_boundaries(planned_calls=normalized_calls))
        findings.extend(
            self.check_tier_3_efficiency(
                planned_calls=normalized_calls,
                previous_signature=previous_signature,
            )
        )
        risk_findings, risk_score, approval_required = self.check_tier_4_risk(planned_calls=normalized_calls)
        findings.extend(risk_findings)
        return PolicyReport(
            findings=findings,
            risk_score=risk_score,
            manual_approval_required=approval_required,
        )

    def check_tier_1(
        self,
        *,
        proposed_call: dict[str, Any],
        available_tools: set[str] | None = None,
    ) -> list[PolicyFinding]:
        return self.check_tier_1_facts(
            input_items=[],
            available_tools=sorted(available_tools or self._resolve_available_tools(None)),
            planned_calls=[self._normalize_planned_call(proposed_call)],
        )

    def check_tier_2(self, *, targets: list[str]) -> list[PolicyFinding]:
        return self.check_tier_2_boundaries(
            planned_calls=[{"tool_name": "policy_verify", "arguments": {"targets": targets}}]
        )

    def check_tier_3(
        self,
        *,
        proposed_call: dict[str, Any],
        chat_history: list[Any],
        system_state: str,
    ) -> list[PolicyFinding]:
        signature = self._call_signature(self._normalize_planned_call(proposed_call))
        if signature is None:
            return []

        matching_entries: list[dict[str, Any]] = []
        for entry in self._recent_history(chat_history, limit=10):
            historical_signature = self._history_signature(entry)
            if historical_signature != signature:
                continue
            if isinstance(entry, dict):
                matching_entries.append(entry)

        total_attempts = len(matching_entries) + 1
        if total_attempts < 3:
            return []

        statuses = [status for status in (self._history_status(entry) for entry in matching_entries) if status]
        states = [state for state in (self._history_state_signature(entry) for entry in matching_entries) if state]

        status_unchanged = True if not statuses else len(set(statuses)) == 1
        combined_states = set(states)
        if system_state:
            combined_states.add(system_state)
        state_unchanged = len(combined_states) <= 1

        if status_unchanged and state_unchanged:
            tool_name, normalized_args = signature
            return [
                PolicyFinding(
                    tier=3,
                    code="looping_behavior_detected",
                    level="block",
                    message=(
                        "Cognitive loop detector blocked a repeated tool call after 3 attempts in the last 10 turns "
                        "without a state change. Try a different tool, narrow the scope, or inspect the last failure before retrying."
                    ),
                    details={
                        "tool_name": tool_name,
                        "arguments": normalized_args,
                        "attempts": total_attempts,
                        "history_window": 10,
                        "status_markers": statuses,
                    },
                )
            ]

        return []

    def check_tier_4(
        self,
        *,
        shell_command: str,
        manual_approval_granted: bool = False,
    ) -> tuple[list[PolicyFinding], int, bool]:
        planned_calls: list[dict[str, Any]] = []
        if shell_command.strip():
            planned_calls.append(
                {
                    "tool_name": "execute_cli_command",
                    "arguments": {"command": shell_command},
                }
            )
        return self.check_tier_4_risk(
            planned_calls=planned_calls,
            manual_approval_granted=manual_approval_granted,
        )

    def verify_tier_1_facts(self, tool_call: dict[str, Any], available_tools: list[str] | None = None) -> list[PolicyFinding]:
        return self.check_tier_1_facts(
            input_items=[],
            available_tools=available_tools or [],
            planned_calls=[self._normalize_planned_call(tool_call)],
        )

    def verify_tier_2_boundaries(
        self,
        action: dict[str, Any],
        *,
        allowed_targets: list[str] | None = None,
    ) -> list[PolicyFinding]:
        return self.check_tier_2_boundaries(
            planned_calls=[self._coerce_action_to_call(action)],
            allowed_targets=allowed_targets,
        )

    def verify_tier_3_efficiency(
        self,
        tool_call: dict[str, Any],
        session_history: list[Any],
        *,
        system_state: Any = None,
    ) -> list[PolicyFinding]:
        return self.check_tier_3(
            proposed_call=self._normalize_planned_call(tool_call),
            chat_history=session_history,
            system_state=self._state_signature(system_state),
        )

    def verify_tier_4_risk(
        self,
        command_string: str,
        *,
        manual_approval_granted: bool = False,
    ) -> tuple[list[PolicyFinding], int, bool]:
        return self.check_tier_4(
            shell_command=command_string,
            manual_approval_granted=manual_approval_granted,
        )

    def check_tier_1_facts(
        self,
        *,
        input_items: list[Any],
        available_tools: list[str],
        planned_calls: list[dict[str, Any]],
    ) -> list[PolicyFinding]:
        findings: list[PolicyFinding] = []
        available_set = self._resolve_available_tools(available_tools)
        normalized_calls = [self._normalize_planned_call(call) for call in planned_calls]

        for call in normalized_calls:
            tool_name = str(call.get("tool_name", "")).strip()
            if not tool_name:
                findings.append(
                    PolicyFinding(
                        tier=1,
                        code="missing_tool_name",
                        level="block",
                        message="Tier 1: Proposed action is missing a tool name.",
                    )
                )
                continue

            if tool_name not in available_set:
                findings.append(
                    PolicyFinding(
                        tier=1,
                        code="tool_unavailable",
                        level="block",
                        message=f"Tier 1: Tool '{tool_name}' is not present in the registered runtime surface.",
                        details={"tool_name": tool_name},
                    )
                )
                continue

            for binary_name in self._binary_requirements_for_call(tool_name, call.get("arguments", {})):
                if self._binary_available(binary_name):
                    continue
                findings.append(
                    PolicyFinding(
                        tier=1,
                        code="missing_dependency",
                        level="block",
                        message=f"Tier 1: Required binary '{binary_name}' is not available on PATH.",
                        details={"tool_name": tool_name, "binary": binary_name},
                    )
                )

        seen_paths: set[tuple[str, str]] = set()
        for path_text in self._extract_paths_from_inputs(input_items):
            normalized = self._normalize_local_path(path_text)
            if normalized is None or (path_text, normalized) in seen_paths:
                continue
            seen_paths.add((path_text, normalized))
            if not Path(normalized).exists():
                findings.append(
                    PolicyFinding(
                        tier=1,
                        code="path_not_found",
                        level="block",
                        message=f"Tier 1: Referenced local path does not exist: {normalized}",
                        details={"path": normalized},
                    )
                )

        for call in normalized_calls:
            for path_text in self._extract_paths_from_call(call):
                normalized = self._normalize_local_path(path_text)
                key = (path_text, normalized or "")
                if normalized is None or key in seen_paths:
                    continue
                seen_paths.add(key)
                if not self._path_exists_for_call(path_text, call):
                    findings.append(
                        PolicyFinding(
                            tier=1,
                            code="path_not_found",
                            level="block",
                            message=f"Tier 1: Referenced local path does not exist: {normalized}",
                            details={"path": normalized, "tool_name": call.get("tool_name", "")},
                        )
                    )

        return findings

    def check_tier_2_boundaries(
        self,
        *,
        planned_calls: list[dict[str, Any]],
        allowed_targets: list[str] | None = None,
    ) -> list[PolicyFinding]:
        findings: list[PolicyFinding] = []
        normalized_calls = [self._normalize_planned_call(call) for call in planned_calls]
        project_root_real = self.project_root.resolve(strict=False)
        allowed_roots = [project_root_real]

        for call in normalized_calls:
            tool_name = str(call.get("tool_name", "")).strip()

            for path_text in self._extract_paths_from_call(call):
                normalized = self._normalize_local_path(path_text)
                if normalized is None:
                    continue
                candidate_real = Path(normalized).resolve(strict=False)
                if self._is_under_any_root(candidate_real, allowed_roots):
                    continue
                findings.append(
                    PolicyFinding(
                        tier=2,
                        code="path_guard_violation",
                        level="block",
                        message=(
                            "Tier 2: Access denied outside the active workspace. "
                            f"Resolved path '{candidate_real}' escapes project '{self.project_id or project_root_real.name}'."
                        ),
                        details={
                            "tool_name": tool_name,
                            "path": str(candidate_real),
                            "allowed_root": str(project_root_real),
                        },
                    )
                )

            if allowed_targets:
                for target in self._extract_network_targets(call):
                    if self._target_in_scope(target, allowed_targets):
                        continue
                    findings.append(
                        PolicyFinding(
                            tier=2,
                            code="target_scope_violation",
                            level="block",
                            message=f"Tier 2: Target '{target}' is outside the active scope.",
                            details={
                                "tool_name": tool_name,
                                "target": target,
                                "allowed_targets": allowed_targets,
                            },
                        )
                    )

        return findings

    def check_tier_3_efficiency(
        self,
        *,
        planned_calls: list[dict[str, Any]],
        previous_signature: tuple[str, str] | None,
    ) -> list[PolicyFinding]:
        findings: list[PolicyFinding] = []
        signatures: list[tuple[str, str]] = []

        for call in (self._normalize_planned_call(item) for item in planned_calls):
            signature = self._call_signature(call)
            if signature is not None:
                signatures.append(signature)

        if previous_signature and signatures and signatures[0] == previous_signature:
            findings.append(
                PolicyFinding(
                    tier=3,
                    code="redundant_tool_repeat",
                    level="warn",
                    message=(
                        f"Planned call repeats the previous tool signature: {signatures[0][0]} {signatures[0][1]}"
                    ),
                )
            )

        seen: set[tuple[str, str]] = set()
        for signature in signatures:
            if signature in seen:
                findings.append(
                    PolicyFinding(
                        tier=3,
                        code="duplicate_planned_call",
                        level="warn",
                        message=f"Duplicate planned call detected for tool '{signature[0]}'.",
                        details={"tool_name": signature[0]},
                    )
                )
                break
            seen.add(signature)

        return findings

    def check_tier_4_risk(
        self,
        *,
        planned_calls: list[dict[str, Any]],
        manual_approval_granted: bool = False,
    ) -> tuple[list[PolicyFinding], int, bool]:
        findings: list[PolicyFinding] = []
        score = 0
        manual_approval_required = False

        for call in (self._normalize_planned_call(item) for item in planned_calls):
            tool_name = str(call.get("tool_name", "")).strip().lower()
            arguments = call.get("arguments", {})
            command_text = self._extract_command_like_text(arguments)

            if any(marker in tool_name for marker in _HIGH_NOISE_MARKERS):
                score += 15
                findings.append(
                    PolicyFinding(
                        tier=4,
                        code="high_noise_tool",
                        level="warn",
                        message=f"High-noise tool planned: {tool_name}",
                        details={"tool_name": tool_name},
                    )
                )

            matched_reasons = self._matched_risk_reasons(command_text)
            if not matched_reasons:
                continue

            score += 80
            manual_approval_required = True
            findings.append(
                PolicyFinding(
                    tier=4,
                    code="dangerous_command",
                    level="warn" if manual_approval_granted else "block",
                    message=(
                        "Tier 4: High-risk command approved for execution."
                        if manual_approval_granted
                        else "Tier 4: High-risk command requires manual approval before execution."
                    ),
                    details={
                        "command": command_text[:400],
                        "risk_level": "HIGH",
                        "matched_rules": matched_reasons,
                    },
                )
            )

        return findings, min(score, 100), manual_approval_required

    @staticmethod
    def _extract_command_like_text(arguments: Any) -> str:
        if isinstance(arguments, str):
            return arguments.strip()
        if isinstance(arguments, dict):
            for key in ("command", "cmd", "shell", "script", "raw"):
                value = arguments.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
            argv = arguments.get("argv")
            if isinstance(argv, list) and argv:
                return " ".join(str(item) for item in argv)
        return ""

    def _extract_paths_from_inputs(self, input_items: list[Any]) -> list[str]:
        paths: list[str] = []
        for item in input_items:
            if isinstance(item, str):
                paths.extend(self._extract_paths_from_text(item))
            elif isinstance(item, dict):
                paths.extend(self._extract_paths_from_payload(item))
        return paths

    def _extract_paths_from_payload(self, payload: Any) -> list[str]:
        paths: list[str] = []
        if isinstance(payload, str):
            try:
                parsed = parse_json_lenient(payload, prefer_last=True)
            except Exception:
                parsed = None
            if isinstance(parsed, dict):
                return self._extract_paths_from_payload(parsed)
            return self._extract_paths_from_text(payload)
        if isinstance(payload, dict):
            for key, value in payload.items():
                key_lower = str(key).lower()
                if isinstance(value, str):
                    if self._is_path_like_key(key_lower):
                        paths.append(value.strip())
                    paths.extend(self._extract_paths_from_text(value))
                elif isinstance(value, (dict, list)):
                    paths.extend(self._extract_paths_from_payload(value))
        elif isinstance(payload, list):
            for item in payload:
                paths.extend(self._extract_paths_from_payload(item))
        return [path for path in paths if path]

    @staticmethod
    def _is_path_like_key(key: str) -> bool:
        """Return True for path-like keys while avoiding substring collisions.

        This intentionally avoids naive substring checks so keys like
        "profile" are not mistaken for file/path keys.
        """
        normalized = re.sub(r"[^a-z0-9]+", "_", key.lower()).strip("_")
        if not normalized:
            return False

        parts = tuple(part for part in normalized.split("_") if part)
        if any(part in _PATH_KEYWORDS for part in parts):
            return True

        return normalized in {
            "filepath",
            "filename",
            "directory",
            "workdir",
            "cwd",
            "output_path",
            "input_path",
        }

    @staticmethod
    def _extract_paths_from_text(text: str) -> list[str]:
        cleaned = _URL_RE.sub(" ", text or "")
        try:
            tokens = shlex.split(cleaned, posix=os.name != "nt")
        except Exception:
            tokens = cleaned.split()

        results: list[str] = []
        for token in tokens:
            candidate = token.strip(" \t\r\n,;:()[]{}\"'")
            if not candidate or candidate.startswith("-"):
                continue
            if candidate.startswith(("/", "./", "../", "~/", "workspaces/", "./workspaces/")):
                results.append(candidate)
        return results

    def _extract_network_targets_from_payload(self, payload: Any) -> list[str]:
        targets: list[str] = []
        if isinstance(payload, str):
            return _NETWORK_TOKEN_RE.findall(payload)
        if isinstance(payload, dict):
            for value in payload.values():
                if isinstance(value, str):
                    targets.extend(_NETWORK_TOKEN_RE.findall(value))
                elif isinstance(value, (dict, list)):
                    targets.extend(self._extract_network_targets_from_payload(value))
        elif isinstance(payload, list):
            for item in payload:
                targets.extend(self._extract_network_targets_from_payload(item))
        return targets

    def _extract_paths_from_call(self, call: dict[str, Any]) -> list[str]:
        normalized = self._normalize_planned_call(call)
        return self._extract_paths_from_payload(normalized.get("arguments", {}))

    def _extract_network_targets(self, call: dict[str, Any]) -> list[str]:
        normalized = self._normalize_planned_call(call)
        return self._extract_network_targets_from_payload(normalized.get("arguments", {}))

    def _normalize_local_path(self, path_text: str) -> str | None:
        candidate = path_text.strip()
        if not candidate or "://" in candidate:
            return None
        if any(ch in candidate for ch in ("\n", "\r", "\x00")):
            return None
        if _NETWORK_TOKEN_RE.fullmatch(candidate):
            return None

        candidate = candidate.replace("\\", "/")
        if candidate.startswith("~"):
            return str(Path(candidate).expanduser().resolve(strict=False))

        candidate_path = Path(candidate)
        if candidate_path.is_absolute():
            return str(candidate_path.resolve(strict=False))
        if candidate in {".", "./"}:
            return str(self.project_root.resolve(strict=False))
        if candidate.startswith("./workspaces/"):
            suffix = candidate[len("./workspaces/"):]
            return str((self.workspaces_root / suffix).resolve(strict=False))
        if candidate.startswith("workspaces/"):
            suffix = candidate[len("workspaces/"):]
            return str((self.workspaces_root / suffix).resolve(strict=False))
        if self.project_id and (candidate == self.project_id or candidate.startswith(f"{self.project_id}/")):
            return str((self.workspaces_root / candidate).resolve(strict=False))
        if candidate.startswith("./"):
            return str((self.project_root / candidate[2:]).resolve(strict=False))
        return str((self.project_root / candidate).resolve(strict=False))

    @staticmethod
    def _is_under_any_root(path: Path, roots: list[Path]) -> bool:
        resolved_path = path.resolve(strict=False)
        resolved_roots = [root.resolve(strict=False) for root in roots]
        for root in resolved_roots:
            try:
                resolved_path.relative_to(root)
                return True
            except ValueError:
                continue
        return False

    @staticmethod
    def _resolve_workspaces_root(workspace_root: Path) -> Path:
        if workspace_root.name == "workspaces":
            return workspace_root.resolve(strict=False)
        for root in (workspace_root, *workspace_root.parents):
            if root.name == "workspaces":
                return root.resolve(strict=False)
        return (workspace_root / "workspaces").resolve(strict=False)

    def _coerce_action_to_call(self, action: dict[str, Any]) -> dict[str, Any]:
        tool_name = str(action.get("tool_name") or "").strip()
        arguments = action.get("arguments")

        if not tool_name and isinstance(action.get("command"), str):
            tool_name = "execute_cli_command"
            arguments = {"command": action.get("command", "")}

        if arguments is None:
            arguments = {}

        return self._normalize_planned_call(
            {
                "tool_name": tool_name,
                "arguments": arguments,
            }
        )

    def _normalize_planned_call(self, call: dict[str, Any]) -> dict[str, Any]:
        tool_name = str(call.get("tool_name", "") or "").strip()
        arguments = call.get("arguments", {})

        if isinstance(arguments, str):
            stripped = arguments.strip()
            if not stripped:
                arguments = {}
            else:
                try:
                    parsed = parse_json_lenient(stripped, prefer_last=True)
                except Exception:
                    parsed = None
                if isinstance(parsed, dict):
                    arguments = parsed
                elif self._tool_accepts_raw_command_text(tool_name):
                    arguments = {"raw": stripped}
                else:
                    arguments = {}
        elif arguments is None:
            arguments = {}

        return {
            "tool_name": tool_name,
            "arguments": arguments,
        }

    @staticmethod
    def _tool_accepts_raw_command_text(tool_name: str) -> bool:
        lowered_tool_name = tool_name.lower().strip()
        return any(marker in lowered_tool_name for marker in _COMMAND_TOOL_MARKERS)

    def _resolve_available_tools(self, available_tools: Any) -> set[str]:
        names = {str(name).strip() for name in available_tools or [] if str(name).strip()}
        names.update(_PLATFORM_TOOL_NAMES)
        try:
            from cerberus.tools.all_tools import get_tool_registry

            registry = get_tool_registry()
            names.update({tool.name.strip() for tool in registry.get_all_tools() if tool.name.strip()})
        except Exception:
            pass
        return names

    def _resolve_allowed_targets(self, action: dict[str, Any]) -> list[str] | None:
        candidates = action.get("allowed_targets")
        if candidates is None and isinstance(action.get("system_state"), dict):
            candidates = action["system_state"].get("allowed_targets")
        if candidates is None:
            return None
        if isinstance(candidates, str):
            values = [item.strip() for item in candidates.split(",") if item.strip()]
            return values or None
        if isinstance(candidates, list):
            values = [str(item).strip() for item in candidates if str(item).strip()]
            return values or None
        return None

    @staticmethod
    def _state_signature(value: Any) -> str:
        if isinstance(value, str):
            return value.strip()
        if value is None:
            return ""
        try:
            return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
        except Exception:
            return str(value)

    @staticmethod
    def _call_signature(call: dict[str, Any]) -> tuple[str, str] | None:
        tool_name = str(call.get("tool_name", "")).strip()
        if not tool_name:
            return None
        arguments = call.get("arguments", {})
        try:
            normalized = json.dumps(arguments, sort_keys=True, separators=(",", ":"), default=str)
        except Exception:
            normalized = str(arguments)
        return tool_name, normalized

    @staticmethod
    def _recent_history(chat_history: list[Any], *, limit: int) -> list[Any]:
        if not isinstance(chat_history, list):
            return []
        return chat_history[-limit:]

    def _history_signature(self, entry: Any) -> tuple[str, str] | None:
        if not isinstance(entry, dict):
            return None
        if "tool_name" in entry:
            return self._call_signature(self._normalize_planned_call(entry))
        action = entry.get("action")
        if isinstance(action, dict):
            return self._call_signature(self._coerce_action_to_call(action))
        return None

    def _history_state_signature(self, entry: Any) -> str:
        if not isinstance(entry, dict):
            return ""
        return self._state_signature(entry.get("system_state"))

    def _history_status(self, entry: Any) -> str:
        if not isinstance(entry, dict):
            return ""
        value = entry.get("status") or entry.get("result_status")
        if value is None and isinstance(entry.get("system_state"), dict):
            value = entry["system_state"].get("status") or entry["system_state"].get("status_line")
        return str(value or "").strip().upper()

    def _path_exists_for_call(self, path_text: str, call: dict[str, Any]) -> bool:
        normalized = self._normalize_local_path(path_text)
        if normalized is None:
            return True

        candidate = Path(normalized)
        if self._call_mutates_paths(call):
            parent = candidate if candidate.exists() and candidate.is_dir() else candidate.parent
            return parent.exists()
        return candidate.exists()

    def _call_mutates_paths(self, call: dict[str, Any]) -> bool:
        tool_name = str(call.get("tool_name", "")).lower().strip()
        if any(token in tool_name for token in _WRITE_TOOL_MARKERS):
            return True
        command_text = self._extract_command_like_text(call.get("arguments", {}))
        executable = self._first_command_token(command_text)
        return executable in _MUTATING_COMMANDS

    def _binary_requirements_for_call(self, tool_name: str, arguments: Any) -> list[str]:
        requirements: list[str] = []
        lowered_tool_name = tool_name.lower().strip()

        for marker, binaries in _BINARY_DEPENDENCY_HINTS.items():
            if marker in lowered_tool_name:
                requirements.extend(binaries)

        command_token = self._first_command_token(self._extract_command_like_text(arguments))
        if command_token:
            requirements.append(command_token)

        deduped: list[str] = []
        seen: set[str] = set()
        for requirement in requirements:
            normalized = requirement.strip()
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            deduped.append(normalized)
        return deduped

    @staticmethod
    def _binary_available(binary_name: str) -> bool:
        active_container = str(os.getenv("CERBERUS_ACTIVE_CONTAINER", "") or os.getenv("CEREBRO_ACTIVE_CONTAINER", "")).strip()
        if active_container:
            return True
        return shutil.which(binary_name) is not None

    @staticmethod
    def _first_command_token(command_text: str) -> str:
        text = (command_text or "").strip()
        if not text:
            return ""
        try:
            tokens = shlex.split(text, posix=os.name != "nt")
        except Exception:
            tokens = text.split()

        for token in tokens:
            stripped = token.strip()
            if not stripped or stripped.startswith("$") or "=" in stripped and not stripped.startswith(("./", "../", "/")):
                if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", stripped):
                    continue
            if stripped in {"sudo", "env", "command", "time", "nohup"}:
                continue
            if stripped.startswith("-"):
                continue
            return Path(stripped).name
        return ""

    @staticmethod
    def _matched_risk_reasons(command_text: str) -> list[str]:
        lowered = (command_text or "").lower()
        if not lowered:
            return []
        reasons = [pattern.pattern for pattern in _DANGEROUS_COMMAND_PATTERNS if pattern.search(lowered)]
        reasons.extend(sorted(keyword for keyword in _DANGEROUS_COMMAND_KEYWORDS if keyword in lowered))
        return reasons

    @staticmethod
    def _normalize_project_id(project_id: str) -> str:
        cleaned = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "-" for ch in project_id.strip())
        return cleaned.strip("-")

    @staticmethod
    def _target_in_scope(target: str, allowed_targets: list[str]) -> bool:
        try:
            target_network = ipaddress.ip_network(target, strict=False)
        except ValueError:
            return target in allowed_targets

        for allowed in allowed_targets:
            try:
                allowed_network = ipaddress.ip_network(allowed, strict=False)
            except ValueError:
                if target == allowed:
                    return True
                continue
            if target_network.subnet_of(allowed_network):
                return True
        return False


def _extract_committing_json(payload: str | dict[str, Any]) -> dict[str, Any]:
    if isinstance(payload, dict):
        return payload

    text = payload.strip()
    if not text:
        return {}

    line_match = re.search(r"COMMITTING_JSON\s*:\s*(\{.*\})", text)
    if line_match:
        parsed = parse_json_lenient(line_match.group(1), prefer_last=True)
        if isinstance(parsed, dict):
            return parsed

    parsed = parse_json_lenient(text, prefer_last=True)
    if isinstance(parsed, dict):
        return parsed

    return {}


def format_logic_audit_report(committing_json: str | dict[str, Any]) -> list[dict[str, str]]:
    """Convert COMMITTING_JSON payload into table rows suitable for TUI/Web rendering."""
    payload = _extract_committing_json(committing_json)
    status = str(payload.get("status") or payload.get("verdict") or "PASS")
    mode = str(payload.get("mode") or payload.get("tier") or "MODE_CRITIQUE")
    rationale = str(payload.get("rationale") or payload.get("message") or "")
    adjustment = str(payload.get("suggested_adjustment") or payload.get("next_action") or "")
    risk = str(payload.get("risk_level") or payload.get("risk") or "Low")

    return [
        {"attribute": "Status", "value": status},
        {"attribute": "Mode", "value": mode},
        {"attribute": "Rationale", "value": rationale},
        {"attribute": "Suggested Adjustment", "value": adjustment},
        {"attribute": "Risk Level", "value": risk},
    ]


def render_logic_audit_report_markdown(rows: list[dict[str, str]]) -> str:
    header = [
        "### Logic Audit Report",
        "| Attribute | Value |",
        "| :--- | :--- |",
    ]
    body = [f"| **{row.get('attribute', '')}** | {row.get('value', '')} |" for row in rows]
    return "\n".join(header + body)
