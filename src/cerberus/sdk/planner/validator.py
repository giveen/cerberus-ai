from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Mapping, Optional

from cerberus.sdk.planner.models import DependencyKind


class UnresolvedDependencyError(RuntimeError):
    """Raised when a dependency cannot be resolved by any known mechanism."""


@dataclass(frozen=True)
class DependencyValidationResult:
    """Dependency classification results for a plan."""

    dependency_kinds: Dict[str, DependencyKind] = field(default_factory=dict)
    unresolved_references: list[str] = field(default_factory=list)
    trace_logs: list[str] = field(default_factory=list)


def _iter_graph_nodes(graph_index: Any) -> Iterable[Any]:
    nodes_by_key = getattr(graph_index, "nodes_by_key", {})
    if isinstance(nodes_by_key, Mapping):
        return nodes_by_key.values()
    return ()


def _is_internal_tool(dep_name: str, graph_index: Any) -> bool:
    token = str(dep_name or "").strip()
    if not token:
        return False

    nodes_by_key = getattr(graph_index, "nodes_by_key", {})
    nodes_by_id = getattr(graph_index, "nodes_by_id", {})

    if isinstance(nodes_by_key, Mapping) and token in nodes_by_key:
        return True
    if isinstance(nodes_by_id, Mapping) and token in nodes_by_id:
        return True

    for node in _iter_graph_nodes(graph_index):
        name = str(getattr(node, "name", "") or "").strip()
        if token == name:
            return True

    return False


def _is_external_capability(dep_name: str) -> bool:
    token = str(dep_name or "").strip().lower()
    if not token:
        return False

    capability_tokens = {
        "network_access",
        "internet_access",
        "filesystem_access",
        "workspace_access",
    }
    return token in capability_tokens or token.endswith("_access")


def validate_plan(plan: Any, graph_index: Any) -> DependencyValidationResult:
    """Validate dependencies using INTERNAL_TOOL/SYSTEM_BINARY/capability checks.

    Resolution order:
    1) Internal tool graph lookup
    2) System binary lookup via shutil.which
    3) External capability token classification
    """

    dependencies = list(getattr(plan, "dependencies", []) or [])
    dependency_kinds: Dict[str, DependencyKind] = {}
    unresolved: list[str] = []
    trace_logs: list[str] = []

    for dep in dependencies:
        dep_name = str(dep or "").strip()
        if not dep_name or dep_name in dependency_kinds:
            continue

        if _is_internal_tool(dep_name, graph_index):
            dependency_kinds[dep_name] = DependencyKind.INTERNAL_TOOL
            continue

        resolved_path: Optional[str] = shutil.which(dep_name)
        if resolved_path:
            dependency_kinds[dep_name] = DependencyKind.SYSTEM_BINARY
            trace_logs.append(
                f"Dependency [{dep_name}] resolved as SYSTEM_BINARY via environment path."
            )
            continue

        if _is_external_capability(dep_name):
            dependency_kinds[dep_name] = DependencyKind.EXTERNAL_CAPABILITY
            continue

        unresolved.append(dep_name)

    if unresolved:
        unresolved_csv = ",".join(sorted(set(unresolved)))
        raise UnresolvedDependencyError(
            f"Unresolved dependencies: {unresolved_csv}"
        )

    return DependencyValidationResult(
        dependency_kinds=dependency_kinds,
        unresolved_references=[],
        trace_logs=trace_logs,
    )
