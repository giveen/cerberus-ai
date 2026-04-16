from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Sequence, Set, Tuple


@dataclass(frozen=True)
class ToolNode:
    """Metadata-only representation of one tool in the registry graph."""

    name: str
    module_path: str
    category: str
    dependencies: Tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ToolCategory:
    """Metadata-only category entry point in the tool graph."""

    name: str
    tools: Tuple[ToolNode, ...]


@dataclass(frozen=True)
class ToolGraph:
    """Deterministic metadata graph for all tools and categories."""

    nodes_by_key: Mapping[str, ToolNode]
    nodes_by_id: Mapping[str, ToolNode]
    categories: Mapping[str, ToolCategory]


def activate_tool_subgraph(graph: ToolGraph, category: str) -> Tuple[ToolNode, ...]:
    """Resolve a deterministic activation order for a category subgraph.

    Traversal is metadata-only and import-free. Direct tools in the category are
    considered graph seeds; any dependency tokens that reference other tools by
    tool-name or tool-key are recursively included.
    """
    normalized_category = str(category or "").strip()
    if not normalized_category:
        return ()

    category_node = graph.categories.get(normalized_category)
    if category_node is None:
        return ()

    nodes_by_name: Dict[str, ToolNode] = {}
    for node in graph.nodes_by_key.values():
        if node.name:
            nodes_by_name.setdefault(node.name, node)

    ordered: list[ToolNode] = []
    visited: Set[str] = set()

    def _resolve_dependency(dep: str) -> ToolNode | None:
        token = str(dep or "").strip()
        if not token:
            return None
        return nodes_by_name.get(token) or graph.nodes_by_key.get(token)

    def _dfs(node: ToolNode) -> None:
        if node.name in visited:
            return
        visited.add(node.name)

        dependency_nodes = []
        for dependency in node.dependencies:
            resolved = _resolve_dependency(dependency)
            if resolved is not None:
                dependency_nodes.append(resolved)

        # Stable dependency order by name keeps activation deterministic.
        for dep_node in sorted(dependency_nodes, key=lambda candidate: candidate.name):
            _dfs(dep_node)

        ordered.append(node)

    seeds: Sequence[ToolNode] = category_node.tools
    for seed in sorted(seeds, key=lambda candidate: candidate.name):
        _dfs(seed)

    return tuple(ordered)


def derive_category_from_module_path(module_path: str) -> str:
    """Derive top-level category from module path without filesystem access."""
    prefix = "cerberus.tools."
    if not module_path.startswith(prefix):
        return "uncategorized"

    suffix = module_path[len(prefix):]
    parts = [part for part in suffix.split(".") if part]
    if len(parts) >= 2:
        return parts[0]
    if len(parts) == 1:
        return "root"
    return "uncategorized"


def build_tool_graph(tool_catalog: Mapping[str, Mapping[str, Any]]) -> ToolGraph:
    """Build a deterministic, metadata-only graph from TOOL_CATALOG.

    This function must not import tool modules; it stores only string references
    and metadata required by the registry.
    """
    nodes_by_key: Dict[str, ToolNode] = {}
    nodes_by_id: Dict[str, ToolNode] = {}
    nodes_by_name: Dict[str, ToolNode] = {}
    category_buckets: Dict[str, list[ToolNode]] = {}

    for tool_key in sorted(tool_catalog.keys()):
        spec = dict(tool_catalog[tool_key])

        module_path = str(spec.get("module", "") or "").strip()
        name = str(spec.get("name", "") or "").strip()
        dependencies_raw = spec.get("dependencies", [])
        if isinstance(dependencies_raw, list):
            dependencies = tuple(str(dep) for dep in dependencies_raw)
        else:
            dependencies = ()

        category = derive_category_from_module_path(module_path)

        metadata = {
            key: value
            for key, value in spec.items()
            if key not in {"module", "name", "dependencies"}
        }

        node = ToolNode(
            name=name,
            module_path=module_path,
            category=category,
            dependencies=dependencies,
            metadata=metadata,
        )

        tool_id = f"{category}:{name}"
        existing_id_node = nodes_by_id.get(tool_id)
        if existing_id_node is not None:
            raise ValueError(
                "Duplicate tool identity detected: "
                f"tool_id='{tool_id}', "
                f"existing_module='{existing_id_node.module_path}', "
                f"conflicting_module='{module_path}'"
            )

        existing_name_node = nodes_by_name.get(name)
        if existing_name_node is not None:
            raise ValueError(
                "Duplicate tool name detected across categories: "
                f"tool_name='{name}', "
                f"existing_category='{existing_name_node.category}', "
                f"conflicting_category='{category}', "
                f"existing_module='{existing_name_node.module_path}', "
                f"conflicting_module='{module_path}'"
            )

        nodes_by_key[tool_key] = node
        nodes_by_id[tool_id] = node
        nodes_by_name[name] = node
        category_buckets.setdefault(category, []).append(node)

    categories: Dict[str, ToolCategory] = {}
    for category_name in sorted(category_buckets.keys()):
        nodes = tuple(sorted(category_buckets[category_name], key=lambda node: node.name))
        categories[category_name] = ToolCategory(name=category_name, tools=nodes)

    return ToolGraph(nodes_by_key=nodes_by_key, nodes_by_id=nodes_by_id, categories=categories)
