"""Engagement topology mapping command for Cerebro REPL.

This module provides a commercial-grade graphing pipeline with decoupled
builders and renderers:
- TopologyBuilder: compute graph nodes/edges from memory and history sources.
- Renderers/Exporters: transform graph documents into Mermaid/ASCII/JSON/
  GraphML and visual PNG/SVG outputs.

No networkx/matplotlib dependencies are used.
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from pydantic import BaseModel, Field
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from cerberus.repl.commands.base import FrameworkCommand, register_command

logger = logging.getLogger(__name__)
console = Console()


# ---------------------------------------------------------------------------
# Graph document models
# ---------------------------------------------------------------------------

class GraphNode(BaseModel):
    id: str
    label: str
    kind: str
    criticality: str = "info"
    color: str = "#4a5568"
    metadata: Dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    source: str
    target: str
    relation: str
    layer: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class GraphDocument(BaseModel):
    graph_type: str
    title: str
    generated_at: str
    nodes: List[GraphNode] = Field(default_factory=list)
    edges: List[GraphEdge] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Privacy redaction policy
# ---------------------------------------------------------------------------

class PrivacyRedactor:
    """Redact sensitive values before rendering/exporting graph artifacts."""

    _PRIVATE_IPV4 = re.compile(
        r"\b(?:10\.(?:\d{1,3}\.){2}\d{1,3}|192\.168\.(?:\d{1,3})\.(?:\d{1,3})|172\.(?:1[6-9]|2\d|3[0-1])\.(?:\d{1,3})\.(?:\d{1,3}))\b"
    )
    _PUBLIC_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    _SECRET_VALUE = re.compile(r"(?i)\b(?:sk|rk)-[A-Za-z0-9]{12,}\b|\bAKIA[0-9A-Z]{16}\b")
    _KEY_VALUE = re.compile(r"(?i)\b([A-Z][A-Z0-9_]{2,})\s*[:=]\s*([^\s,;]+)")

    def __init__(self) -> None:
        self._allow_private_ip = os.getenv("CERBERUS_GRAPH_ALLOW_PRIVATE_IP", "false").lower() == "true"

        try:
            from cerberus.repl.commands.env import ENV_AUDITOR

            self._env_allow = set(ENV_AUDITOR.allow_list())
        except Exception:
            self._env_allow = set()

        try:
            from cerberus.repl.commands.config import _is_secret as cfg_is_secret, _mask as cfg_mask

            self._cfg_is_secret = cfg_is_secret
            self._cfg_mask = cfg_mask
        except Exception:
            self._cfg_is_secret = None
            self._cfg_mask = None

    def _mask_key_value(self, key: str, val: str) -> str:
        if self._cfg_is_secret and self._cfg_mask:
            try:
                if self._cfg_is_secret(key):
                    return f"{key}=HIDDEN_BY_POLICY"
                return f"{key}={self._cfg_mask(key, val)}"
            except Exception:
                pass

        # Fallback behavior
        upper = key.upper()
        if any(m in upper for m in ("KEY", "TOKEN", "SECRET", "PASSWORD", "PASS", "PRIVATE")):
            return f"{key}=HIDDEN_BY_POLICY"

        # Respect allow-list semantics for env-like keys
        if self._env_allow and upper not in self._env_allow:
            return f"{key}=HIDDEN_BY_POLICY"

        return f"{key}={val}"

    def sanitize_text(self, text: str) -> str:
        if not text:
            return ""

        cleaned = str(text)
        cleaned = self._SECRET_VALUE.sub("HIDDEN_BY_POLICY", cleaned)

        def _kv_replace(match: re.Match[str]) -> str:
            key = match.group(1)
            val = match.group(2)
            return self._mask_key_value(key, val)

        cleaned = self._KEY_VALUE.sub(_kv_replace, cleaned)

        if not self._allow_private_ip:
            cleaned = self._PRIVATE_IPV4.sub("PRIVATE_IP_REDACTED", cleaned)

        return cleaned


# ---------------------------------------------------------------------------
# Topology builder (data computation only)
# ---------------------------------------------------------------------------

class TopologyBuilder:
    """Compute graph nodes/edges from memory and agent history sources."""

    _IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    _PORT = re.compile(r"\b(?:port|tcp|udp|:)(\d{1,5})\b", re.IGNORECASE)
    _SERVICE = re.compile(r"\b(http|https|ssh|ftp|smb|rdp|mysql|postgres|mssql|redis|ldap|kerberos|dns)\b", re.IGNORECASE)
    _CVSS = re.compile(r"(?i)cvss\s*[:=]?\s*([0-9](?:\.[0-9])?)")

    def __init__(self, memory_manager: Any = None, redactor: Optional[PrivacyRedactor] = None) -> None:
        self.memory_manager = memory_manager
        self.redactor = redactor or PrivacyRedactor()

    # -- source gathering ---------------------------------------------------

    def _runtime_memory(self) -> Any:
        if self.memory_manager is not None:
            return self.memory_manager
        try:
            from cerberus.repl.commands.memory import RUNTIME_MEMORY

            return RUNTIME_MEMORY
        except Exception:
            return None

    def _collect_memory_events(self, query: str, limit: int = 200) -> List[Dict[str, Any]]:
        mm = self._runtime_memory()
        if mm is None:
            return []

        get_context = getattr(mm, "get_context", None)
        if not callable(get_context):
            return []

        try:
            ctx = get_context(query, limit=limit)
            events = getattr(ctx, "events", []) or []
        except Exception:
            return []

        rows: List[Dict[str, Any]] = []
        for ev in events:
            rows.append(
                {
                    "topic": str(getattr(ev, "topic", "general")),
                    "content": str(getattr(ev, "content", "")),
                    "tags": list(getattr(ev, "tags", []) or []),
                    "agent_id": str(getattr(ev, "agent_id", "default")),
                    "created_at": str(getattr(ev, "created_at", "")),
                }
            )
        return rows

    def _collect_agent_histories(self) -> Dict[str, List[Dict[str, Any]]]:
        try:
            from cerberus.agents.simple_agent_manager import AGENT_MANAGER

            all_histories = AGENT_MANAGER.get_all_histories() or {}
        except Exception:
            all_histories = {}

        rows: Dict[str, List[Dict[str, Any]]] = {}
        for name, hist in all_histories.items():
            safe_msgs: List[Dict[str, Any]] = []
            for msg in hist or []:
                if isinstance(msg, dict):
                    safe_msgs.append(dict(msg))
            rows[str(name)] = safe_msgs
        return rows

    # -- criticality and color ---------------------------------------------

    def _criticality_from_text(self, text: str) -> str:
        match = self._CVSS.search(text)
        if match:
            try:
                score = float(match.group(1))
                if score >= 9.0:
                    return "critical"
                if score >= 7.0:
                    return "high"
                if score >= 4.0:
                    return "medium"
                return "low"
            except Exception:
                pass

        t = text.lower()
        if any(k in t for k in ("critical", "rce", "domain admin", "full compromise")):
            return "critical"
        if any(k in t for k in ("high", "privilege escalation", "credential dump", "lateral movement")):
            return "high"
        if any(k in t for k in ("medium", "misconfiguration", "weak tls")):
            return "medium"
        if any(k in t for k in ("low", "info", "informational")):
            return "low"
        return "info"

    @staticmethod
    def _color_for_criticality(level: str) -> str:
        return {
            "critical": "#9B1C1C",
            "high": "#C2410C",
            "medium": "#B7791F",
            "low": "#2B6CB0",
            "info": "#4A5568",
        }.get(level, "#4A5568")

    # -- graph builders -----------------------------------------------------

    def build_network_graph(self) -> GraphDocument:
        events = self._collect_memory_events("host ip port service scan nmap")
        hosts: Dict[str, GraphNode] = {}
        ports: Dict[str, GraphNode] = {}
        services: Dict[str, GraphNode] = {}
        edges: List[GraphEdge] = []

        for row in events:
            text = self.redactor.sanitize_text(row.get("content", ""))
            crit = self._criticality_from_text(text)

            ip_matches = self._IPV4.findall(text)
            port_matches = self._PORT.findall(text)
            svc_matches = self._SERVICE.findall(text)

            for ip in ip_matches:
                host_id = f"host::{ip}"
                if host_id not in hosts:
                    hosts[host_id] = GraphNode(
                        id=host_id,
                        label=ip,
                        kind="host",
                        criticality=crit,
                        color=self._color_for_criticality(crit),
                        metadata={"source": "memory"},
                    )

                for port in port_matches:
                    p = int(port)
                    if p < 1 or p > 65535:
                        continue
                    port_id = f"port::{ip}:{p}"
                    if port_id not in ports:
                        ports[port_id] = GraphNode(
                            id=port_id,
                            label=f"{ip}:{p}",
                            kind="port",
                            criticality=crit,
                            color=self._color_for_criticality(crit),
                        )
                    edges.append(GraphEdge(source=host_id, target=port_id, relation="exposes", layer="network"))

                    for svc in svc_matches:
                        svc_label = svc.lower()
                        svc_id = f"svc::{ip}:{p}:{svc_label}"
                        if svc_id not in services:
                            services[svc_id] = GraphNode(
                                id=svc_id,
                                label=svc_label,
                                kind="service",
                                criticality=crit,
                                color=self._color_for_criticality(crit),
                            )
                        edges.append(GraphEdge(source=port_id, target=svc_id, relation="runs", layer="network"))

        nodes = list(hosts.values()) + list(ports.values()) + list(services.values())
        return GraphDocument(
            graph_type="network",
            title="Engagement Network Topology",
            generated_at=datetime.now(tz=timezone.utc).isoformat(),
            nodes=nodes,
            edges=edges,
        )

    def build_attack_path_graph(self) -> GraphDocument:
        histories = self._collect_agent_histories()
        nodes: List[GraphNode] = []
        edges: List[GraphEdge] = []

        stage_keywords = [
            ("recon", "Reconnaissance"),
            ("scan", "Scanning"),
            ("enum", "Enumeration"),
            ("exploit", "Exploitation"),
            ("privesc", "Privilege Escalation"),
            ("lateral", "Lateral Movement"),
            ("exfil", "Exfiltration"),
            ("report", "Reporting"),
        ]

        counter = 0
        prev_node_id: Optional[str] = None

        for agent_name, msgs in histories.items():
            for msg in msgs:
                role = msg.get("role", "unknown")
                if role not in ("user", "assistant", "tool"):
                    continue

                content = self.redactor.sanitize_text(str(msg.get("content", "")))
                label = "Step"
                for key, stage in stage_keywords:
                    if key in content.lower():
                        label = stage
                        break

                crit = self._criticality_from_text(content)
                node_id = f"atk::{counter}"
                node = GraphNode(
                    id=node_id,
                    label=f"{label} ({agent_name})",
                    kind="attack_step",
                    criticality=crit,
                    color=self._color_for_criticality(crit),
                    metadata={
                        "agent": agent_name,
                        "role": role,
                        "snippet": content[:200],
                    },
                )
                nodes.append(node)

                if prev_node_id is not None:
                    edges.append(GraphEdge(source=prev_node_id, target=node_id, relation="next", layer="attack"))
                prev_node_id = node_id
                counter += 1

        return GraphDocument(
            graph_type="attack",
            title="Chronological Attack Path",
            generated_at=datetime.now(tz=timezone.utc).isoformat(),
            nodes=nodes,
            edges=edges,
        )

    def build_knowledge_graph(self) -> GraphDocument:
        events = self._collect_memory_events("credential password db finding vulnerability leak")

        nodes: Dict[str, GraphNode] = {}
        edges: List[GraphEdge] = []

        db_re = re.compile(r"\b(mysql|postgres(?:ql)?|mssql|mongodb|redis)\b", re.IGNORECASE)
        cred_re = re.compile(r"(?i)\b(password|credential|hash|token|api key)\b")
        vuln_re = re.compile(r"(?i)\b(cve-\d{4}-\d+|sqli|xss|rce|lfi|ssrf|auth bypass)\b")

        for row in events:
            text = self.redactor.sanitize_text(row.get("content", ""))
            crit = self._criticality_from_text(text)
            finding_id = f"finding::{abs(hash(text)) % 10_000_000}"
            if finding_id not in nodes:
                nodes[finding_id] = GraphNode(
                    id=finding_id,
                    label=(text[:72] + "...") if len(text) > 75 else text,
                    kind="finding",
                    criticality=crit,
                    color=self._color_for_criticality(crit),
                    metadata={"topic": row.get("topic", "")},
                )

            db_match = db_re.search(text)
            if db_match:
                db = db_match.group(1).lower()
                db_id = f"db::{db}"
                if db_id not in nodes:
                    nodes[db_id] = GraphNode(
                        id=db_id,
                        label=db,
                        kind="database",
                        criticality=crit,
                        color=self._color_for_criticality(crit),
                    )
                edges.append(GraphEdge(source=finding_id, target=db_id, relation="targets", layer="knowledge"))

            if cred_re.search(text):
                cred_id = f"cred::{abs(hash(text + 'cred')) % 10_000_000}"
                if cred_id not in nodes:
                    nodes[cred_id] = GraphNode(
                        id=cred_id,
                        label="Credential Artifact",
                        kind="credential",
                        criticality=crit,
                        color=self._color_for_criticality(crit),
                    )
                edges.append(GraphEdge(source=cred_id, target=finding_id, relation="enables", layer="knowledge"))

            vuln_match = vuln_re.search(text)
            if vuln_match:
                vuln = vuln_match.group(1).lower()
                vuln_id = f"vuln::{vuln}"
                if vuln_id not in nodes:
                    nodes[vuln_id] = GraphNode(
                        id=vuln_id,
                        label=vuln,
                        kind="vulnerability",
                        criticality=crit,
                        color=self._color_for_criticality(crit),
                    )
                edges.append(GraphEdge(source=vuln_id, target=finding_id, relation="evidence", layer="knowledge"))

        return GraphDocument(
            graph_type="knowledge",
            title="Finding Relationship Knowledge Graph",
            generated_at=datetime.now(tz=timezone.utc).isoformat(),
            nodes=list(nodes.values()),
            edges=edges,
        )


# ---------------------------------------------------------------------------
# Rendering and exporting (presentation only)
# ---------------------------------------------------------------------------

class MermaidRenderer:
    @staticmethod
    def render(doc: GraphDocument) -> str:
        lines = ["flowchart TD"]
        for node in doc.nodes:
            safe_label = node.label.replace('"', "'").replace("\n", " ")
            lines.append(f"  {node.id.replace('::', '_')}[\"{safe_label}\"]")
            lines.append(f"  style {node.id.replace('::', '_')} fill:{node.color},stroke:#1a202c,stroke-width:1px")
        for edge in doc.edges:
            lines.append(
                f"  {edge.source.replace('::', '_')} -->|{edge.relation}| {edge.target.replace('::', '_')}"
            )
        return "\n".join(lines)


class AsciiRenderer:
    @staticmethod
    def render(doc: GraphDocument) -> str:
        out: List[str] = [f"{doc.title} ({doc.graph_type})"]
        out.append("=" * min(80, len(out[0]) + 8))

        edge_map: Dict[str, List[GraphEdge]] = {}
        for e in doc.edges:
            edge_map.setdefault(e.source, []).append(e)

        for n in doc.nodes:
            out.append(f"[{n.kind}] {n.label}  [{n.criticality}]")
            for e in edge_map.get(n.id, []):
                target = next((x for x in doc.nodes if x.id == e.target), None)
                tlabel = target.label if target else e.target
                out.append(f"  -> ({e.relation}) {tlabel}")
        return "\n".join(out)


class DataExporter:
    @staticmethod
    def to_json(doc: GraphDocument, out: Path) -> Path:
        payload = {
            "graph_type": doc.graph_type,
            "title": doc.title,
            "generated_at": doc.generated_at,
            "nodes": [n.model_dump() for n in doc.nodes],
            "edges": [e.model_dump() for e in doc.edges],
        }
        out.write_text(json.dumps(payload, indent=2))
        return out

    @staticmethod
    def to_graphml(doc: GraphDocument, out: Path) -> Path:
        def esc(v: str) -> str:
            return (
                str(v)
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
            )

        lines: List[str] = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">',
            '  <key id="d0" for="node" attr.name="label" attr.type="string"/>',
            '  <key id="d1" for="node" attr.name="kind" attr.type="string"/>',
            '  <key id="d2" for="node" attr.name="criticality" attr.type="string"/>',
            '  <key id="d3" for="edge" attr.name="relation" attr.type="string"/>',
            '  <graph id="G" edgedefault="directed">',
        ]

        for n in doc.nodes:
            lines.append(f'    <node id="{esc(n.id)}">')
            lines.append(f'      <data key="d0">{esc(n.label)}</data>')
            lines.append(f'      <data key="d1">{esc(n.kind)}</data>')
            lines.append(f'      <data key="d2">{esc(n.criticality)}</data>')
            lines.append("    </node>")

        for i, e in enumerate(doc.edges):
            lines.append(f'    <edge id="e{i}" source="{esc(e.source)}" target="{esc(e.target)}">')
            lines.append(f'      <data key="d3">{esc(e.relation)}</data>')
            lines.append("    </edge>")

        lines.extend(["  </graph>", "</graphml>"])
        out.write_text("\n".join(lines))
        return out


class VisualExporter:
    """Graphviz-based visual exporter (PNG/SVG)."""

    @staticmethod
    def to_dot(doc: GraphDocument) -> str:
        lines: List[str] = ["digraph Engagement {", "  rankdir=LR;"]
        for n in doc.nodes:
            label = n.label.replace('"', "'")
            lines.append(
                f'  "{n.id}" [label="{label}", style="filled", fillcolor="{n.color}", color="#1a202c", fontname="Helvetica"];'
            )
        for e in doc.edges:
            rel = e.relation.replace('"', "'")
            lines.append(f'  "{e.source}" -> "{e.target}" [label="{rel}", color="#2d3748", fontname="Helvetica"];')
        lines.append("}")
        return "\n".join(lines)

    @staticmethod
    def export(doc: GraphDocument, out: Path, fmt: str) -> Path:
        dot = VisualExporter.to_dot(doc)
        fmt = fmt.lower()
        if fmt not in ("png", "svg"):
            raise ValueError("Visual format must be png or svg")

        with tempfile.NamedTemporaryFile("w", suffix=".dot", delete=False) as tf:
            tf.write(dot)
            dot_path = Path(tf.name)

        try:
            cmd = ["dot", f"-T{fmt}", str(dot_path), "-o", str(out)]
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if proc.returncode != 0:
                raise RuntimeError(proc.stderr.strip() or "dot command failed")
            return out
        finally:
            try:
                dot_path.unlink(missing_ok=True)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Command
# ---------------------------------------------------------------------------

class GraphCommand(FrameworkCommand):
    """Interactive engagement topology mapper command."""

    name = "graph"
    description = "Build and export engagement topology graphs"
    aliases = ["/graph", "/g"]

    def __init__(self) -> None:
        super().__init__()
        self.add_subcommand("all", "Build all graph layers", self._sub_all)
        self.add_subcommand("network", "Build network graph", self._sub_network)
        self.add_subcommand("attack", "Build attack path graph", self._sub_attack)
        self.add_subcommand("knowledge", "Build knowledge graph", self._sub_knowledge)
        self.add_subcommand("stats", "Show graph statistics", self._sub_stats)
        self.add_subcommand("export", "Export graphs to files", self._sub_export)

    @property
    def help(self) -> str:
        return (
            "graph [all|network|attack|knowledge|stats|export] [options]\n\n"
            "Options:\n"
            "  --format mermaid|ascii|json|graphml|png|svg\n"
            "  --output <path>\n"
            "  --layer network|attack|knowledge  (for export)\n"
            "\n"
            "Examples:\n"
            "  /graph network --format mermaid\n"
            "  /graph attack --format ascii\n"
            "  /graph export --layer knowledge --format svg\n"
        )

    async def execute(self, args: List[str]) -> bool:
        if not args:
            return await self._sub_all([])

        sub = args[0].lower()
        handler = getattr(self, f"_sub_{sub}", None)
        if handler is None:
            console.print(f"[red]graph: unknown sub-command '{sub}'[/red]")
            console.print(self.help)
            return False
        return await handler(args[1:])

    def _builder(self) -> TopologyBuilder:
        return TopologyBuilder(memory_manager=self.memory)

    def _workspace_report_dir(self) -> Path:
        try:
            from cerberus.tools.workspace import get_project_space

            return get_project_space().ensure_initialized().resolve() / ".cerberus" / "reports"
        except Exception:
            return Path.cwd().resolve() / ".cerberus" / "reports"

    @staticmethod
    def _parse_options(args: List[str]) -> Dict[str, str]:
        opts: Dict[str, str] = {"format": "mermaid"}
        i = 0
        while i < len(args):
            tok = args[i]
            if tok in ("--format", "-f") and i + 1 < len(args):
                opts["format"] = args[i + 1].lower()
                i += 2
            elif tok in ("--output", "-o") and i + 1 < len(args):
                opts["output"] = args[i + 1]
                i += 2
            elif tok == "--layer" and i + 1 < len(args):
                opts["layer"] = args[i + 1].lower()
                i += 2
            else:
                # positional fallback as format
                if "format" not in opts or opts["format"] == "mermaid":
                    opts["format"] = tok.lower()
                i += 1
        return opts

    def _render_terminal(self, doc: GraphDocument, fmt: str) -> bool:
        fmt = fmt.lower()
        if fmt == "mermaid":
            body = MermaidRenderer.render(doc)
            console.print(Panel(body, title=f"{doc.title} [Mermaid]", border_style="cyan", box=box.ROUNDED))
            return True
        if fmt == "ascii":
            body = AsciiRenderer.render(doc)
            console.print(Panel(body, title=f"{doc.title} [ASCII]", border_style="cyan", box=box.ROUNDED))
            return True
        return False

    async def _render_or_export_single(self, doc: GraphDocument, opts: Dict[str, str], default_stem: str) -> bool:
        fmt = opts.get("format", "mermaid").lower()

        if fmt in ("mermaid", "ascii"):
            return self._render_terminal(doc, fmt)

        out_dir = self._workspace_report_dir()
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = Path(opts["output"]).expanduser().resolve() if "output" in opts else out_dir / f"{default_stem}.{fmt}"

        try:
            if fmt == "json":
                DataExporter.to_json(doc, out_path)
            elif fmt == "graphml":
                DataExporter.to_graphml(doc, out_path)
            elif fmt in ("png", "svg"):
                VisualExporter.export(doc, out_path, fmt)
            else:
                console.print(f"[red]Unsupported format: {fmt}[/red]")
                return False
        except Exception as exc:
            console.print(f"[red]graph export failed: {exc}[/red]")
            return False

        console.print(f"[green]Graph exported:[/green] {out_path}")
        return True

    # -- subcommands --------------------------------------------------------

    async def _sub_network(self, args: List[str]) -> bool:
        opts = self._parse_options(args)
        doc = self._builder().build_network_graph()
        return await self._render_or_export_single(doc, opts, "network_topology")

    async def _sub_attack(self, args: List[str]) -> bool:
        opts = self._parse_options(args)
        doc = self._builder().build_attack_path_graph()
        return await self._render_or_export_single(doc, opts, "attack_path")

    async def _sub_knowledge(self, args: List[str]) -> bool:
        opts = self._parse_options(args)
        doc = self._builder().build_knowledge_graph()
        return await self._render_or_export_single(doc, opts, "knowledge_graph")

    async def _sub_all(self, args: List[str]) -> bool:
        opts = self._parse_options(args)
        fmt = opts.get("format", "mermaid")

        builder = self._builder()
        docs = [
            builder.build_network_graph(),
            builder.build_attack_path_graph(),
            builder.build_knowledge_graph(),
        ]

        if fmt in ("mermaid", "ascii"):
            ok = True
            for doc in docs:
                ok = self._render_terminal(doc, fmt) and ok
            return ok

        # For file formats, export all as separate files.
        all_ok = True
        for doc in docs:
            stem = {
                "network": "network_topology",
                "attack": "attack_path",
                "knowledge": "knowledge_graph",
            }.get(doc.graph_type, "graph")
            local_opts = dict(opts)
            if "output" in local_opts:
                # If output is set for --all, treat it as directory.
                od = Path(local_opts["output"]).expanduser().resolve()
                od.mkdir(parents=True, exist_ok=True)
                local_opts["output"] = str(od / f"{stem}.{fmt}")
            all_ok = (await self._render_or_export_single(doc, local_opts, stem)) and all_ok

        return all_ok

    async def _sub_stats(self, args: List[str]) -> bool:
        builder = self._builder()
        docs = [
            builder.build_network_graph(),
            builder.build_attack_path_graph(),
            builder.build_knowledge_graph(),
        ]

        table = Table(title="Topology Mapper Statistics", box=box.ROUNDED, show_header=True, header_style="bold")
        table.add_column("Layer", style="cyan")
        table.add_column("Nodes", style="yellow", justify="right")
        table.add_column("Edges", style="green", justify="right")
        table.add_column("Critical", style="red", justify="right")

        for d in docs:
            critical = sum(1 for n in d.nodes if n.criticality == "critical")
            table.add_row(d.graph_type, str(len(d.nodes)), str(len(d.edges)), str(critical))

        console.print(table)
        return True

    async def _sub_export(self, args: List[str]) -> bool:
        opts = self._parse_options(args)
        layer = opts.get("layer", "network")

        builder = self._builder()
        if layer == "network":
            doc = builder.build_network_graph()
            return await self._render_or_export_single(doc, opts, "network_topology")
        if layer == "attack":
            doc = builder.build_attack_path_graph()
            return await self._render_or_export_single(doc, opts, "attack_path")
        if layer == "knowledge":
            doc = builder.build_knowledge_graph()
            return await self._render_or_export_single(doc, opts, "knowledge_graph")
        if layer == "all":
            return await self._sub_all(args)

        console.print("[red]graph export: --layer must be network|attack|knowledge|all[/red]")
        return False


GRAPH_COMMAND_INSTANCE = GraphCommand()
register_command(GRAPH_COMMAND_INSTANCE)
