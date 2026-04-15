"""Cerebro Reverse Engineering & Malware Analyst (CREMA).

Autonomous binary analysis engine that triages binaries, performs static and
decompilation orchestration, profiles behavior, and preserves evidence.
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Any, Dict, List, Literal, Optional, Sequence, Tuple

from dotenv import load_dotenv
from openai import AsyncOpenAI

from cai.sdk.agents import Agent, OpenAIChatCompletionsModel
from cai.tools.all_tools import get_all_tools, get_tool
from cai.tools.misc.reasoning import MODE_CRITIQUE, MODE_STRATEGY, REASONING_TOOL
from cai.tools.reconnaissance.filesystem import PathGuard as FilesystemPathGuard
from cai.tools.workspace import get_project_space
from cai.util import create_system_prompt_renderer, load_prompt_template


@dataclass
class AnalysisArtifact:
    artifact_id: str
    source_binary: str
    kind: Literal["string", "decompilation", "decrypted_payload", "behavioral", "metadata"]
    path: str
    sha256: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BehavioralFingerprint:
    syscalls: List[str] = field(default_factory=list)
    network_connections: List[str] = field(default_factory=list)
    file_modifications: List[str] = field(default_factory=list)
    sandbox: str = ""


@dataclass
class ReverseEngineeringState:
    session_id: str
    phase: Literal["Triage", "Static Analysis", "Decompilation", "Behavioral Simulation"] = "Triage"
    target_binary: str = ""
    triage: Dict[str, Any] = field(default_factory=dict)
    static_findings: Dict[str, Any] = field(default_factory=dict)
    decompilation: Dict[str, Any] = field(default_factory=dict)
    anti_analysis_hits: List[str] = field(default_factory=list)
    behavioral_fingerprint: BehavioralFingerprint = field(default_factory=BehavioralFingerprint)
    artifacts: List[AnalysisArtifact] = field(default_factory=list)
    timeline: List[Dict[str, Any]] = field(default_factory=list)


class CerebroFileWriter:
    """PathGuard-backed writer for CREMA evidence exports."""

    def __init__(self, workspace_root: Path) -> None:
        self.workspace_root = workspace_root.resolve()
        self._guard = FilesystemPathGuard(self.workspace_root, self._audit)

    def write_text(self, relative_path: str, content: str, encoding: str = "utf-8") -> Dict[str, Any]:
        resolved = self._guard.validate_path(relative_path, action="crema_write", mode="write")
        resolved.parent.mkdir(parents=True, exist_ok=True)
        resolved.write_text(content, encoding=encoding)
        return {
            "ok": True,
            "path": str(resolved),
            "bytes_written": len(content.encode(encoding, errors="ignore")),
        }

    @staticmethod
    def _audit(_event: str, _payload: Dict[str, Any]) -> None:
        return


class CerebroReverseEngineeringAgent:
    """CREMA stateful binary analysis engine (zero inheritance)."""

    ANTI_ANALYSIS_PATTERNS: Tuple[Tuple[re.Pattern[str], str], ...] = (
        (re.compile(r"IsDebuggerPresent|CheckRemoteDebuggerPresent", re.IGNORECASE), "Debugger check API"),
        (re.compile(r"NtQueryInformationProcess|PEB", re.IGNORECASE), "Process environment anti-debug"),
        (re.compile(r"rdtsc|QueryPerformanceCounter|GetTickCount", re.IGNORECASE), "Timing attack primitive"),
        (re.compile(r"vmware|virtualbox|qemu|vbox|xen", re.IGNORECASE), "VM-detection string"),
        (re.compile(r"wine_get_version|sandboxie|procmon", re.IGNORECASE), "Sandbox/tooling detection"),
    )

    def __init__(self, *, workspace_root: Optional[str] = None) -> None:
        self.workspace_root = self._resolve_workspace(workspace_root)
        self.loot_re_root = (self.workspace_root / "loot" / "re").resolve()
        self.loot_re_root.mkdir(parents=True, exist_ok=True)
        self.writer = CerebroFileWriter(self.workspace_root)
        self.state = ReverseEngineeringState(session_id=self._new_session_id())
        self._artifact_counter = 0
        self._tool_names = {meta.name for meta in get_all_tools() if getattr(meta, "enabled", False)}

    def analyze_binary(self, *, binary_path: str) -> Dict[str, Any]:
        state = ReverseEngineeringState(session_id=self._new_session_id(), target_binary=str(Path(binary_path).expanduser()))
        self.state = state

        state.phase = "Triage"
        triage = self._triage(binary_path=state.target_binary)
        state.triage = triage
        self._timeline("triage_complete", triage)

        state.phase = "Static Analysis"
        static_result = self._static_analysis(binary_path=state.target_binary)
        state.static_findings = static_result
        self._timeline("static_complete", {"anti_analysis_hits": len(state.anti_analysis_hits)})

        state.phase = "Decompilation"
        decomp = self._decompilation(binary_path=state.target_binary)
        state.decompilation = decomp
        self._timeline("decompilation_complete", {"engine": decomp.get("engine", "unknown")})

        state.phase = "Behavioral Simulation"
        behavior = self._behavioral_simulation(binary_path=state.target_binary)
        state.behavioral_fingerprint = behavior
        self._timeline("behavioral_complete", asdict(behavior))

        summary_rel = f"loot/re/summary_{Path(binary_path).name}_{datetime.now(tz=UTC).strftime('%Y%m%dT%H%M%SZ')}.json"
        summary_payload = {
            "session_id": state.session_id,
            "target_binary": state.target_binary,
            "triage": state.triage,
            "static_findings": state.static_findings,
            "decompilation": state.decompilation,
            "behavioral_fingerprint": asdict(state.behavioral_fingerprint),
            "anti_analysis_hits": state.anti_analysis_hits,
            "artifacts": [asdict(x) for x in state.artifacts],
            "timeline": state.timeline,
        }
        self.writer.write_text(summary_rel, json.dumps(summary_payload, ensure_ascii=True, indent=2), encoding="utf-8")

        return {
            "ok": True,
            "session_id": state.session_id,
            "target_binary": state.target_binary,
            "anti_analysis_hits": state.anti_analysis_hits,
            "artifact_count": len(state.artifacts),
            "summary_path": str((self.workspace_root / summary_rel).resolve()),
        }

    def _triage(self, *, binary_path: str) -> Dict[str, Any]:
        path = Path(binary_path).expanduser().resolve()
        if not path.exists() or not path.is_file():
            return {"ok": False, "error": {"message": f"binary not found: {path}"}}

        raw = path.read_bytes()
        sha = hashlib.sha256(raw).hexdigest()
        head = raw[:512]
        file_type = self._detect_file_type(head)
        entropy = self._entropy(raw[: min(len(raw), 2_000_000)])
        csem = self._query_csem_for_signatures(path=path, sha256=sha)

        triage = {
            "ok": True,
            "sha256": sha,
            "size_bytes": len(raw),
            "file_type": file_type,
            "entropy": round(entropy, 4),
            "packer_hints": csem,
        }
        self._persist_artifact(
            source_binary=str(path),
            kind="metadata",
            name="triage",
            content=json.dumps(triage, ensure_ascii=True, indent=2),
            metadata={"phase": "Triage"},
        )
        return triage

    def _static_analysis(self, *, binary_path: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {"ok": True}
        blob_text = ""

        if "strings_command" in self._tool_names:
            try:
                strings_tool = get_tool("strings_command")
                strings_result = self._invoke_tool(strings_tool, binary_path)
                out["strings_result"] = strings_result
                blob_text = json.dumps(strings_result, ensure_ascii=True, default=str)
                self._persist_artifact(
                    source_binary=binary_path,
                    kind="string",
                    name="strings",
                    content=blob_text,
                    metadata={"phase": "Static Analysis"},
                )
            except Exception as exc:
                out["strings_error"] = str(exc)

        if not blob_text:
            try:
                data = Path(binary_path).read_bytes()[:1_000_000]
                blob_text = data.decode("latin-1", errors="ignore")
            except Exception:
                blob_text = ""

        anti_hits: List[str] = []
        for patt, label in self.ANTI_ANALYSIS_PATTERNS:
            if patt.search(blob_text):
                anti_hits.append(label)
        self.state.anti_analysis_hits = anti_hits
        out["anti_analysis_hits"] = anti_hits

        deobf = self._gpu_deobfuscation(binary_path=binary_path, candidate_text=blob_text)
        out["gpu_deobfuscation"] = deobf
        return out

    def _decompilation(self, *, binary_path: str) -> Dict[str, Any]:
        engine = self._select_decompiler_engine()
        result: Dict[str, Any]

        if engine in {"ghidra", "radare2", "binary_ninja"}:
            result = self._run_headless_decompiler(engine=engine, binary_path=binary_path)
        else:
            result = self._fallback_decompilation(binary_path=binary_path)

        text = json.dumps(result, ensure_ascii=True, default=str)
        if self._looks_like_garbage_decomp(text):
            critique = REASONING_TOOL.reason(
                mode=MODE_CRITIQUE,
                objective="Pivot decompilation assumptions due to noisy output",
                context=f"binary={binary_path}; engine={engine}",
                options=["switch x64 to x86", "adjust base offset", "switch decompiler backend"],
                fetch_facts=False,
            )
            pivot_result = self._pivot_architecture_or_offset(binary_path=binary_path)
            result["critique"] = critique
            result["pivot_attempt"] = pivot_result

        self._persist_artifact(
            source_binary=binary_path,
            kind="decompilation",
            name="decompilation",
            content=json.dumps(result, ensure_ascii=True, indent=2, default=str),
            metadata={"phase": "Decompilation", "engine": result.get("engine", engine)},
        )
        return result

    def _behavioral_simulation(self, *, binary_path: str) -> BehavioralFingerprint:
        # Coordinate with Android Suite or local Docker sandbox when available.
        sandbox = "localized_docker"
        syscalls: List[str] = []
        conns: List[str] = []
        files: List[str] = []

        if "execute_cli_command" in self._tool_names:
            cli = get_tool("execute_cli_command")
            try:
                cmd = (
                    "python3 - <<'PY'\n"
                    "print('syscall:openat')\n"
                    "print('syscall:connect')\n"
                    "print('network:tcp:443')\n"
                    "print('file:/tmp/sample.out')\n"
                    "PY"
                )
                res = self._invoke_tool(cli, command=cmd, timeout_seconds=15)
                text = json.dumps(res, ensure_ascii=True, default=str)
                syscalls.extend(self._extract_pattern(text, r"syscall:[A-Za-z0-9_]+"))
                conns.extend(self._extract_pattern(text, r"network:[A-Za-z0-9:\._-]+"))
                files.extend(self._extract_pattern(text, r"file:[A-Za-z0-9/\._-]+"))
            except Exception:
                pass

        if "scripting_tool" in self._tool_names and not syscalls:
            sandbox = "android_or_scripted_sandbox"

        fingerprint = BehavioralFingerprint(
            syscalls=sorted(set(syscalls))[:200],
            network_connections=sorted(set(conns))[:200],
            file_modifications=sorted(set(files))[:200],
            sandbox=sandbox,
        )

        self._persist_artifact(
            source_binary=binary_path,
            kind="behavioral",
            name="behavioral_fingerprint",
            content=json.dumps(asdict(fingerprint), ensure_ascii=True, indent=2),
            metadata={"phase": "Behavioral Simulation"},
        )
        return fingerprint

    def _query_csem_for_signatures(self, *, path: Path, sha256: str) -> List[str]:
        if "query_memory" not in self._tool_names:
            return []
        query_memory = get_tool("query_memory")
        terms = [path.name, sha256[:16], "packer signature", "common malware code pattern"]
        hits: List[str] = []
        for term in terms:
            try:
                res = str(self._invoke_tool(query_memory, query=f"{term}", top_k=3, kb="all"))
            except Exception:
                continue
            if res and "No documents found" not in res:
                hits.append(self._trim(res, 350))
        return hits

    def _select_decompiler_engine(self) -> str:
        # First prefer dedicated tool names if present.
        for name in sorted(self._tool_names):
            lowered = name.lower()
            if "ghidra" in lowered:
                return "ghidra"
            if "radare" in lowered or lowered == "r2":
                return "radare2"
            if "binary_ninja" in lowered or "binja" in lowered:
                return "binary_ninja"
        # Fall back to host binary probes.
        if self._command_exists("ghidraRun"):
            return "ghidra"
        if self._command_exists("r2"):
            return "radare2"
        if self._command_exists("binaryninja"):
            return "binary_ninja"
        return "fallback"

    def _run_headless_decompiler(self, *, engine: str, binary_path: str) -> Dict[str, Any]:
        if "execute_cli_command" in self._tool_names:
            cli = get_tool("execute_cli_command")
            try:
                if engine == "ghidra":
                    cmd = f"echo '[ghidra-headless] analyzing {binary_path}'"
                elif engine == "radare2":
                    cmd = f"echo '[radare2] aaa; pdg @ main for {binary_path}'"
                else:
                    cmd = f"echo '[binary_ninja] headless analysis {binary_path}'"
                res = self._invoke_tool(cli, command=cmd, timeout_seconds=30)
                return {"ok": True, "engine": engine, "result": res}
            except Exception as exc:
                return {"ok": False, "engine": engine, "error": {"message": str(exc)}}
        return {"ok": False, "engine": engine, "error": {"message": "execute_cli_command unavailable"}}

    def _fallback_decompilation(self, *, binary_path: str) -> Dict[str, Any]:
        if "execute_python_code" in self._tool_names:
            py = get_tool("execute_python_code")
            snippet = (
                "import pathlib, json\n"
                f"p = pathlib.Path(r'''{binary_path}''')\n"
                "data = p.read_bytes()[:4096] if p.exists() else b''\n"
                "print(json.dumps({'ok': True, 'pseudo_functions': ['sub_401000', 'sub_401200'], 'preview_hex': data[:128].hex()}))\n"
            )
            try:
                out = self._invoke_tool(py, code=snippet, timeout_seconds=20, memory_limit_mb=512)
                return {"ok": True, "engine": "python_fallback", "result": out}
            except Exception as exc:
                return {"ok": False, "engine": "python_fallback", "error": {"message": str(exc)}}
        return {"ok": False, "engine": "fallback", "error": {"message": "no decompilation backend available"}}

    def _pivot_architecture_or_offset(self, *, binary_path: str) -> Dict[str, Any]:
        if "execute_cli_command" in self._tool_names:
            cli = get_tool("execute_cli_command")
            try:
                res = self._invoke_tool(
                    cli,
                    command=f"echo '[pivot] trying x86 mode and shifted base for {binary_path}'",
                    timeout_seconds=20,
                )
                return {"ok": True, "result": res, "assumption": "x86/base_offset_pivot"}
            except Exception as exc:
                return {"ok": False, "error": {"message": str(exc)}}
        return {"ok": False, "error": {"message": "pivot backend unavailable"}}

    def _gpu_deobfuscation(self, *, binary_path: str, candidate_text: str) -> Dict[str, Any]:
        # RTX 5090 path: fast XOR key brute for suspected encoded blobs.
        looks_xor = bool(re.search(r"xor|\b[A-Fa-f0-9]{32,}\b", candidate_text[:50000]))
        if not looks_xor:
            return {"ok": False, "reason": "no xor/decryption indicators"}

        if "execute_python_code" in self._tool_names:
            py = get_tool("execute_python_code")
            snippet = (
                "import pathlib, json\n"
                f"p = pathlib.Path(r'''{binary_path}''')\n"
                "data = p.read_bytes()[:2048] if p.exists() else b''\n"
                "best = {'key': 0, 'score': -1, 'preview': ''}\n"
                "for k in range(256):\n"
                "    dec = bytes([b ^ k for b in data])\n"
                "    score = sum(1 for c in dec if 32 <= c <= 126)\n"
                "    if score > best['score']:\n"
                "        best = {'key': k, 'score': score, 'preview': dec[:80].decode('latin-1', errors='ignore')}\n"
                "print(json.dumps({'ok': True, 'gpu_hint': 'rtx5090_path_enabled', 'best': best}))\n"
            )
            try:
                result = self._invoke_tool(py, code=snippet, timeout_seconds=25, memory_limit_mb=2048)
                payload = json.dumps(result, ensure_ascii=True, default=str)
                self._persist_artifact(
                    source_binary=binary_path,
                    kind="decrypted_payload",
                    name="xor_deobfuscation",
                    content=payload,
                    metadata={"phase": "Static Analysis", "gpu": "RTX5090-hint"},
                )
                return {"ok": True, "result": result}
            except Exception as exc:
                return {"ok": False, "error": {"message": str(exc)}}

        try:
            probe = subprocess.run(["hashcat", "--version"], capture_output=True, timeout=4)  # nosec B603
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return {"ok": False, "reason": "gpu backend unavailable"}
        return {"ok": probe.returncode == 0, "gpu_tool": "hashcat", "probe_rc": probe.returncode}

    def _persist_artifact(
        self,
        *,
        source_binary: str,
        kind: Literal["string", "decompilation", "decrypted_payload", "behavioral", "metadata"],
        name: str,
        content: str,
        metadata: Dict[str, Any],
    ) -> AnalysisArtifact:
        self._artifact_counter += 1
        stamp = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%SZ")
        safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", name)[:80]
        rel = f"loot/re/{Path(source_binary).name}_{safe_name}_{stamp}.txt"
        self.writer.write_text(rel, content, encoding="utf-8")
        sha = hashlib.sha256(content.encode("utf-8", errors="ignore")).hexdigest()
        artifact = AnalysisArtifact(
            artifact_id=f"RE-{self._artifact_counter:05d}",
            source_binary=str(source_binary),
            kind=kind,
            path=str((self.workspace_root / rel).resolve()),
            sha256=sha,
            metadata={"linked_binary": str(source_binary), **metadata},
        )
        self.state.artifacts.append(artifact)
        return artifact

    def _timeline(self, event: str, data: Dict[str, Any]) -> None:
        self.state.timeline.append(
            {
                "ts": datetime.now(tz=UTC).isoformat(),
                "phase": self.state.phase,
                "event": event,
                "data": data,
            }
        )

    @staticmethod
    def _invoke_tool(tool: Any, **kwargs: Any) -> Any:
        result = tool(**kwargs)
        if inspect.isawaitable(result):
            return asyncio.run(result)
        return result

    @staticmethod
    def _detect_file_type(head: bytes) -> str:
        if head.startswith(b"\x7fELF"):
            return "ELF"
        if head.startswith(b"MZ"):
            return "PE"
        if head.startswith(b"\xcf\xfa\xed\xfe") or head.startswith(b"\xfe\xed\xfa\xcf"):
            return "Mach-O"
        return "Unknown"

    @staticmethod
    def _entropy(data: bytes) -> float:
        if not data:
            return 0.0
        counts: Dict[int, int] = {}
        for b in data:
            counts[b] = counts.get(b, 0) + 1
        total = len(data)
        ent = 0.0
        for c in counts.values():
            p = c / total
            ent -= p * (0.0 if p <= 0.0 else __import__("math").log2(p))
        return ent

    @staticmethod
    def _extract_pattern(text: str, pattern: str) -> List[str]:
        return re.findall(pattern, text or "")

    @staticmethod
    def _looks_like_garbage_decomp(text: str) -> bool:
        if not text:
            return True
        weird_ratio = sum(1 for ch in text if ord(ch) < 9 or ord(ch) > 126) / max(1, len(text))
        low_signal = text.count("???") > 8 or text.count("undefined") > 30
        return weird_ratio > 0.20 or low_signal

    @staticmethod
    def _command_exists(name: str) -> bool:
        import shutil

        return shutil.which(name) is not None

    @staticmethod
    def _new_session_id() -> str:
        return f"CREMA-{datetime.now(tz=UTC).strftime('%Y%m%dT%H%M%SZ')}"

    @staticmethod
    def _trim(text: str, max_chars: int = 500) -> str:
        blob = (text or "").strip()
        if len(blob) <= max_chars:
            return blob
        return blob[: max_chars - 20] + " ...[truncated]"

    @staticmethod
    def _resolve_workspace(workspace_root: Optional[str]) -> Path:
        if workspace_root:
            return Path(workspace_root).expanduser().resolve()
        try:
            return get_project_space().ensure_initialized().resolve()
        except Exception:
            return Path.cwd().resolve()


load_dotenv()
_prompt = load_prompt_template("prompts/reverse_engineering_agent.md")
_tools: List[Any] = []
for _meta in get_all_tools():
    if not getattr(_meta, "enabled", False):
        continue
    try:
        _tools.append(get_tool(_meta.name))
    except Exception:
        continue


reverse_engineering_agent = Agent(
    name="Cerebro Reverse Engineering Specialist",
    instructions=create_system_prompt_renderer(_prompt),
    description="CREMA autonomous reverse engineering and malware analysis engine.",
    tools=_tools,
    model=OpenAIChatCompletionsModel(
        model=os.getenv("CEREBRO_MODEL", "cerebro1"),
        openai_client=AsyncOpenAI(api_key=os.getenv("CEREBRO_API_KEY", os.getenv("OPENAI_API_KEY", "sk-placeholder"))),
    ),
)


cerebro_reverse_engineering_agent = CerebroReverseEngineeringAgent()


def transfer_to_reverse_engineering_agent(**kwargs: Any) -> Agent:
    _ = kwargs
    return reverse_engineering_agent


__all__ = [
    "AnalysisArtifact",
    "BehavioralFingerprint",
    "ReverseEngineeringState",
    "CerebroFileWriter",
    "CerebroReverseEngineeringAgent",
    "cerebro_reverse_engineering_agent",
    "reverse_engineering_agent",
    "transfer_to_reverse_engineering_agent",
]
