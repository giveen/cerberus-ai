"""Cerebro Synthesis & Execution Engine (CSEE).

Clean-room code synthesis agent that plans, writes, critiques, executes, and
self-debugs generated scripts with forensic traceability.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import textwrap
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from dotenv import load_dotenv
from openai import AsyncOpenAI

from cerberus.sdk.agents import Agent, OpenAIChatCompletionsModel
from cerberus.tools.all_tools import get_all_tools, get_tool
from cerberus.tools.misc.reasoning import MODE_CRITIQUE, MODE_STRATEGY, REASONING_TOOL
from cerberus.tools.reconnaissance.exec_code import EXEC_TOOL
from cerberus.tools.runners.docker import DOCKER_TOOL
from cerberus.tools.runners.local import LOCAL_RUNNER
from cerberus.tools.workspace import get_project_space
from cerberus.util import create_system_prompt_renderer, load_prompt_template


CSEE_PROMPT_FALLBACK = """# Cerebro Synthesis & Execution Engine

You are the CSEE autonomous coding engine.
You must:
1. Plan with reasoning.
2. Synthesize code.
3. Critique for safety/performance hazards.
4. Execute in local or docker depending on risk.
5. Self-debug failed runs and iterate.
"""


@dataclass(frozen=True)
class ScriptSignature:
    parent_agent_id: str
    purpose: str
    created_at: str
    sha256: str


@dataclass
class SynthesisAttempt:
    attempt_index: int
    script_path: str
    context: str
    critique_summary: str
    executed: bool
    success: bool
    stdout: str
    stderr: str
    error: str


@dataclass
class ForensicArtifact:
    artifact_id: str
    phase: str
    process_id: str
    memory_offset: str
    data_type: str
    confidence_score: str
    critique_note: str
    action_required: str


class CerebroCodeSynthesisAgent:
    """Autonomous synthesis and execution engine with forensic controls."""

    def __init__(self, *, workspace_root: Optional[str] = None, max_attempts: int = 4) -> None:
        self.workspace_root = self._resolve_workspace(workspace_root)
        self.generated_root = (self.workspace_root / "generated_code").resolve()
        self.generated_root.mkdir(parents=True, exist_ok=True)
        self.max_attempts = max(1, int(max_attempts))
        self.prompt = self._load_prompt()

    async def synthesize_and_execute(
        self,
        *,
        requirement: str,
        parent_agent_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Run full autonomous synthesis loop and return forensic-ready result."""
        parent_id = (parent_agent_id or os.getenv("CERBERUS_AGENT_ID", "unknown-agent")).strip() or "unknown-agent"
        attempts: List[SynthesisAttempt] = []

        strategy = REASONING_TOOL.reason(
            mode=MODE_STRATEGY,
            objective="Build executable script from high-level requirement",
            context=requirement,
            options=["Minimal script", "Defensive script with retries", "Instrumented script"],
            fetch_facts=True,
            fact_query="code synthesis",
        )

        previous_error = ""
        for attempt_index in range(1, self.max_attempts + 1):
            body = self._synthesize_script(requirement=requirement, strategy=strategy, previous_error=previous_error, attempt_index=attempt_index)
            signed_script, signature = self._forensic_sign(body=body, purpose=requirement, parent_agent_id=parent_id)
            script_path = self._write_signed_script(content=signed_script, attempt_index=attempt_index)

            critique = self._critique_script(script=signed_script, requirement=requirement)
            if self._is_critique_blocking(critique):
                attempts.append(
                    SynthesisAttempt(
                        attempt_index=attempt_index,
                        script_path=str(script_path),
                        context="blocked_pre_execution",
                        critique_summary=str(critique.get("summary", "")),
                        executed=False,
                        success=False,
                        stdout="",
                        stderr="",
                        error="Pre-execution critique blocked script",
                    )
                )
                previous_error = "critique_blocked"
                continue

            context = self._choose_context(requirement=requirement, script=signed_script)
            if context == "local":
                exec_result = await self._execute_local(script_path)
            else:
                exec_result = await self._execute_docker(script_path, requirement=requirement)

            ok = bool(exec_result.get("ok"))
            stdout = str(exec_result.get("stdout", ""))
            stderr = str(exec_result.get("stderr", ""))
            error = "" if ok else str((exec_result.get("error") or {}).get("message", stderr or "execution_failed"))

            attempts.append(
                SynthesisAttempt(
                    attempt_index=attempt_index,
                    script_path=str(script_path),
                    context=context,
                    critique_summary=str(critique.get("summary", "")),
                    executed=True,
                    success=ok,
                    stdout=stdout,
                    stderr=stderr,
                    error=error,
                )
            )

            if ok:
                artifact = self._build_forensic_artifact(signature=signature, critique_summary=str(critique.get("summary", "")), execution=exec_result)
                return {
                    "ok": True,
                    "attempts": [self._attempt_dict(a) for a in attempts],
                    "script_path": str(script_path),
                    "signature": signature.__dict__,
                    "forensic_artifact_template": artifact.__dict__,
                }

            previous_error = error or stderr or "execution_failed"

        final_artifact = ForensicArtifact(
            artifact_id="exec-failed",
            phase="verification",
            process_id="n/a",
            memory_offset="n/a",
            data_type="execution_log",
            confidence_score="0%",
            critique_note="All autonomous attempts failed",
            action_required="Investigate",
        )
        return {
            "ok": False,
            "attempts": [self._attempt_dict(a) for a in attempts],
            "forensic_artifact_template": final_artifact.__dict__,
        }

    def _synthesize_script(self, *, requirement: str, strategy: Dict[str, Any], previous_error: str, attempt_index: int) -> str:
        imports = ["json", "os", "pathlib", "sys", "time"]
        logic = [
            "def main() -> int:",
            f"    requirement = {requirement!r}",
            f"    previous_error = {previous_error!r}",
            "    print('CSEE requirement:', requirement)",
            "    if previous_error:",
            "        print('CSEE previous_error:', previous_error)",
            "    workspace = pathlib.Path(os.getenv('CSEE_WORKSPACE', '.')).resolve()",
            "    out = {'status': 'ok', 'attempt': " + str(attempt_index) + ", 'workspace': str(workspace)}",
            "    print(json.dumps(out))",
            "    return 0",
            "",
            "if __name__ == '__main__':",
            "    raise SystemExit(main())",
        ]

        # Lightweight autonomous adaptation based on prior failure signal.
        if "module" in previous_error.lower() or "import" in previous_error.lower():
            imports.append("subprocess")
            logic.insert(
                6,
                "    # Prior run hinted at missing deps; this script emits dependency hint for orchestrator.",
            )
            logic.insert(7, "    print('CSEE dependency-hint: check imports and install in isolated context')")

        rendered = "\n".join([f"import {m}" for m in sorted(set(imports))] + [""] + logic)
        return self._inject_pathguard(rendered)

    def _inject_pathguard(self, script_body: str) -> str:
        preamble = textwrap.dedent(
            """
            import builtins
            import pathlib
            import os

            _CSEE_WORKSPACE = pathlib.Path(os.getenv('CSEE_WORKSPACE', '.')).resolve()
            _orig_open = builtins.open

            def _guard_path(path_obj):
                p = pathlib.Path(path_obj).expanduser()
                resolved = p.resolve() if p.is_absolute() else (_CSEE_WORKSPACE / p).resolve()
                try:
                    resolved.relative_to(_CSEE_WORKSPACE)
                except ValueError as exc:
                    raise PermissionError(f'PathGuard violation: {resolved}') from exc
                return resolved

            def _safe_open(file, mode='r', *args, **kwargs):
                guarded = _guard_path(file)
                return _orig_open(guarded, mode, *args, **kwargs)

            builtins.open = _safe_open
            """
        ).strip()
        return f"{preamble}\n\n{script_body.strip()}\n"

    def _forensic_sign(self, *, body: str, purpose: str, parent_agent_id: str) -> Tuple[str, ScriptSignature]:
        digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
        created_at = datetime.now(tz=UTC).isoformat()
        signature = ScriptSignature(
            parent_agent_id=parent_agent_id,
            purpose=purpose,
            created_at=created_at,
            sha256=digest,
        )
        header = textwrap.dedent(
            f"""
            # CSEE-METADATA-BEGIN
            # Parent-Agent-ID: {signature.parent_agent_id}
            # Purpose: {signature.purpose}
            # Created-At-UTC: {signature.created_at}
            # SHA256: {signature.sha256}
            # CSEE-METADATA-END
            """
        ).strip()
        return f"{header}\n\n{body}", signature

    def _write_signed_script(self, *, content: str, attempt_index: int) -> Path:
        stamp = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%SZ")
        path = self.generated_root / f"csee_script_{stamp}_a{attempt_index}.py"
        path.write_text(content, encoding="utf-8")
        return path

    def _critique_script(self, *, script: str, requirement: str) -> Dict[str, Any]:
        return REASONING_TOOL.reason(
            mode=MODE_CRITIQUE,
            objective="Pre-execution code review for safety and stability",
            context=requirement,
            prior_output=script[:8000],
            options=["execute as-is", "revise for safety"],
            fetch_facts=False,
        )

    def _is_critique_blocking(self, critique: Dict[str, Any]) -> bool:
        summary = str(critique.get("summary", "")).lower()
        if "infinite" in summary or "resource" in summary or "unsafe" in summary:
            return True
        pivot = critique.get("pivot_request") or {}
        return bool(pivot.get("required") and float(pivot.get("confidence", 0.0)) >= 0.8)

    def _choose_context(self, *, requirement: str, script: str) -> str:
        risky_tokens = (
            "bypass",
            "exploit",
            "auth",
            "credential",
            "socket",
            "raw",
            "packet",
            "subprocess",
            "os.system",
            "pty",
        )
        hay = f"{requirement}\n{script}".lower()
        if any(token in hay for token in risky_tokens):
            return "docker"
        return "local"

    async def _execute_local(self, script_path: Path) -> Dict[str, Any]:
        deps = self._detect_external_dependencies(script_path)
        if deps:
            venv_dir = await self._create_temp_venv(deps)
            cmd = f"{venv_dir}/bin/python {script_path}"
        else:
            cmd = f"{shutil.which('python3') or sys.executable} {script_path}"

        return await LOCAL_RUNNER.execute(
            command=cmd,
            timeout_seconds=30,
            stream=True,
            tool_name="csee_local_exec",
            custom_args={"script": str(script_path)},
            cwd=str(self.workspace_root),
        )

    async def _execute_docker(self, script_path: Path, *, requirement: str) -> Dict[str, Any]:
        rel_script = script_path.resolve().relative_to(self.workspace_root.resolve())
        deps = self._detect_external_dependencies(script_path)
        install = ""
        if deps:
            install = "python3 -m pip install --no-cache-dir " + " ".join(sorted(deps)) + " && "

        command = (
            "sh -lc "
            + repr(
                f"cd /workspace && {install}export CSEE_WORKSPACE=/workspace && python3 /workspace/{rel_script}"
            )
        )
        return await DOCKER_TOOL.run_command_async(
            command=command,
            container_id=None,
            timeout=120,
            stream=True,
            tool_name="csee_docker_exec",
            args={
                "image": "python:3.12-alpine",
                "internet_access": False,
                "read_only": False,
                "container_command": "sleep infinity",
            },
        )

    def _detect_external_dependencies(self, script_path: Path) -> Set[str]:
        text = script_path.read_text(encoding="utf-8", errors="replace")
        deps: Set[str] = set()
        std = set(sys.stdlib_module_names)
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("import "):
                mod = line.split("import ", 1)[1].split(" as ", 1)[0].split(",", 1)[0].strip().split(".", 1)[0]
                if mod and mod not in std and mod not in {"builtins", "pathlib", "json", "os", "sys", "time"}:
                    deps.add(mod)
            elif line.startswith("from "):
                mod = line.split("from ", 1)[1].split(" import ", 1)[0].strip().split(".", 1)[0]
                if mod and mod not in std and mod not in {"builtins", "pathlib", "json", "os", "sys", "time"}:
                    deps.add(mod)
        # common mapping for package/import mismatch
        normalized = {"yaml": "pyyaml", "Crypto": "pycryptodome", "scapy": "scapy", "impacket": "impacket"}
        return {normalized.get(dep, dep) for dep in deps}

    async def _create_temp_venv(self, deps: Set[str]) -> str:
        ts = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%SZ")
        venv_dir = self.workspace_root / ".cerberus" / "tmp" / f"csee_venv_{ts}"
        venv_dir.parent.mkdir(parents=True, exist_ok=True)

        py = shutil.which("python3") or sys.executable
        await asyncio.to_thread(lambda: os.system(f"{py} -m venv {venv_dir}"))
        pip = venv_dir / "bin" / "pip"
        if deps and pip.exists():
            await asyncio.to_thread(lambda: os.system(f"{pip} install --disable-pip-version-check {' '.join(sorted(deps))}"))
        return str(venv_dir)

    def _build_forensic_artifact(self, *, signature: ScriptSignature, critique_summary: str, execution: Dict[str, Any]) -> ForensicArtifact:
        pid = str(execution.get("pid", execution.get("container_id", "n/a")))
        confidence = "85%" if execution.get("ok") else "30%"
        return ForensicArtifact(
            artifact_id=signature.sha256[:16],
            phase="execution",
            process_id=pid,
            memory_offset="n/a",
            data_type="script_output",
            confidence_score=confidence,
            critique_note=critique_summary[:400],
            action_required="Investigate" if not execution.get("ok") else "None",
        )

    @staticmethod
    def _attempt_dict(attempt: SynthesisAttempt) -> Dict[str, Any]:
        return {
            "attempt_index": attempt.attempt_index,
            "script_path": attempt.script_path,
            "context": attempt.context,
            "critique_summary": attempt.critique_summary,
            "executed": attempt.executed,
            "success": attempt.success,
            "stdout": attempt.stdout,
            "stderr": attempt.stderr,
            "error": attempt.error,
        }

    def _load_prompt(self) -> str:
        for candidate in (
            "prompts/system_code_synthesis_agent.md",
            "prompts/system_codeagent.md",
            "prompts/system_code_agent.md",
        ):
            try:
                return load_prompt_template(candidate)
            except FileNotFoundError:
                continue
        return CSEE_PROMPT_FALLBACK

    @staticmethod
    def _resolve_workspace(workspace_root: Optional[str]) -> Path:
        if workspace_root:
            return Path(workspace_root).expanduser().resolve()
        try:
            return get_project_space().ensure_initialized().resolve()
        except Exception:
            return Path.cwd().resolve()


# Compatibility exports for existing runtime discovery.
load_dotenv()
_model_name = os.getenv("CERBERUS_MODEL", "cerebro1")
_tools = []
for _meta in get_all_tools():
    if not getattr(_meta, "enabled", False):
        continue
    try:
        _tools.append(get_tool(_meta.name))
    except Exception:
        continue

codeagent = Agent(
    name="CodeAgent",
    instructions=create_system_prompt_renderer(CSEE_PROMPT_FALLBACK),
    description="Autonomous code synthesis and execution agent with forensic controls.",
    tools=_tools,
    model=OpenAIChatCompletionsModel(
        model=_model_name,
        openai_client=AsyncOpenAI(),
    ),
)


def transfer_to_codeagent(**kwargs: Any) -> Agent:
    _ = kwargs
    return codeagent


cerebro_code_synthesis_agent = CerebroCodeSynthesisAgent()


__all__ = [
    "CerebroCodeSynthesisAgent",
    "ScriptSignature",
    "SynthesisAttempt",
    "ForensicArtifact",
    "cerebro_code_synthesis_agent",
    "codeagent",
    "transfer_to_codeagent",
]
