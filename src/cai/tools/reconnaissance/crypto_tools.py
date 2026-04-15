"""Hardened crypto analysis and cracking engine for Cerberus AI."""

from __future__ import annotations

import asyncio
import base64
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from hashlib import pbkdf2_hmac, sha256
import json
import math
import os
from pathlib import Path
import re
import secrets
import shutil
from typing import Any, Dict, List, Optional, Sequence
from urllib.parse import unquote_plus

from pydantic import BaseModel, Field

from cai.memory.logic import clean_data
from cai.repl.commands.shell import SecureSubprocess
from cai.repl.ui.logging import get_cerebro_logger
from cai.sdk.agents import function_tool
from cai.tools.validation import sanitize_tool_output
from cai.tools.workspace import get_project_space


class IdentifiedArtifact(BaseModel):
    input_sample: str = Field(default="")
    probable_types: List[str] = Field(default_factory=list)
    probable_encodings: List[str] = Field(default_factory=list)
    entropy_bits_per_char: float = 0.0
    decoded_candidates: List[str] = Field(default_factory=list)


class ProcessEntry(BaseModel):
    pid: int
    user: str
    command: str


class CrackingResult(BaseModel):
    ok: bool
    tool: str
    mode: str
    duration_ms: int
    exit_code: Optional[int] = None
    timed_out: bool = False
    output_redacted: str = ""
    vault_recorded: bool = False


@dataclass
class VaultRecord:
    timestamp: str
    hash_value: str
    algorithm: str
    cleartext_encrypted: str
    source: str


class CerebroCryptoTool:
    """Risk-aware crypto analysis with encrypted credential vaulting."""

    DEFAULT_TIME_LIMIT_SECONDS = 120

    def __init__(self) -> None:
        self._workspace = get_project_space().ensure_initialized().resolve()
        self._secure_subprocess = SecureSubprocess(workspace_root=self._workspace)
        self._logger = get_cerebro_logger()

        self._wordlists_dir = (self._workspace / "config" / "wordlists").resolve()
        self._vault_path = (self._workspace / "credentials.json").resolve()
        self._audit_path = (self._workspace / ".cai" / "audit" / "crypto_jobs.jsonl").resolve()

    async def identify_artifact(self, value: str) -> Dict[str, Any]:
        sample = (value or "").strip()
        if not sample:
            return {"ok": False, "error": {"code": "empty_input", "message": "Input is empty."}}

        probable_types = self._identify_hash_types(sample)
        probable_encodings = self._identify_encodings(sample)
        entropy = self.compute_entropy(sample)
        decoded = self._auto_decode(sample)

        payload = IdentifiedArtifact(
            input_sample=sample[:256],
            probable_types=probable_types,
            probable_encodings=probable_encodings,
            entropy_bits_per_char=round(entropy, 4),
            decoded_candidates=decoded,
        )
        return {"ok": True, "analysis": payload.model_dump()}

    def compute_entropy(self, value: str) -> float:
        if not value:
            return 0.0
        counts: Dict[str, int] = {}
        for ch in value:
            counts[ch] = counts.get(ch, 0) + 1
        length = len(value)
        entropy = 0.0
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    async def decode_value(self, value: str) -> Dict[str, Any]:
        sample = (value or "").strip()
        if not sample:
            return {"ok": False, "error": {"code": "empty_input", "message": "Input is empty."}}
        return {"ok": True, "decoded": self._auto_decode(sample)}

    async def execute_cracking_job(
        self,
        *,
        hash_value: str,
        algorithm_hint: str = "",
        mode: str = "wordlist",
        input_file: str = "",
        wordlist: str = "",
        time_limit_seconds: int = DEFAULT_TIME_LIMIT_SECONDS,
    ) -> Dict[str, Any]:
        started = datetime.now(tz=UTC)
        time_limit_seconds = max(5, min(int(time_limit_seconds), 3600))

        if not hash_value and not input_file:
            return self._error("invalid_input", "Provide hash_value or input_file.")

        tool = self._select_cracker()
        if not tool:
            return self._error("missing_dependency", "Neither hashcat nor john is available.")

        detected = self._identify_hash_types(hash_value) if hash_value else []
        algorithm = algorithm_hint.strip() or (detected[0] if detected else "UNKNOWN")

        hash_file_path = await self._prepare_hash_input(hash_value=hash_value, input_file=input_file)
        if not hash_file_path:
            return self._error("invalid_hash_input", "Unable to prepare hash input.")

        input_sha = self._sha256_file(hash_file_path)
        wordlist_path = self._select_wordlist(wordlist)

        argv = self._build_cracker_argv(
            tool=tool,
            mode=mode,
            hash_file=hash_file_path,
            algorithm=algorithm,
            wordlist_path=wordlist_path,
        )
        if not argv:
            return self._error("invalid_mode", "Unsupported cracking mode or tool arguments.")

        command_line = " ".join(argv)
        self._secure_subprocess.enforce_denylist(command_line)

        clean_env, redaction_map = self._secure_subprocess.build_clean_environment()
        process = await asyncio.create_subprocess_exec(
            *argv,
            cwd=str(self._workspace),
            env=clean_env,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        timed_out = False
        try:
            out, err = await asyncio.wait_for(process.communicate(), timeout=time_limit_seconds)
        except asyncio.TimeoutError:
            timed_out = True
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=2)
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
            out, err = b"", b"Cracking job timed out by policy"

        ended = datetime.now(tz=UTC)
        duration_ms = int((ended - started).total_seconds() * 1000)

        stdout = self._secure_subprocess.redact_text(out.decode("utf-8", errors="replace"), redaction_map)
        stderr = self._secure_subprocess.redact_text(err.decode("utf-8", errors="replace"), redaction_map)
        merged = (stdout + "\n" + stderr).strip()

        cracked = self._extract_cracked_pairs(tool=tool, output=merged, hash_file=hash_file_path)
        vault_recorded = False
        if cracked:
            await self._store_vault_records(cracked, source=hash_file_path.name)
            vault_recorded = True

        redacted_output = self._redact_sensitive_output(merged)
        result = CrackingResult(
            ok=(not timed_out and (process.returncode == 0)),
            tool=tool,
            mode=mode,
            duration_ms=max(0, duration_ms),
            exit_code=process.returncode,
            timed_out=timed_out,
            output_redacted=sanitize_tool_output("crypto_cracker", redacted_output),
            vault_recorded=vault_recorded,
        )

        await self._log_forensic_attempt(
            algorithm=algorithm,
            mode=mode,
            tool=tool,
            duration_ms=result.duration_ms,
            input_sha256=input_sha,
            success=bool(cracked),
        )

        return {"ok": True, "result": result.model_dump(), "identified": detected}

    def _identify_hash_types(self, value: str) -> List[str]:
        out: List[str] = []
        v = value.strip()
        if re.fullmatch(r"[a-fA-F0-9]{32}", v):
            out.extend(["MD5", "NTLM"])
        if re.fullmatch(r"[a-fA-F0-9]{40}", v):
            out.append("SHA1")
        if re.fullmatch(r"[a-fA-F0-9]{56}", v):
            out.append("SHA224")
        if re.fullmatch(r"[a-fA-F0-9]{64}", v):
            out.append("SHA256")
        if re.fullmatch(r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}", v):
            out.append("BCRYPT")
        if re.fullmatch(r"\$6\$[^$]{1,16}\$[./A-Za-z0-9]{43,86}", v):
            out.append("SHA512_CRYPT")
        if not out:
            out.append("UNKNOWN")
        return list(dict.fromkeys(out))

    def _identify_encodings(self, value: str) -> List[str]:
        out: List[str] = []
        v = value.strip()
        if re.fullmatch(r"[A-Za-z0-9+/=\s]+", v) and len(v) % 4 == 0:
            out.append("BASE64")
        if re.fullmatch(r"(?:0x)?[a-fA-F0-9]+", v) and len(v.replace("0x", "")) % 2 == 0:
            out.append("HEX")
        if re.search(r"%[0-9A-Fa-f]{2}", v):
            out.append("URL_ENCODED")
        if not out:
            out.append("PLAIN_OR_BINARY")
        return out

    def _auto_decode(self, value: str) -> List[str]:
        out: List[str] = []
        v = value.strip()

        if re.search(r"%[0-9A-Fa-f]{2}", v):
            with_s = unquote_plus(v)
            out.append(f"URL_DECODED: {with_s[:400]}")

        b64 = re.sub(r"\s+", "", v)
        try:
            if b64 and len(b64) % 4 == 0:
                decoded = base64.b64decode(b64, validate=True)
                out.append("BASE64_DECODED: " + decoded.decode("utf-8", errors="replace")[:400])
        except Exception:
            pass

        hex_candidate = v[2:] if v.lower().startswith("0x") else v
        try:
            if re.fullmatch(r"[a-fA-F0-9]+", hex_candidate) and len(hex_candidate) % 2 == 0:
                out.append("HEX_DECODED: " + bytes.fromhex(hex_candidate).decode("utf-8", errors="replace")[:400])
        except Exception:
            pass

        return out

    async def _prepare_hash_input(self, *, hash_value: str, input_file: str) -> Optional[Path]:
        if input_file:
            path = Path(input_file).expanduser()
            if not path.is_absolute():
                path = (self._workspace / path).resolve()
            if not path.exists() or not path.is_file():
                return None
            try:
                path.relative_to(self._workspace)
            except ValueError:
                return None
            return path

        hv = (hash_value or "").strip()
        if not hv:
            return None
        target = (self._workspace / ".cai" / "tmp" / f"hash_{secrets.token_hex(6)}.txt").resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(hv + "\n", encoding="utf-8")
        return target

    def _select_cracker(self) -> str:
        hashcat = shutil.which("hashcat")
        if hashcat:
            return hashcat
        john = shutil.which("john")
        if john:
            return john
        return ""

    def _select_wordlist(self, requested: str) -> Optional[Path]:
        self._wordlists_dir.mkdir(parents=True, exist_ok=True)
        if requested:
            candidate = (self._wordlists_dir / requested).resolve()
            if candidate.exists() and candidate.is_file():
                return candidate
        common = ["rockyou.txt", "common.txt", "top1000.txt", "wordlist.txt"]
        for name in common:
            c = (self._wordlists_dir / name).resolve()
            if c.exists() and c.is_file():
                return c
        return None

    def _build_cracker_argv(
        self,
        *,
        tool: str,
        mode: str,
        hash_file: Path,
        algorithm: str,
        wordlist_path: Optional[Path],
    ) -> List[str]:
        mode_n = (mode or "wordlist").strip().lower()
        algo_n = algorithm.upper()

        if tool.endswith("hashcat"):
            hash_mode = {
                "MD5": "0",
                "SHA1": "100",
                "SHA256": "1400",
                "NTLM": "1000",
                "BCRYPT": "3200",
            }.get(algo_n, "0")
            argv = [tool, "-m", hash_mode, "-a", "0", str(hash_file)]
            if mode_n == "wordlist" and wordlist_path:
                argv.append(str(wordlist_path))
            elif mode_n == "mask":
                argv.append("?a?a?a?a?a?a")
            return argv

        if tool.endswith("john"):
            argv = [tool]
            if mode_n == "wordlist" and wordlist_path:
                argv.extend(["--wordlist", str(wordlist_path)])
            elif mode_n == "mask":
                argv.extend(["--mask=?a?a?a?a?a?a"])
            fmt = {
                "MD5": "raw-md5",
                "SHA1": "raw-sha1",
                "SHA256": "raw-sha256",
                "NTLM": "nt",
                "BCRYPT": "bcrypt",
            }.get(algo_n)
            if fmt:
                argv.extend(["--format", fmt])
            argv.append(str(hash_file))
            return argv

        return []

    def _extract_cracked_pairs(self, *, tool: str, output: str, hash_file: Path) -> List[tuple[str, str, str]]:
        records: List[tuple[str, str, str]] = []

        if tool.endswith("john"):
            show_cmd = [tool, "--show", str(hash_file)]
            try:
                show_out = self._run_sync_capture(show_cmd)
                for line in show_out.splitlines():
                    if ":" in line and not line.startswith(" "):
                        parts = line.split(":")
                        if len(parts) >= 2 and parts[1]:
                            records.append((parts[0], "UNKNOWN", parts[1]))
            except Exception:
                pass

        if tool.endswith("hashcat"):
            for line in output.splitlines():
                if ":" in line:
                    hv, plain = line.split(":", 1)
                    if hv.strip() and plain.strip() and len(hv.strip()) >= 8:
                        records.append((hv.strip(), "UNKNOWN", plain.strip()))

        return records

    async def _store_vault_records(self, items: Sequence[tuple[str, str, str]], source: str) -> None:
        existing = self._load_vault_records()
        for hash_value, algorithm, cleartext in items:
            encrypted = self._encrypt_cleartext(cleartext)
            record = VaultRecord(
                timestamp=datetime.now(tz=UTC).isoformat(),
                hash_value=hash_value,
                algorithm=algorithm,
                cleartext_encrypted=encrypted,
                source=source,
            )
            existing.append(asdict(record))
        self._vault_path.write_text(json.dumps(clean_data(existing), ensure_ascii=True, indent=2), encoding="utf-8")

    def _load_vault_records(self) -> List[Dict[str, Any]]:
        if not self._vault_path.exists():
            return []
        try:
            payload = json.loads(self._vault_path.read_text(encoding="utf-8"))
            if isinstance(payload, list):
                return payload
        except Exception:
            pass
        return []

    def _encrypt_cleartext(self, cleartext: str) -> str:
        master = os.getenv("CEREBRO_PROJECT_MASTER_KEY", "") or os.getenv("CEREBRO_MASTER_KEY", "")
        if not master:
            # Fallback uses workspace-derived key to keep vault encrypted at rest.
            master = sha256(str(self._workspace).encode("utf-8")).hexdigest()

        salt = secrets.token_bytes(16)
        key = pbkdf2_hmac("sha256", master.encode("utf-8"), salt, 120000, dklen=32)
        data = cleartext.encode("utf-8")
        stream = self._keystream(key=key, length=len(data))
        cipher = bytes(a ^ b for a, b in zip(data, stream))
        payload = {
            "kdf": "pbkdf2-sha256",
            "iter": 120000,
            "salt": base64.b64encode(salt).decode("ascii"),
            "ciphertext": base64.b64encode(cipher).decode("ascii"),
        }
        return base64.b64encode(json.dumps(payload, ensure_ascii=True).encode("utf-8")).decode("ascii")

    @staticmethod
    def _keystream(*, key: bytes, length: int) -> bytes:
        out = b""
        counter = 0
        while len(out) < length:
            block = sha256(key + counter.to_bytes(8, "big")).digest()
            out += block
            counter += 1
        return out[:length]

    async def _log_forensic_attempt(
        self,
        *,
        algorithm: str,
        mode: str,
        tool: str,
        duration_ms: int,
        input_sha256: str,
        success: bool,
    ) -> None:
        entry = {
            "timestamp": datetime.now(tz=UTC).isoformat(),
            "agent_id": self._agent_id(),
            "algorithm": algorithm,
            "mode": mode,
            "tool": Path(tool).name,
            "duration_ms": duration_ms,
            "input_sha256": input_sha256,
            "success": success,
        }
        self._audit_path.parent.mkdir(parents=True, exist_ok=True)
        with self._audit_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(clean_data(entry), ensure_ascii=True) + "\n")

        if self._logger is not None:
            try:
                self._logger.audit("Crypto cracking attempt", actor="crypto_tools", data=entry, tags=["crypto", "crack"])
            except Exception:
                pass

    @staticmethod
    def _sha256_file(path: Path) -> str:
        digest = sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _redact_sensitive_output(text: str) -> str:
        output = text or ""
        output = re.sub(r"\b[a-fA-F0-9]{32,128}\b", "[REDACTED_HASH]", output)
        output = re.sub(r"(?i)(password|passwd|secret|token)\s*[:=]\s*\S+", r"\1=[REDACTED_SECRET]", output)
        return output

    @staticmethod
    def _agent_id() -> str:
        for key in ("CEREBRO_AGENT_ID", "AGENT_ID", "CEREBRO_AGENT", "CEREBRO_AGENT_TYPE"):
            value = os.getenv(key, "").strip()
            if value:
                return value
        return "unknown-agent"

    @staticmethod
    def _run_sync_capture(argv: Sequence[str]) -> str:
        import subprocess

        proc = subprocess.run(argv, capture_output=True, text=True, check=False)
        return (proc.stdout or "") + "\n" + (proc.stderr or "")

    @staticmethod
    def _error(code: str, message: str) -> Dict[str, Any]:
        return {"ok": False, "error": {"code": code, "message": message}}


CRYPTO_TOOL = CerebroCryptoTool()


@function_tool
async def strings_command(file_path: str, timeout: int = 10) -> str:
    path = Path(file_path).expanduser() if file_path else Path("")
    if not file_path:
        return "Error: file_path is required"
    if not path.is_absolute():
        path = (get_project_space().ensure_initialized().resolve() / path).resolve()
    if not path.exists() or not path.is_file():
        return "Error: file_path not found"

    clean_env, redactions = CRYPTO_TOOL._secure_subprocess.build_clean_environment()
    proc = await asyncio.create_subprocess_exec(
        "strings",
        str(path),
        cwd=str(get_project_space().ensure_initialized().resolve()),
        env=clean_env,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=max(1, int(timeout)))
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return "Error: strings timed out"

    text = (out or b"").decode("utf-8", errors="replace") + (err or b"").decode("utf-8", errors="replace")
    text = CRYPTO_TOOL._secure_subprocess.redact_text(text, redactions)
    text = CRYPTO_TOOL._redact_sensitive_output(text)
    return sanitize_tool_output("strings", text)


@function_tool
async def decode64(input_data: str, max_input: int = 200_000) -> str:
    if not input_data:
        return ""
    cleaned = re.sub(r"\s+", "", input_data)
    if len(cleaned) > max_input:
        return "Error: input too large"
    try:
        decoded = base64.b64decode(cleaned, validate=True)
    except Exception as exc:
        return f"Error decoding base64: {exc}"
    return decoded.decode("utf-8", errors="replace")


@function_tool
async def decode_hex_bytes(input_data: str, max_bytes: int = 16_384) -> str:
    if not input_data:
        return ""
    raw = re.sub(r"\s+", "", input_data)
    if raw.lower().startswith("0x"):
        raw = raw[2:]
    if len(raw) % 2 != 0:
        return "Error decoding hex bytes: odd-length token"
    try:
        data = bytes.fromhex(raw)
    except Exception as exc:
        return f"Error decoding hex bytes: {exc}"
    if len(data) > max_bytes:
        return f"Error: decoded output too large (>{max_bytes} bytes)"
    return data.decode("utf-8", errors="replace")


@function_tool
async def identify_crypto_material(value: str) -> Dict[str, Any]:
    return await CRYPTO_TOOL.identify_artifact(value)


@function_tool
async def analyze_entropy(value: str) -> Dict[str, Any]:
    if value is None:
        return {"ok": False, "error": {"code": "invalid_input", "message": "value is required"}}
    entropy = CRYPTO_TOOL.compute_entropy(value)
    return {"ok": True, "entropy_bits_per_char": round(entropy, 6), "length": len(value)}


@function_tool
async def execute_cracking_job(
    hash_value: str = "",
    algorithm_hint: str = "",
    mode: str = "wordlist",
    input_file: str = "",
    wordlist: str = "",
    time_limit_seconds: int = 120,
) -> Dict[str, Any]:
    return await CRYPTO_TOOL.execute_cracking_job(
        hash_value=hash_value,
        algorithm_hint=algorithm_hint,
        mode=mode,
        input_file=input_file,
        wordlist=wordlist,
        time_limit_seconds=time_limit_seconds,
    )


__all__ = [
    "CerebroCryptoTool",
    "CRYPTO_TOOL",
    "strings_command",
    "decode64",
    "decode_hex_bytes",
    "identify_crypto_material",
    "analyze_entropy",
    "execute_cracking_job",
]
