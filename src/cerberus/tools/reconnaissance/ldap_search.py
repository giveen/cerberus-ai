"""Hardened LDAP directory intelligence tool with encrypted transport and triaged output."""

from __future__ import annotations

import asyncio
from contextlib import suppress
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import tempfile
import threading
from typing import Any, Dict, Iterable, List, Optional, Sequence

from cerberus.memory.logic import clean_data
from cerberus.repl.commands.shell import SecureSubprocess
from cerberus.repl.ui.logging import get_cerberus_logger
from cerberus.agents import function_tool
from cerberus.tools._lazy import LazyToolProxy
from cerberus.tools.misc.cli_utils import CLI_UTILS
from cerberus.tools.validation import sanitize_tool_output
from cerberus.tools.workspace import get_project_space


_HIGH_VALUE_ATTRS = {
    "memberof",
    "serviceprincipalname",
    "pwdlastset",
    "description",
    "useraccountcontrol",
    "admincount",
}
_VALID_SCOPES = {"base", "one", "sub", "children"}
_OUTPUT_LIMIT = 50_000
_DEFAULT_MAX_ENTRIES = 100
_DEFAULT_TIMEOUT = 20
_PII_PATTERNS = (
    (re.compile(r"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b"), "[REDACTED_EMAIL]"),
    (re.compile(r"\b\d{1,5}\s+[A-Za-z0-9.\- ]{2,}\s(?:Street|St|Road|Rd|Lane|Ln|Drive|Dr|Court|Ct|Avenue|Ave)\b", re.IGNORECASE), "[REDACTED_ADDRESS]"),
)
_PASSWORD_ATTR_RE = re.compile(r"(?i)(password|userpassword|unicodepwd|pwd|secret)")


@dataclass(frozen=True)
class SemanticError:
    code: str
    message: str
    retryable: bool
    category: str


class PathGuard:
    """Restrict local file inputs used by the LDAP tool to safe sandbox roots."""

    def __init__(self, workspace_root: Path) -> None:
        self._workspace = workspace_root.resolve()
        self._tmp_roots = self._build_tmp_roots()

    def validate_path(self, candidate: str, *, mode: str = "read") -> Path:
        raw = Path(candidate).expanduser()
        resolved = (self._workspace / raw).resolve() if not raw.is_absolute() else raw.resolve()
        if self._is_within(self._workspace, resolved):
            return resolved
        if any(self._is_within(root, resolved) for root in self._tmp_roots):
            return resolved
        raise PermissionError(f"Boundary Violation: path outside allowed roots ({mode}): {resolved}")

    @staticmethod
    def _is_within(root: Path, value: Path) -> bool:
        try:
            value.relative_to(root)
            return True
        except ValueError:
            return False

    @staticmethod
    def _build_tmp_roots() -> List[Path]:
        roots = {Path(tempfile.gettempdir()).resolve(), Path("/var/tmp").resolve()}
        env_tmp = os.getenv("TMPDIR", "").strip()
        if env_tmp:
            with suppress(Exception):
                roots.add(Path(env_tmp).expanduser().resolve())
        return sorted(roots)


class CerebroLDAPTool:
    """Asynchronous LDAP search proxy with strict transport, triage, and forensics."""

    SHORTCUTS: Dict[str, str] = {
        "FIND_DOMAIN_ADMINS": "(&(objectCategory=person)(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:=CN=Domain Admins,CN=Users,{base_dn}))",
        "FIND_UNCONSTRAINED_DELEGATION": "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))",
        "FIND_USER_DESCRIPTIONS": "(&(objectCategory=person)(objectClass=user)(description=*))",
    }

    def __init__(self) -> None:
        self._workspace = get_project_space().ensure_initialized().resolve()
        self._guard = PathGuard(self._workspace)
        self._secure_subprocess = SecureSubprocess(workspace_root=self._workspace)
        self._logger = get_cerberus_logger()
        self._audit_path = (self._workspace / ".cerberus" / "audit" / "ldap_queries.jsonl").resolve()
        self._evidence_dir = (self._workspace / "evidence" / "discovery" / "ldap").resolve()
        self._audit_path.parent.mkdir(parents=True, exist_ok=True)
        self._evidence_dir.mkdir(parents=True, exist_ok=True)
        self._loop = asyncio.new_event_loop()
        self._loop_thread = threading.Thread(target=self._run_loop, daemon=True)
        self._loop_thread.start()

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def _run_coro(self, coro: Any, timeout: float = 180.0) -> Dict[str, Any]:
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return future.result(timeout=timeout)

    def query(
        self,
        *,
        host: str,
        base_dn: str,
        ldap_filter: str,
        attributes: Optional[Sequence[str]] = None,
        bind_dn: str = "",
        password: str = "",
        port: int = 636,
        use_ldaps: bool = True,
        start_tls: bool = True,
        scope: str = "sub",
        max_entries: int = _DEFAULT_MAX_ENTRIES,
        search_timeout: int = _DEFAULT_TIMEOUT,
        shortcut: str = "",
        attribute_wordlist: str = "",
    ) -> Dict[str, Any]:
        return self._run_coro(
            self._query_async(
                host=host,
                base_dn=base_dn,
                ldap_filter=ldap_filter,
                attributes=attributes,
                bind_dn=bind_dn,
                password=password,
                port=port,
                use_ldaps=use_ldaps,
                start_tls=start_tls,
                scope=scope,
                max_entries=max_entries,
                search_timeout=search_timeout,
                shortcut=shortcut,
                attribute_wordlist=attribute_wordlist,
            ),
            timeout=max(45.0, float(search_timeout) + 20.0),
        )

    async def _query_async(
        self,
        *,
        host: str,
        base_dn: str,
        ldap_filter: str,
        attributes: Optional[Sequence[str]],
        bind_dn: str,
        password: str,
        port: int,
        use_ldaps: bool,
        start_tls: bool,
        scope: str,
        max_entries: int,
        search_timeout: int,
        shortcut: str,
        attribute_wordlist: str,
    ) -> Dict[str, Any]:
        if not host.strip():
            return self._error("invalid_target", "host is required")

        ldap_bin = shutil.which("ldapsearch")
        if not ldap_bin:
            return self._error("missing_dependency", "ldapsearch binary not found on host PATH")

        scope_norm = scope.strip().lower() if scope else "sub"
        if scope_norm not in _VALID_SCOPES:
            scope_norm = "sub"
        max_entries = max(1, min(int(max_entries), 500))
        search_timeout = max(3, min(int(search_timeout), 120))

        resolved_filter = self._resolve_filter(shortcut=shortcut, ldap_filter=ldap_filter, base_dn=base_dn)
        attrs = [item.strip() for item in (attributes or []) if str(item).strip()]
        if attribute_wordlist.strip():
            attrs.extend(await self._read_attribute_wordlist(attribute_wordlist))
        attrs = sorted(set(attrs))[:80]

        if port == 636:
            use_ldaps = True

        uri_scheme = "ldaps" if use_ldaps else "ldap"
        uri = f"{uri_scheme}://{host}:{int(port)}"

        argv = [
            ldap_bin,
            "-x",
            "-LLL",
            "-o",
            "ldif-wrap=no",
            "-H",
            uri,
            "-l",
            str(search_timeout),
            "-z",
            str(max_entries),
            "-s",
            scope_norm,
            "-b",
            base_dn or "",
        ]
        if not use_ldaps and start_tls:
            argv.append("-ZZ")

        password_file: Optional[Path] = None
        if bind_dn.strip():
            argv.extend(["-D", bind_dn.strip()])
            if password:
                password_file = await self._create_password_file(password)
                argv.extend(["-y", str(password_file)])

        argv.append(resolved_filter)
        if attrs:
            argv.extend(attrs)

        clean_env, redactions = self._secure_subprocess.build_clean_environment()
        with CLI_UTILS.managed_env_context(base_env=clean_env) as runtime_env:
            process = await asyncio.create_subprocess_exec(
                *argv,
                cwd=str(self._workspace),
                env=runtime_env,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout_raw, stderr_raw = await asyncio.wait_for(process.communicate(), timeout=float(search_timeout + 5))
                timed_out = False
            except asyncio.TimeoutError:
                timed_out = True
                process.terminate()
                with suppress(Exception):
                    await asyncio.wait_for(process.wait(), timeout=2.0)
                if process.returncode is None:
                    process.kill()
                    await process.wait()
                stdout_raw, stderr_raw = b"", b"LDAP query timed out by policy."
        if password_file is not None:
            with suppress(Exception):
                password_file.unlink(missing_ok=True)

        stdout_txt = self._secure_subprocess.redact_text(stdout_raw.decode("utf-8", errors="replace"), redactions)
        stderr_txt = self._secure_subprocess.redact_text(stderr_raw.decode("utf-8", errors="replace"), redactions)
        stdout_txt = self._scrub_text(stdout_txt)
        stderr_txt = self._scrub_text(stderr_txt)
        stdout_txt = stdout_txt[:_OUTPUT_LIMIT]
        stderr_txt = stderr_txt[:_OUTPUT_LIMIT]

        exit_code = process.returncode if process.returncode is not None else -1
        if timed_out:
            await self._audit(
                event="ldap_query_timeout",
                data={"target": host, "filter": resolved_filter, "exit_code": exit_code, "result_count": 0},
            )
            return self._error("timeout", "LDAP query exceeded timeout policy")

        if exit_code != 0:
            semantic = self._semantic_error(exit_code, stderr_txt)
            await self._audit(
                event="ldap_query_failed",
                data={"target": host, "filter": resolved_filter, "exit_code": exit_code, "result_count": 0},
            )
            return clean_data({"ok": False, "error": asdict(semantic), "stderr": sanitize_tool_output("ldap_stderr", stderr_txt)})

        entries = self._parse_ldif(stdout_txt)
        triaged = self._triage(entries)
        serialized = json.dumps(clean_data(entries), ensure_ascii=True, sort_keys=True)
        result_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        evidence_path = self._evidence_dir / f"LDAP_{datetime.now(tz=UTC).strftime('%Y%m%dT%H%M%SZ')}_{secrets.token_hex(4)}.json"
        evidence_payload = {
            "target": host,
            "timestamp": datetime.now(tz=UTC).isoformat(),
            "filter": resolved_filter,
            "base_dn": base_dn,
            "result_count": len(entries),
            "result_hash": result_hash,
            "entries": clean_data(entries),
        }
        evidence_path.write_text(json.dumps(evidence_payload, ensure_ascii=True, indent=2), encoding="utf-8")

        await self._audit(
            event="ldap_query_completed",
            data={
                "target_dc": host,
                "filter": resolved_filter,
                "result_count": len(entries),
                "result_hash": result_hash,
                "exit_code": exit_code,
                "user_context": bind_dn.strip() or "anonymous",
            },
        )

        return clean_data(
            {
                "ok": True,
                "target": host,
                "transport": "ldaps" if use_ldaps else ("ldap+starttls" if start_tls else "ldap"),
                "scope": scope_norm,
                "filter": resolved_filter,
                "result_count": len(entries),
                "high_value_findings": triaged,
                "results": entries,
                "evidence_path": self._display_path(evidence_path),
                "result_hash": result_hash,
                "stderr": sanitize_tool_output("ldap_stderr", stderr_txt),
            }
        )

    async def _read_attribute_wordlist(self, wordlist_path: str) -> List[str]:
        resolved = self._guard.validate_path(wordlist_path, mode="read")
        if not resolved.exists() or not resolved.is_file():
            raise FileNotFoundError(f"attribute wordlist not found: {wordlist_path}")

        def _load() -> List[str]:
            out: List[str] = []
            for line in resolved.read_text(encoding="utf-8", errors="replace").splitlines():
                token = line.strip()
                if not token or token.startswith("#"):
                    continue
                if re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{1,63}", token):
                    out.append(token)
            return out

        return await asyncio.to_thread(_load)

    async def _create_password_file(self, password: str) -> Path:
        password_dir = (self._workspace / ".cerberus" / "tmp").resolve()
        password_dir.mkdir(parents=True, exist_ok=True)

        def _write() -> Path:
            fd, tmp_path = tempfile.mkstemp(prefix="ldap_pw_", dir=str(password_dir), text=True)
            os.close(fd)
            path = Path(tmp_path)
            path.write_text(password, encoding="utf-8")
            with suppress(Exception):
                path.chmod(0o600)
            return path

        return await asyncio.to_thread(_write)

    def _resolve_filter(self, *, shortcut: str, ldap_filter: str, base_dn: str) -> str:
        token = (shortcut or "").strip().upper()
        if token and token in self.SHORTCUTS:
            rendered = self.SHORTCUTS[token].replace("{base_dn}", base_dn or "DC=example,DC=com")
            return rendered
        return (ldap_filter or "(objectClass=*)").strip() or "(objectClass=*)"

    def _parse_ldif(self, text: str) -> List[Dict[str, Any]]:
        blocks = [chunk.strip() for chunk in re.split(r"\n\s*\n", text) if chunk.strip()]
        parsed: List[Dict[str, Any]] = []
        for block in blocks:
            lines = block.splitlines()
            expanded: List[str] = []
            for line in lines:
                if line.startswith(" ") and expanded:
                    expanded[-1] += line[1:]
                else:
                    expanded.append(line)

            dn = ""
            attrs: Dict[str, List[str]] = {}
            for line in expanded:
                if ":" not in line:
                    continue
                key, value = line.split(":", 1)
                attr = key.strip()
                val = self._scrub_attr(attr, value.lstrip())
                if attr.lower() == "dn":
                    dn = val
                else:
                    attrs.setdefault(attr, []).append(val)
            if dn or attrs:
                parsed.append({"dn": dn, "attributes": attrs})
        return parsed

    def _triage(self, entries: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
        highlights: List[Dict[str, Any]] = []
        for entry in entries:
            attrs = entry.get("attributes", {})
            if not isinstance(attrs, dict):
                continue
            hv: Dict[str, Any] = {}
            for key, values in attrs.items():
                low = str(key).lower()
                if low in _HIGH_VALUE_ATTRS:
                    hv[key] = values
                if low == "description" and any("pass" in str(v).lower() for v in (values or [])):
                    hv["description_flag"] = "potential_credential_in_description"
            if hv:
                highlights.append({"dn": entry.get("dn", ""), "high_value": clean_data(hv)})
        return highlights[:100]

    def _scrub_attr(self, attr: str, value: str) -> str:
        if _PASSWORD_ATTR_RE.search(attr):
            return "[REDACTED_SECRET]"
        return self._scrub_text(value)

    def _scrub_text(self, text: str) -> str:
        redacted = text or ""
        for pattern, replacement in _PII_PATTERNS:
            redacted = pattern.sub(replacement, redacted)
        redacted = re.sub(r"(?i)(password\s*[:=]\s*)([^\s,;]+)", r"\1[REDACTED_SECRET]", redacted)
        redacted = re.sub(r"(?i)(secret\s*[:=]\s*)([^\s,;]+)", r"\1[REDACTED_SECRET]", redacted)
        return redacted

    async def _audit(self, *, event: str, data: Dict[str, Any]) -> None:
        row = {
            "timestamp": datetime.now(tz=UTC).isoformat(),
            "event": event,
            "data": clean_data(data),
        }
        line = json.dumps(row, ensure_ascii=True, default=str) + "\n"

        def _append() -> None:
            self._audit_path.parent.mkdir(parents=True, exist_ok=True)
            with self._audit_path.open("a", encoding="utf-8") as handle:
                handle.write(line)

        await asyncio.to_thread(_append)
        if self._logger is not None:
            with suppress(Exception):
                self._logger.audit("ldap query event", actor="ldap", data=row, tags=["ldap", event])

    def _display_path(self, path: Path) -> str:
        try:
            return str(path.resolve().relative_to(self._workspace))
        except ValueError:
            return str(path.resolve())

    @staticmethod
    def _semantic_error(exit_code: int, stderr: str) -> SemanticError:
        lowered = (stderr or "").lower()
        if exit_code == 127:
            return SemanticError(
                code="command_not_found",
                message="ldapsearch binary is not available on the target host PATH.",
                retryable=False,
                category="dependency",
            )
        if exit_code == 13 or "permission denied" in lowered or "insufficient access" in lowered:
            return SemanticError(
                code="permission_denied",
                message="Directory query denied by server ACL or local execution permissions.",
                retryable=False,
                category="authorization",
            )
        return SemanticError(
            code="ldap_query_failed",
            message="LDAP query failed. Review sanitized stderr for details.",
            retryable=True,
            category="runtime",
        )

    @staticmethod
    def _error(code: str, message: str) -> Dict[str, Any]:
        return {"ok": False, "error": {"code": code, "message": message}}


LDAP_TOOL = LazyToolProxy(CerebroLDAPTool)


@function_tool
def ldap_search(
    host: str,
    base_dn: str = "",
    filter_str: str = "(objectClass=*)",
    attributes: str = "",
    bind_dn: str = "",
    password: str = "",
    scope: str = "sub",
    port: int = 636,
    use_tls: bool = True,
    search_timeout: int = _DEFAULT_TIMEOUT,
    max_entries: int = _DEFAULT_MAX_ENTRIES,
    shortcut: str = "",
    attribute_wordlist: str = "",
) -> Dict[str, Any]:
    attrs = [item for item in attributes.split() if item.strip()] if attributes else []
    return LDAP_TOOL.query(
        host=host,
        base_dn=base_dn,
        ldap_filter=filter_str,
        attributes=attrs,
        bind_dn=bind_dn,
        password=password,
        port=port,
        use_ldaps=use_tls,
        start_tls=True,
        scope=scope,
        max_entries=max_entries,
        search_timeout=search_timeout,
        shortcut=shortcut,
        attribute_wordlist=attribute_wordlist,
    )


@function_tool
def ldap_shortcuts() -> str:
    payload = {"ok": True, "shortcuts": clean_data(LDAP_TOOL.SHORTCUTS)}
    return sanitize_tool_output("ldap_shortcuts", json.dumps(payload, ensure_ascii=True, indent=2))


__all__ = ["CerebroLDAPTool", "LDAP_TOOL", "ldap_search", "ldap_shortcuts"]
