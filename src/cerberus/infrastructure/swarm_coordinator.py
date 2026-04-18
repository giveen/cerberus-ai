"""
Swarm Coordination: Inter-agent context sharing via Redis.

Enables multiple agents to share discoveries and findings in real-time.
Example: Agent 1 discovers open port -> Agent 2 sees it automatically.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Callable, Optional

from cerberus.infrastructure.redis_client import get_redis_manager

logger = logging.getLogger("cerberus.swarm")


class GlobalFinding:
    """Represents a shared discovery/finding across agent sessions."""
    
    def __init__(
        self,
        finding_id: str,
        agent_id: str,
        finding_type: str,
        content: dict[str, Any],
        timestamp: Optional[float] = None,
        priority: int = 1,  # 1=low, 2=medium, 3=high, 4=critical
    ):
        """Initialize a finding.
        
        Args:
            finding_id: Unique identifier for this finding
            agent_id: ID of the agent that discovered this
            finding_type: Type of finding (e.g., "open_port", "vulnerability", "credential")
            content: Discovery content (port number, CVSS score, etc.)
            timestamp: When the finding was discovered (defaults to now)
            priority: Severity/importance level
        """
        self.finding_id = finding_id
        self.agent_id = agent_id
        self.finding_type = finding_type
        self.content = content
        self.timestamp = timestamp or time.time()
        self.priority = priority
    
    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "finding_id": self.finding_id,
            "agent_id": self.agent_id,
            "finding_type": self.finding_type,
            "content": self.content,
            "timestamp": self.timestamp,
            "priority": self.priority,
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GlobalFinding:
        """Deserialize from dict."""
        return cls(
            finding_id=data.get("finding_id", ""),
            agent_id=data.get("agent_id", ""),
            finding_type=data.get("finding_type", ""),
            content=data.get("content", {}),
            timestamp=data.get("timestamp"),
            priority=data.get("priority", 1),
        )


class SwarmCoordinator:
    """Manages shared findings across agent sessions."""
    
    FINDINGS_KEY_PREFIX = "cerberus:findings"
    FINDINGS_INDEX_KEY = f"{FINDINGS_KEY_PREFIX}:index"
    SESSION_SUBSCRIPTIONS_KEY = f"{FINDINGS_KEY_PREFIX}:subscriptions"
    
    def __init__(self):
        """Initialize the coordinator."""
        self.redis = get_redis_manager()
        self._subscription_callbacks: dict[str, list[Callable]] = {}
    
    def register_finding(self, finding: GlobalFinding) -> bool:
        """Register a new finding in the global findings store.
        
        Args:
            finding: GlobalFinding object
        
        Returns:
            True if registered successfully, False otherwise
        """
        try:
            # Serialize finding
            finding_json = json.dumps(finding.to_dict(), ensure_ascii=True)
            finding_key = f"{self.FINDINGS_KEY_PREFIX}:{finding.finding_id}"
            
            # Store finding
            self.redis.setex(
                finding_key,
                86400,  # Expire after 24 hours
                finding_json,
            )
            
            # Add to index
            self.redis.lpush(self.FINDINGS_INDEX_KEY, finding.finding_id)
            self.redis.ltrim(self.FINDINGS_INDEX_KEY, 0, 999)  # Keep last 1000
            
            logger.info(f"Registered finding: {finding.finding_id} (type={finding.finding_type})")
            
            # Notify subscribers
            self._notify_subscribers(finding)
            
            return True
        except Exception as e:
            logger.error(f"Failed to register finding: {e}")
            return False
    
    def get_finding(self, finding_id: str) -> Optional[GlobalFinding]:
        """Retrieve a specific finding by ID."""
        try:
            finding_key = f"{self.FINDINGS_KEY_PREFIX}:{finding_id}"
            data = self.redis.get(finding_key)
            if data:
                finding_dict = json.loads(data)
                return GlobalFinding.from_dict(finding_dict)
        except Exception as e:
            logger.error(f"Failed to get finding {finding_id}: {e}")
        
        return None
    
    def get_findings_by_type(self, finding_type: str) -> list[GlobalFinding]:
        """Get all findings of a specific type."""
        findings = []
        try:
            # Get all finding IDs from index
            finding_ids = self.redis.lrange(self.FINDINGS_INDEX_KEY, 0, -1)
            
            for finding_id in finding_ids:
                finding_id_str = finding_id if isinstance(finding_id, str) else finding_id.decode()
                finding = self.get_finding(finding_id_str)
                if finding and finding.finding_type == finding_type:
                    findings.append(finding)
        except Exception as e:
            logger.error(f"Failed to get findings by type {finding_type}: {e}")
        
        return findings
    
    def get_all_findings(self) -> list[GlobalFinding]:
        """Get all active findings."""
        findings = []
        try:
            # Get all finding IDs from index
            finding_ids = self.redis.lrange(self.FINDINGS_INDEX_KEY, 0, -1)
            
            for finding_id in finding_ids:
                finding_id_str = finding_id if isinstance(finding_id, str) else finding_id.decode()
                finding = self.get_finding(finding_id_str)
                if finding:
                    findings.append(finding)
        except Exception as e:
            logger.error(f"Failed to get all findings: {e}")
        
        return findings
    
    def subscribe_to_findings(
        self,
        session_id: str,
        callback: Callable[[GlobalFinding], None],
        finding_type: Optional[str] = None,
    ) -> None:
        """Subscribe to new findings.
        
        Args:
            session_id: Session ID subscribing to findings
            callback: Function to call when new findings are received
            finding_type: Optional filter - only notify for this finding type
        """
        subscription_key = f"{session_id}:{finding_type or 'all'}"
        
        if subscription_key not in self._subscription_callbacks:
            self._subscription_callbacks[subscription_key] = []
        
        self._subscription_callbacks[subscription_key].append(callback)
        
        logger.info(f"Session {session_id} subscribed to findings (type={finding_type or 'all'})")
    
    def unsubscribe_from_findings(self, session_id: str) -> None:
        """Unsubscribe from findings."""
        # Clean up subscription callbacks
        keys_to_remove = [k for k in self._subscription_callbacks if k.startswith(session_id)]
        for key in keys_to_remove:
            del self._subscription_callbacks[key]
        
        logger.info(f"Session {session_id} unsubscribed from findings")
    
    def _notify_subscribers(self, finding: GlobalFinding) -> None:
        """Notify all interested subscribers of a new finding."""
        # Notify "all" subscribers
        all_subscribers_key = f"*:{finding.finding_type}"
        for subscription_key in self._subscription_callbacks:
            if finding.finding_type in subscription_key or subscription_key.endswith(":all"):
                for callback in self._subscription_callbacks[subscription_key]:
                    try:
                        callback(finding)
                    except Exception as e:
                        logger.error(f"Callback failed: {e}")
    
    def clear_findings(self) -> bool:
        """Clear all findings (for testing or cleanup)."""
        try:
            finding_ids = self.redis.lrange(self.FINDINGS_INDEX_KEY, 0, -1)
            for finding_id in finding_ids:
                finding_id_str = finding_id if isinstance(finding_id, str) else finding_id.decode()
                finding_key = f"{self.FINDINGS_KEY_PREFIX}:{finding_id_str}"
                self.redis.delete(finding_key)
            
            self.redis.delete(self.FINDINGS_INDEX_KEY)
            logger.info("Cleared all findings")
            return True
        except Exception as e:
            logger.error(f"Failed to clear findings: {e}")
            return False


# Global coordinator instance
_coordinator: Optional[SwarmCoordinator] = None


def get_swarm_coordinator() -> SwarmCoordinator:
    """Get or create the swarm coordinator."""
    global _coordinator
    if _coordinator is None:
        _coordinator = SwarmCoordinator()
    return _coordinator


def publish_finding(
    finding_type: str,
    content: dict[str, Any],
    agent_id: str,
    priority: int = 1,
) -> str:
    """Convenience function to publish a finding to the swarm.
    
    Args:
        finding_type: Type of finding (e.g., "open_port", "vulnerability")
        content: Finding content/details
        agent_id: ID of the agent publishing
        priority: Priority level (1-4)
    
    Returns:
        Finding ID if successful, empty string otherwise
    """
    import uuid
    coordinator = get_swarm_coordinator()
    
    finding_id = str(uuid.uuid4())[:8]
    finding = GlobalFinding(
        finding_id=finding_id,
        agent_id=agent_id,
        finding_type=finding_type,
        content=content,
        priority=priority,
    )
    
    if coordinator.register_finding(finding):
        return finding_id
    return ""
