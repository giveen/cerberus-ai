"""Synchronous Redis client for Cerberus infrastructure.

Provides simple get/set/lpush/lpop operations for findings and shared state.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Optional

logger = logging.getLogger("cerberus.redis_client")


class RedisManager:
    """Simple synchronous Redis client wrapper."""

    _instance: Optional[RedisManager] = None

    def __init__(self, redis_url: str | None = None):
        """Initialize Redis manager.
        
        Args:
            redis_url: Redis connection URL (e.g., redis://localhost:6379).
                      Defaults to environment variable REDIS_URL.
        """
        try:
            import redis
            self.redis_module = redis
        except ImportError:
            logger.warning("redis package not installed; using in-memory fallback")
            self.redis_module = None

        self.redis_url = redis_url or os.getenv("REDIS_URL", "redis://localhost:6379").strip()
        self._client: Any = None

        if self.redis_module:
            try:
                self._client = self.redis_module.from_url(self.redis_url, decode_responses=True)
                self._client.ping()
                logger.debug(f"Redis connected: {self.redis_url}")
            except Exception as e:
                logger.warning(f"Failed to connect to Redis: {e}; using in-memory fallback")
                self._client = None
        
        # Fallback in-memory store
        self._memory_store: dict[str, Any] = {}

    @classmethod
    def get_instance(cls, redis_url: str | None = None) -> RedisManager:
        """Get or create singleton instance."""
        if cls._instance is None:
            cls._instance = cls(redis_url)
        return cls._instance

    def get(self, key: str) -> Optional[str]:
        """Get a value by key."""
        try:
            if self._client:
                return self._client.get(key)
            return self._memory_store.get(key)
        except Exception as e:
            logger.error(f"Error getting key {key}: {e}")
            return self._memory_store.get(key)

    def set(self, key: str, value: str) -> bool:
        """Set a key-value pair."""
        try:
            if self._client:
                self._client.set(key, value)
            self._memory_store[key] = value
            return True
        except Exception as e:
            logger.error(f"Error setting key {key}: {e}")
            return False

    def setex(self, key: str, time: int, value: str) -> bool:
        """Set a key-value pair with expiration (seconds)."""
        try:
            if self._client:
                self._client.setex(key, time, value)
            self._memory_store[key] = value
            return True
        except Exception as e:
            logger.error(f"Error setting key {key} with expiration: {e}")
            return False

    def delete(self, key: str) -> bool:
        """Delete a key."""
        try:
            if self._client:
                self._client.delete(key)
            self._memory_store.pop(key, None)
            return True
        except Exception as e:
            logger.error(f"Error deleting key {key}: {e}")
            return False

    def lpush(self, key: str, *values: str) -> int:
        """Push values to the left of a list."""
        try:
            if self._client:
                return self._client.lpush(key, *values)
            
            # Fallback: maintain list in memory
            if key not in self._memory_store:
                self._memory_store[key] = []
            
            if not isinstance(self._memory_store[key], list):
                self._memory_store[key] = []
            
            self._memory_store[key] = list(values) + self._memory_store[key]
            return len(self._memory_store[key])
        except Exception as e:
            logger.error(f"Error lpush to key {key}: {e}")
            return 0

    def lpop(self, key: str, count: int = 1) -> Optional[Any]:
        """Pop from the left of a list."""
        try:
            if self._client:
                return self._client.lpop(key, count)
            
            if key not in self._memory_store:
                return None
            
            if not isinstance(self._memory_store[key], list):
                return None
            
            if count == 1:
                if self._memory_store[key]:
                    return self._memory_store[key].pop(0)
                return None
            
            result = self._memory_store[key][:count]
            self._memory_store[key] = self._memory_store[key][count:]
            return result
        except Exception as e:
            logger.error(f"Error lpop from key {key}: {e}")
            return None

    def lrange(self, key: str, start: int, end: int) -> list[str]:
        """Get a range of values from a list."""
        try:
            if self._client:
                return self._client.lrange(key, start, end)
            
            if key not in self._memory_store:
                return []
            
            if not isinstance(self._memory_store[key], list):
                return []
            
            items = self._memory_store[key]
            if end == -1:
                return items[start:]
            return items[start:end + 1]
        except Exception as e:
            logger.error(f"Error lrange on key {key}: {e}")
            return []

    def ltrim(self, key: str, start: int, end: int) -> bool:
        """Trim a list to a specified range."""
        try:
            if self._client:
                self._client.ltrim(key, start, end)
            
            if key in self._memory_store and isinstance(self._memory_store[key], list):
                items = self._memory_store[key]
                if end == -1:
                    self._memory_store[key] = items[start:]
                else:
                    self._memory_store[key] = items[start:end + 1]
            
            return True
        except Exception as e:
            logger.error(f"Error ltrim on key {key}: {e}")
            return False

    def flushall(self) -> bool:
        """Clear all keys."""
        try:
            if self._client:
                self._client.flushall()
            self._memory_store.clear()
            return True
        except Exception as e:
            logger.error(f"Error flushing Redis: {e}")
            return False

    def close(self) -> None:
        """Close Redis connection."""
        if self._client:
            try:
                self._client.close()
                logger.debug("Redis connection closed")
            except Exception as e:
                logger.error(f"Error closing Redis: {e}")


def get_redis_manager(redis_url: str | None = None) -> RedisManager:
    """Get or create the Redis manager."""
    return RedisManager.get_instance(redis_url)
