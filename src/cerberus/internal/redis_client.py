"""Redis client utilities for Cerberus streaming data persistence and pub/sub broadcasting.

This module provides:
- Async Redis connection pooling
- History buffer (Redis Lists): cerberus:history:<token>
- Live broadcaster (Pub/Sub): cerberus:live:<token>
- State transition publishing
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Optional

try:
    import redis.asyncio as redis
    from redis.asyncio import Redis, ConnectionPool
except ImportError:
    redis = None  # type: ignore
    Redis = None  # type: ignore
    ConnectionPool = None  # type: ignore

logger = logging.getLogger(__name__)


class RedisClientManager:
    """Async Redis client manager with pooling and pub/sub utilities."""

    _instance: Optional[RedisClientManager] = None
    _lock: asyncio.Lock = asyncio.Lock()

    def __init__(self, redis_url: str | None = None):
        """Initialize Redis client manager.
        
        Args:
            redis_url: Redis connection URL (e.g., redis://localhost:6379).
                      Defaults to environment variable REDIS_URL or redis://localhost:6379.
        """
        if redis is None:
            raise RuntimeError("redis.asyncio package is required but not installed")

        self.redis_url = redis_url or os.getenv("REDIS_URL", "redis://localhost:6379").strip()
        self._client: Optional[Redis] = None
        self._pool: Optional[ConnectionPool] = None

    @classmethod
    async def get_instance(cls, redis_url: str | None = None) -> RedisClientManager:
        """Get or create singleton instance with thread-safe initialization."""
        if cls._instance is None:
            async with cls._lock:
                if cls._instance is None:
                    cls._instance = cls(redis_url)
                    await cls._instance._initialize()
        return cls._instance

    async def _initialize(self) -> None:
        """Initialize connection pool and client."""
        try:
            self._pool = ConnectionPool.from_url(
                self.redis_url,
                decode_responses=True,
                max_connections=10,
            )
            self._client = Redis(connection_pool=self._pool)
            # Test connection
            await self._client.ping()
            logger.debug(f"Redis connected: {self.redis_url}")
        except Exception as e:
            logger.error(f"Failed to initialize Redis: {e}")
            raise

    async def close(self) -> None:
        """Close Redis connection pool."""
        if self._pool:
            await self._pool.disconnect()
            logger.debug("Redis connection pool closed")

    @property
    def client(self) -> Redis:
        """Get Redis client."""
        if self._client is None:
            raise RuntimeError("Redis client not initialized. Call await get_instance() first.")
        return self._client

    async def push_history(
        self,
        client_token: str,
        message: str,
        max_entries: int = 10000,
    ) -> int:
        """Push message to history list for client.
        
        Args:
            client_token: Unique client identifier (from cerberus_client_token)
            message: Message or line to store
            max_entries: Maximum entries to retain in history list
            
        Returns:
            List length after push
        """
        history_key = f"cerberus:history:{client_token}"
        try:
            list_len = await self.client.rpush(history_key, message)
            # Trim list to max_entries (keep newest)
            if list_len > max_entries:
                await self.client.ltrim(history_key, -max_entries, -1)
                list_len = max_entries
            return list_len
        except Exception as e:
            logger.error(f"Failed to push history for {client_token}: {e}")
            return 0

    async def publish_live(
        self,
        client_token: str,
        message: str,
    ) -> int:
        """Publish message to live broadcast channel.
        
        Args:
            client_token: Unique client identifier
            message: Message to broadcast (can be plain text or JSON)
            
        Returns:
            Number of subscribers that received message
        """
        live_channel = f"cerberus:live:{client_token}"
        try:
            subscribers = await self.client.publish(live_channel, message)
            return subscribers
        except Exception as e:
            logger.error(f"Failed to publish to {live_channel}: {e}")
            return 0

    async def publish_state_change(
        self,
        client_token: str,
        state: str,
        index: int | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> int:
        """Publish structured state change message.
        
        Args:
            client_token: Unique client identifier
            state: New state (e.g., 'BUSY', 'ACTIVE', 'IDLE')
            index: Optional session index
            metadata: Optional additional metadata
            
        Returns:
            Number of subscribers
        """
        payload = {
            "type": "state_change",
            "state": state,
            "index": index,
            **(metadata or {}),
        }
        return await self.publish_live(client_token, json.dumps(payload))

    async def get_history(
        self,
        client_token: str,
        start: int = 0,
        end: int = -1,
    ) -> list[str]:
        """Retrieve history entries for client.
        
        Args:
            client_token: Unique client identifier
            start: Start index (0-based, inclusive)
            end: End index (-1 for last)
            
        Returns:
            List of history entries
        """
        history_key = f"cerberus:history:{client_token}"
        try:
            entries = await self.client.lrange(history_key, start, end)
            return entries if isinstance(entries, list) else []
        except Exception as e:
            logger.error(f"Failed to get history for {client_token}: {e}")
            return []

    async def history_length(self, client_token: str) -> int:
        """Get current history length."""
        history_key = f"cerberus:history:{client_token}"
        try:
            length = await self.client.llen(history_key)
            return length if isinstance(length, int) else 0
        except Exception as e:
            logger.error(f"Failed to get history length for {client_token}: {e}")
            return 0

    async def clear_history(self, client_token: str) -> bool:
        """Clear all history for client."""
        history_key = f"cerberus:history:{client_token}"
        try:
            result = await self.client.delete(history_key)
            return bool(result)
        except Exception as e:
            logger.error(f"Failed to clear history for {client_token}: {e}")
            return False

    @asynccontextmanager
    async def subscribe(
        self,
        client_token: str,
    ) -> AsyncIterator[redis.client.PubSub]:
        """Context manager for subscribing to live channel.
        
        Usage:
            async with manager.subscribe(token) as pubsub:
                async for message in pubsub.listen():
                    print(message)
        """
        live_channel = f"cerberus:live:{client_token}"
        pubsub = self.client.pubsub()
        try:
            await pubsub.subscribe(live_channel)
            logger.debug(f"Subscribed to {live_channel}")
            yield pubsub
        except Exception as e:
            logger.error(f"Subscription error for {live_channel}: {e}")
            raise
        finally:
            await pubsub.unsubscribe(live_channel)
            await pubsub.close()
            logger.debug(f"Unsubscribed from {live_channel}")


async def get_redis_manager(redis_url: str | None = None) -> RedisClientManager:
    """Get singleton Redis manager instance."""
    return await RedisClientManager.get_instance(redis_url)


async def push_history_line(
    client_token: str,
    line: str,
    redis_url: str | None = None,
) -> int:
    """Convenience function: push single line to history and publish to live."""
    manager = await get_redis_manager(redis_url)
    
    # Push to history list
    list_len = await manager.push_history(client_token, line)
    
    # Immediately broadcast to live subscribers
    await manager.publish_live(client_token, line)
    
    return list_len


async def broadcast_state_change(
    client_token: str,
    state: str,
    index: int | None = None,
    metadata: dict[str, Any] | None = None,
    redis_url: str | None = None,
) -> int:
    """Convenience function: broadcast state change."""
    manager = await get_redis_manager(redis_url)
    return await manager.publish_state_change(client_token, state, index, metadata)
