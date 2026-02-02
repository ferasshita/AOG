"""
Redis-backed store for challenges, replay protection, and rate limiting.

Uses redis.asyncio for async operations.

Key strategy:
- challenge:{nonce} -> JSON value, EXPIRE = ttl_seconds
- used:{nonce} -> string flag (SETNX used for atomic consume)
- rl:{client_id}:{window_ts} -> integer counter with EXPIRE = RATE_LIMIT_WINDOW

Atomic nonce consume uses SETNX to avoid race conditions.
"""

import json
import time
import asyncio
from typing import Optional, Dict
import redis.asyncio as aioredis
from .config import REDIS_URL, RATE_LIMIT_WINDOW, RATE_LIMIT_COUNT

class RedisStore:
    def __init__(self, url: str = REDIS_URL):
        # Create a lazy client; actual connection is established on first use
        self._client = aioredis.from_url(url, decode_responses=True)

    async def set_challenge(self, nonce: str, challenge: Dict, ttl_seconds: int):
        key = f"challenge:{nonce}"
        challenge_json = json.dumps(challenge)
        # EXPIRE in seconds
        await self._client.set(key, challenge_json, ex=ttl_seconds)

    async def get_challenge(self, nonce: str) -> Optional[Dict]:
        key = f"challenge:{nonce}"
        data = await self._client.get(key)
        if not data:
            return None
        return json.loads(data)

    async def delete_challenge(self, nonce: str):
        key = f"challenge:{nonce}"
        await self._client.delete(key)

    async def consume_nonce(self, nonce: str) -> bool:
        """
        Atomically mark nonce as used. Returns True if this call marked it used (first consumer),
        False if it already existed.
        """
        key = f"used:{nonce}"
        # SETNX semantics: set if not exists
        set_result = await self._client.setnx(key, "1")
        if set_result:
            # Keep used markers for a long time to prevent replays (e.g., 7 days)
            await self._client.expire(key, 7 * 24 * 3600)
        return set_result

    async def rate_limit_check(self, client_id: str, window_seconds: int = RATE_LIMIT_WINDOW, limit: int = RATE_LIMIT_COUNT) -> bool:
        """
        Simple fixed window rate limiter per client_id.
        Returns True if the client is rate-limited (exceeded), False otherwise.
        """
        now = int(time.time())
        window = now // window_seconds
        key = f"rl:{client_id}:{window}"
        # INCR key and set expiry when newly created
        count = await self._client.incr(key)
        if count == 1:
            await self._client.expire(key, window_seconds * 2)
        return count > limit

# Provide a module-level client for convenience
_redis_store = RedisStore()

async def get_redis_store() -> RedisStore:
    return _redis_store