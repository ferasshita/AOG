"""
Unit tests for RedisStore using fakeredis.
"""

import asyncio
import pytest
import fakeredis.aioredis as fakeredis
from server.app.redis_store import RedisStore

@pytest.mark.asyncio
async def test_challenge_set_get(monkeypatch):
    # Use fakeredis for async redis
    fake = await fakeredis.create_redis_pool()
    r = RedisStore(url="redis://localhost")
    # monkeypatch internal client with fakeredis pool
    r._client = fake

    nonce = "deadbeef"
    challenge = {"nonce": nonce, "seed": "00", "iterations": 10}
    await r.set_challenge(nonce, challenge, ttl_seconds=5)
    got = await r.get_challenge(nonce)
    assert got["nonce"] == nonce

    consumed = await r.consume_nonce(nonce)
    assert consumed is True
    consumed2 = await r.consume_nonce(nonce)
    assert consumed2 is False

    await fake.flushall()
    fake.close()
    await fake.wait_closed()