"""
Integration tests for FastAPI app with Redis mocked.
"""

import pytest
from fastapi.testclient import TestClient
from server.app.main import app
from server.app.redis_store import _redis_store
import fakeredis.aioredis as fakeredis
import asyncio

@pytest.fixture(autouse=True)
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()

@pytest.fixture(autouse=True)
async def fake_redis(monkeypatch):
    fake = await fakeredis.create_redis_pool()
    # replace module-level _redis_store._client
    _redis_store._client = fake
    yield
    await fake.flushall()
    fake.close()
    await fake.wait_closed()

def test_challenge_and_submit():
    client = TestClient(app)
    # Request challenge with dev fingerprint header
    r = client.get("/challenge", headers={"x-client-fingerprint": "test-client-1"})
    assert r.status_code == 200
    ch = r.json()
    nonce = ch["nonce"]

    # For test speed, manipulate redis challenge to use small iterations
    from server.app.redis_store import _redis_store as store
    # get raw challenge and replace iterations
    import asyncio
    async def mod():
        c = await store.get_challenge(nonce)
        c["iterations"] = 5
        await store.set_challenge(nonce, c, ttl_seconds=60)
    asyncio.get_event_loop().run_until_complete(mod())

    # compute expected
    from server.app.security import iterative_hash
    expected = iterative_hash(c["seed"], 5)

    payload = {
        "nonce": nonce,
        "result_hash": expected,
        "runtime_ms": 10,
        "client_fingerprint": "fp",
        "trace_hash": None,
    }
    r2 = client.post("/task", json=payload, headers={"x-client-fingerprint": "test-client-1"})
    assert r2.status_code == 200
    assert r2.json()["status"] == "accepted"