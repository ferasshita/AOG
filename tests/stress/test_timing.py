"""
Light stress test to exercise iterative hashing (CI-aware).
"""

import time
from server.app.security import iterative_hash
from server.app.config import DEFAULT_TARGET_MS

def test_iterative_timing():
    # Small iterations for CI
    seed = "00"*32
    iterations = 20000
    start = time.time()
    h = iterative_hash(seed, iterations)
    elapsed_ms = (time.time() - start) * 1000
    # sanity check: should finish
    assert elapsed_ms < DEFAULT_TARGET_MS * 20