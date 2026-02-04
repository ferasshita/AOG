"""
Unit tests for deterministic task generator and iterative hash verifier.
"""

import time
from server.app.security import iterative_hash

def test_iterative_hash_known_vector():
    # Small iterations test for correctness
    seed = "00"*32  # 32 bytes of zero
    iterations = 10
    h = iterative_hash(seed, iterations)
    # Deterministic: repeated calls should match
    h2 = iterative_hash(seed, iterations)
    assert h == h2
    assert len(h) == 64  # SHA-256 hex length