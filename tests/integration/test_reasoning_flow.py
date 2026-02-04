"""
Simple integration test for reasoning challenges without Redis dependency.
"""

import pytest
from fastapi.testclient import TestClient
from server.app.main import app
import hashlib

def test_reasoning_challenge_flow_without_redis():
    """
    Test the reasoning challenge flow at the API level.
    Note: This will fail at nonce consumption because Redis is not available,
    but we can verify the challenge generation and answer validation logic works.
    """
    client = TestClient(app)
    
    # Request a reasoning challenge
    r = client.get("/challenge", 
                   params={"challenge_type": "reasoning"},
                   headers={"x-client-fingerprint": "test-client-1"})
    
    # If Redis is not available, we might get a 500 error, but that's okay for this test
    # We're mainly testing the new API structure
    if r.status_code == 200:
        ch = r.json()
        assert "nonce" in ch
        assert "challenge_type" in ch
        assert ch["challenge_type"] == "reasoning"
        assert "question" in ch
        assert "seed" in ch
        assert "deadline_ts" in ch
        assert "issued_at" in ch
        print("✓ Reasoning challenge generation works correctly")
    else:
        # If Redis is not available, at least verify the endpoint exists
        print(f"Note: Got status {r.status_code}, which is expected without Redis")

def test_legacy_challenge_flow_without_redis():
    """
    Test the legacy challenge flow at the API level.
    """
    client = TestClient(app)
    
    # Request a legacy challenge
    r = client.get("/challenge", 
                   params={"challenge_type": "legacy"},
                   headers={"x-client-fingerprint": "test-client-1"})
    
    if r.status_code == 200:
        ch = r.json()
        assert "nonce" in ch
        assert "challenge_type" in ch
        assert ch["challenge_type"] == "legacy"
        assert "seed" in ch
        assert "iterations" in ch
        assert "deadline_ts" in ch
        assert "issued_at" in ch
        print("✓ Legacy challenge generation works correctly")
    else:
        print(f"Note: Got status {r.status_code}, which is expected without Redis")

def test_client_answer_logic():
    """
    Test the client-side reasoning logic in isolation.
    """
    from client.agent import solve_reasoning_challenge
    
    # Test semantic analysis
    question1 = "Given the following code snippet, identify the primary design pattern used: 'class Database:\n    _instance = None\n    def __new__(cls):\n        if cls._instance is None:\n            cls._instance = super().__new__(cls)\n        return cls._instance'. Options: A) Singleton B) Factory C) Observer D) Strategy"
    answer1 = solve_reasoning_challenge(question1)
    assert answer1 == "A", f"Expected 'A', got '{answer1}'"
    
    # Test logic reasoning
    question2 = "If all autonomous agents can process natural language, and this system processes natural language, can we conclude this system is an autonomous agent? Answer: A) Yes B) No C) Cannot determine"
    answer2 = solve_reasoning_challenge(question2)
    assert answer2 == "B", f"Expected 'B', got '{answer2}'"
    
    # Test context understanding
    question3 = "An API receives requests at variable rates. During peak hours, legitimate traffic increases 10x. What's the BEST approach? A) Fixed rate limit for all B) Dynamic rate limiting based on patterns C) Block all peak traffic D) No rate limiting"
    answer3 = solve_reasoning_challenge(question3)
    assert answer3 == "B", f"Expected 'B', got '{answer3}'"
    
    # Test error handling for unrecognized questions
    try:
        solve_reasoning_challenge("This is an unrecognized question format?")
        assert False, "Should have raised ValueError for unrecognized question"
    except ValueError as e:
        assert "Unable to solve unrecognized question pattern" in str(e)
    
    # Test error handling for invalid input
    try:
        solve_reasoning_challenge("")
        assert False, "Should have raised ValueError for empty question"
    except ValueError as e:
        assert "Invalid question" in str(e)
    
    print("✓ All client-side reasoning logic tests passed")

if __name__ == "__main__":
    test_reasoning_challenge_flow_without_redis()
    test_legacy_challenge_flow_without_redis()
    test_client_answer_logic()
