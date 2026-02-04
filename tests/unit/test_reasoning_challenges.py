"""
Unit tests for reasoning challenges and autonomy attestation.
"""

import time
from server.app.security import (
    generate_reasoning_challenge, 
    verify_reasoning_answer, 
    validate_autonomy_attestation
)

def test_generate_reasoning_challenge():
    """Test that reasoning challenge generation works."""
    challenge = generate_reasoning_challenge()
    
    assert "question" in challenge
    assert "answer_hash" in challenge
    assert "seed" in challenge
    assert "type" in challenge
    assert len(challenge["answer_hash"]) == 64  # SHA-256 hex length
    assert len(challenge["seed"]) == 32  # 16 bytes hex

def test_verify_reasoning_answer_correct():
    """Test correct answer verification."""
    # Create a test hash for answer "A"
    import hashlib
    expected_hash = hashlib.sha256("A".encode()).hexdigest()
    
    # Test with correct answer
    assert verify_reasoning_answer("A", expected_hash) is True
    assert verify_reasoning_answer("a", expected_hash) is True  # Case insensitive
    assert verify_reasoning_answer(" A ", expected_hash) is True  # Whitespace trimmed

def test_verify_reasoning_answer_incorrect():
    """Test incorrect answer rejection."""
    import hashlib
    expected_hash = hashlib.sha256("A".encode()).hexdigest()
    
    # Test with wrong answers
    assert verify_reasoning_answer("B", expected_hash) is False
    assert verify_reasoning_answer("", expected_hash) is False
    assert verify_reasoning_answer(None, expected_hash) is False

def test_validate_autonomy_attestation_valid():
    """Test valid autonomy attestation."""
    attestation = {
        "operation_time": 5.0,
        "autonomous_actions": [
            {"action": "challenge_request", "timestamp": 100.0},
            {"action": "solve", "timestamp": 105.0}
        ],
        "decision_chain": [
            {"decision": "connect", "rationale": "authenticate"},
            {"decision": "solve", "rationale": "verify"}
        ]
    }
    
    assert validate_autonomy_attestation(attestation) is True

def test_validate_autonomy_attestation_missing_fields():
    """Test autonomy attestation with missing fields."""
    # Missing operation_time
    attestation = {
        "autonomous_actions": [{"action": "test"}],
        "decision_chain": [{"decision": "test"}]
    }
    assert validate_autonomy_attestation(attestation) is False
    
    # Missing autonomous_actions
    attestation = {
        "operation_time": 5.0,
        "decision_chain": [{"decision": "test"}]
    }
    assert validate_autonomy_attestation(attestation) is False
    
    # Missing decision_chain
    attestation = {
        "operation_time": 5.0,
        "autonomous_actions": [{"action": "test"}]
    }
    assert validate_autonomy_attestation(attestation) is False

def test_validate_autonomy_attestation_insufficient_operation_time():
    """Test autonomy attestation with insufficient operation time."""
    attestation = {
        "operation_time": 0.5,  # Less than 1 second
        "autonomous_actions": [{"action": "test"}],
        "decision_chain": [{"decision": "test"}]
    }
    assert validate_autonomy_attestation(attestation) is False

def test_validate_autonomy_attestation_empty_lists():
    """Test autonomy attestation with empty lists."""
    attestation = {
        "operation_time": 5.0,
        "autonomous_actions": [],  # Empty
        "decision_chain": [{"decision": "test"}]
    }
    assert validate_autonomy_attestation(attestation) is False
    
    attestation = {
        "operation_time": 5.0,
        "autonomous_actions": [{"action": "test"}],
        "decision_chain": []  # Empty
    }
    assert validate_autonomy_attestation(attestation) is False
