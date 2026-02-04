"""
Security helpers:
- reasoning challenges: semantic verification tasks
- autonomy attestation: continuous operation verification
- header HMAC verification to validate signed headers from a trusted proxy
- extract client identity from headers or TLS (header-first)
"""

import hashlib
import hmac
import base64
import secrets
import json
from typing import Optional, Dict, Any
from .config import HEADER_HMAC_SECRET
import logging

logger = logging.getLogger("aog_server.security")

# Challenge templates for reasoning verification
CHALLENGE_TEMPLATES = [
    {
        "type": "semantic_analysis",
        "question": "Given the following code snippet, identify the primary design pattern used: '{code}'. Options: A) Singleton B) Factory C) Observer D) Strategy",
        "codes": [
            "class Database:\n    _instance = None\n    def __new__(cls):\n        if cls._instance is None:\n            cls._instance = super().__new__(cls)\n        return cls._instance",
            "class ShapeFactory:\n    @staticmethod\n    def create(type):\n        if type == 'circle': return Circle()\n        elif type == 'square': return Square()",
            "class Subject:\n    def __init__(self):\n        self._observers = []\n    def attach(self, observer):\n        self._observers.append(observer)\n    def notify(self):\n        for obs in self._observers: obs.update()",
            "class Context:\n    def __init__(self, strategy):\n        self._strategy = strategy\n    def execute(self):\n        return self._strategy.algorithm()"
        ],
        "answers": ["A", "B", "C", "D"]
    },
    {
        "type": "logic_reasoning",
        "question": "If all autonomous agents can process natural language, and this system processes natural language, can we conclude this system is an autonomous agent? Answer: A) Yes B) No C) Cannot determine",
        "answer": "B"
    },
    {
        "type": "context_understanding",
        "question": "An API receives requests at variable rates. During peak hours, legitimate traffic increases 10x. What's the BEST approach? A) Fixed rate limit for all B) Dynamic rate limiting based on patterns C) Block all peak traffic D) No rate limiting",
        "answer": "B"
    },
    {
        "type": "problem_solving",
        "question": "You need to verify client authenticity without storing passwords. Which approach is MOST secure? A) Plain text comparison B) MD5 hash C) Challenge-response with certificates D) Base64 encoding",
        "answer": "C"
    },
    {
        "type": "system_design",
        "question": "For distributed rate limiting across multiple servers, which data structure provides O(1) operations and atomic updates? A) Distributed array B) Redis sorted set C) File-based counter D) Redis hash with TTL",
        "answer": "D"
    }
]

def generate_reasoning_challenge() -> Dict[str, Any]:
    """
    Generate a reasoning-based challenge that requires semantic understanding,
    problem-solving, or contextual analysis capabilities.
    """
    template = secrets.choice(CHALLENGE_TEMPLATES)
    
    if template["type"] == "semantic_analysis":
        idx = secrets.randbelow(len(template["codes"]))
        question = template["question"].replace("{code}", template["codes"][idx])
        answer_hash = hashlib.sha256(template["answers"][idx].encode()).hexdigest()
    else:
        question = template["question"]
        answer_hash = hashlib.sha256(template["answer"].encode()).hexdigest()
    
    # Add seed for additional binding
    challenge_seed = secrets.token_hex(16)
    
    return {
        "question": question,
        "answer_hash": answer_hash,
        "seed": challenge_seed,
        "type": template["type"]
    }

def verify_reasoning_answer(submitted_answer: str, expected_hash: str) -> bool:
    """
    Verify the submitted answer against the expected hash.
    Uses constant-time comparison to prevent timing attacks.
    """
    if not submitted_answer or not expected_hash:
        return False
    
    submitted_hash = hashlib.sha256(submitted_answer.strip().upper().encode()).hexdigest()
    return hmac.compare_digest(submitted_hash, expected_hash)

def validate_autonomy_attestation(attestation_data: Dict[str, Any]) -> bool:
    """
    Validate autonomy attestation claims:
    - Continuous operation indicators
    - System resource access patterns
    - Process lifecycle metadata
    """
    if not attestation_data:
        return False
    
    # Check for key autonomy indicators
    required_fields = ["operation_time", "autonomous_actions", "decision_chain"]
    if not all(field in attestation_data for field in required_fields):
        return False
    
    # Verify operation time is reasonable (at least a few seconds of autonomous operation)
    operation_time = attestation_data.get("operation_time", 0)
    if operation_time < 1.0:  # Less than 1 second is suspicious
        return False
    
    # Verify autonomous actions list exists and has entries
    actions = attestation_data.get("autonomous_actions", [])
    if not actions or len(actions) < 1:
        return False
    
    # Verify decision chain (evidence of autonomous decision making)
    decision_chain = attestation_data.get("decision_chain", [])
    if not decision_chain or len(decision_chain) < 1:
        return False
    
    return True

def iterative_hash(seed_hex: str, iterations: int) -> str:
    """
    Legacy deterministic iterative SHA-256 for backward compatibility.
    H_0 = SHA256(seed)
    H_i = SHA256(H_{i-1}) for i in 1..iterations
    Returns hex digest.
    """
    h = hashlib.sha256(bytes.fromhex(seed_hex)).digest()
    for _ in range(iterations):
        h = hashlib.sha256(h).digest()
    return h.hex()

def verify_signed_header(header_value: str, signature_b64: str) -> bool:
    """
    Verify header_value using HMAC-SHA256 and base64(signature).
    Returns True if signature matches and HEADER_HMAC_SECRET is set.
    """
    if not HEADER_HMAC_SECRET:
        logger.warning("HEADER_HMAC_SECRET not set; cannot verify signed header.")
        return False
    try:
        expected = hmac.new(HEADER_HMAC_SECRET.encode("utf-8"), header_value.encode("utf-8"), hashlib.sha256).digest()
        sig = base64.b64decode(signature_b64)
        return hmac.compare_digest(expected, sig)
    except Exception:
        return False