"""
Security helpers:
- iterative_hash: deterministic compute work
- header HMAC verification to validate signed headers from a trusted proxy
- extract client identity from headers or TLS (header-first)

⚠️ SECURITY LIMITATION WARNING ⚠️
=================================
The iterative_hash function implements a deterministic computational challenge that
CANNOT reliably distinguish between autonomous AI agents and humans who write programs.

FUNDAMENTAL FLAW:
- Hash computation is trivial for both humans and agents
- Proves "can you run code?" NOT "are you an AI agent?"
- Any human can write a script to solve this in milliseconds:
  
  import hashlib
  def solve(seed_hex, iterations):
      h = hashlib.sha256(bytes.fromhex(seed_hex)).digest()
      for _ in range(iterations):
          h = hashlib.sha256(h).digest()
      return h.hex()

This implementation is a PROOF-OF-CONCEPT for distributed challenge infrastructure,
NOT a production-ready agent authentication system.

For genuine agent-vs-human distinction, consider:
- Reasoning-based challenges (language understanding, problem-solving)
- Autonomy attestation mechanisms
- Behavioral analysis over time
- Alternative approaches like BOTCHA (botcha.binary.ly)

See ARCHITECTURE.md for detailed analysis of this limitation.
"""

import hashlib
import hmac
import base64
from typing import Optional
from .config import HEADER_HMAC_SECRET
import logging

logger = logging.getLogger("aog_server.security")

def iterative_hash(seed_hex: str, iterations: int) -> str:
    """
    Deterministic iterative SHA-256:
    H_0 = SHA256(seed)
    H_i = SHA256(H_{i-1}) for i in 1..iterations
    Returns hex digest.
    
    ⚠️ WARNING: This challenge can be easily solved by both humans and AI agents.
    It does NOT prove the solver is an autonomous agent. See module docstring.
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