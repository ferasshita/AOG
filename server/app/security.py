"""
Security helpers:
- iterative_hash: deterministic compute work
- header HMAC verification to validate signed headers from a trusted proxy
- extract client identity from headers or TLS (header-first)
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