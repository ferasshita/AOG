"""
Attestation placeholder and minimal verification.

Design:
- Agents may include a JWT in their submission as attestation.
- JWT should be signed by the agent's private key (or another attestation service).
- Server can validate the signature with a public key associated with the agent identity (from cert or pre-provisioned registry).
- This module provides a simple verification path based on JWT and client public key.

In production:
- Integrate TPM/SGX/Cloud KMS attestation flows or vendor SDKs for secure attestation verification.
"""

from typing import Optional
import jwt
from cryptography import x509
from cryptography.hazmat.primitives import serialization

def verify_attestation_jwt(attestation_jwt: str, agent_cert_pem: Optional[str]) -> bool:
    """
    Verify a JWT attestation using the public key extracted from agent_cert_pem.
    Returns True if verification succeeds, False otherwise.

    Note: This is a simple scheme and not a substitute for real hardware attestation.
    """
    if not attestation_jwt or not agent_cert_pem:
        return False

    try:
        cert = x509.load_pem_x509_certificate(agent_cert_pem.encode("utf-8"))
        pubkey = cert.public_key()
        pubkey_pem = pubkey.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        # Try to verify the JWT; allow RS256 or PS256
        # jwt.decode will raise if invalid
        jwt.decode(attestation_jwt, key=pubkey_pem, algorithms=["RS256", "PS256"])
        return True
    except Exception:
        return False