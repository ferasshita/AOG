"""
Agent client that uses mTLS to interact with the AOG server.

- Supports attestation token creation (JWT signed with agent private key).
- Verifies deadlines and submits result and trace fingerprint.

For dev usage the client uses client cert and key from /certs.
"""

import os
import time
import hashlib
import httpx
import socket
import sys
import jwt
from cryptography.hazmat.primitives import serialization

SERVER_URL = os.environ.get("SERVER_URL", "https://aog_nginx:443")
CLIENT_CERT = os.environ.get("CLIENT_CERT", "/certs/client.crt")
CLIENT_KEY = os.environ.get("CLIENT_KEY", "/certs/client.key")
CA_CERT = os.environ.get("CA_CERT", "/certs/ca.crt")
ATTESTATION_SUBJECT = os.environ.get("ATTESTATION_SUBJECT", "aog-agent")

def compute_iterative_hash(seed_hex: str, iterations: int):
    h = hashlib.sha256(bytes.fromhex(seed_hex)).digest()
    trace_samples = []
    sample_every = max(1, iterations // 4)
    for i in range(iterations):
        h = hashlib.sha256(h).digest()
        if i % sample_every == 0:
            trace_samples.append(h.hex()[:16])
    return h.hex(), trace_samples

def fingerprint_runtime():
    data = {
        "python": sys.version,
        "hostname": socket.gethostname(),
        "pid": os.getpid(),
    }
    s = (data["python"] + data["hostname"] + str(data["pid"])).encode("utf-8")
    return hashlib.sha256(s).hexdigest()

def create_attestation_jwt(private_key_path: str):
    """
    Create a minimal JWT attestation signed by agent private key (RS256).
    In production, attestation should come from HW-backed attestation (TPM/SGX).
    """
    with open(private_key_path, "rb") as f:
        key_data = f.read()
    key = serialization.load_pem_private_key(key_data, password=None)
    # Extract PEM for jwt usage
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    # Create token
    token = jwt.encode({"sub": ATTESTATION_SUBJECT, "iat": int(time.time())}, key=pem, algorithm="RS256")
    return token

def main():
    client = httpx.Client(verify=CA_CERT, cert=(CLIENT_CERT, CLIENT_KEY), timeout=60.0)
    try:
        r = client.get(f"{SERVER_URL}/challenge")
        r.raise_for_status()
        ch = r.json()
        nonce = ch["nonce"]
        seed = ch["seed"]
        iterations = int(ch["iterations"])
        deadline = float(ch["deadline_ts"])
        now = time.time()
        if now > deadline:
            raise RuntimeError("Challenge already expired")

        start = time.time()
        result_hash, trace_samples = compute_iterative_hash(seed, iterations)
        end = time.time()
        runtime_ms = int((end - start) * 1000)

        client_fp = fingerprint_runtime()
        trace_hash = hashlib.sha256(",".join(trace_samples).encode("utf-8")).hexdigest()

        # Create attestation token (dev only)
        attestation = create_attestation_jwt(CLIENT_KEY)

        payload = {
            "nonce": nonce,
            "result_hash": result_hash,
            "runtime_ms": runtime_ms,
            "client_fingerprint": client_fp,
            "trace_hash": trace_hash,
            "attestation": attestation,
        }

        r2 = client.post(f"{SERVER_URL}/task", json=payload)
        r2.raise_for_status()
        print("Submission response:", r2.json())
    finally:
        client.close()

if __name__ == "__main__":
    main()