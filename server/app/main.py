"""
Production-hardened FastAPI application for Agent-Only Access Gate.

Features:
- Redis-backed challenge and replay state.
- Distributed rate limiting.
- HMAC-signed client-cert header verification (for TLS-terminating proxies).
- Reasoning-based challenge verification.
- Autonomy attestation validation.
- Prometheus metrics endpoint.
- Structured logging and error handling.
"""

import logging
import secrets
import time
from typing import Optional
from fastapi import FastAPI, Request, HTTPException, status, Depends, Header
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel
from .config import DEFAULT_ITERATIONS, DEFAULT_TARGET_MS, CHALLENGE_TTL_EXTRA, REQUIRE_ATTESTATION
from .redis_store import get_redis_store
from .security import iterative_hash, verify_signed_header, generate_reasoning_challenge, verify_reasoning_answer, validate_autonomy_attestation
from .attestation import verify_attestation_jwt
from .metrics import challenges_issued, tasks_accepted, tasks_rejected, rate_limited, metrics_response
from .logging_setup import setup_logging

logger = logging.getLogger("aog_server")
setup_logging()

app = FastAPI(title="Agent-Only Access Gate")

# Pydantic models
class ChallengeResponse(BaseModel):
    nonce: str
    challenge_type: str
    question: Optional[str] = None
    seed: Optional[str] = None
    iterations: Optional[int] = None
    deadline_ts: float
    issued_at: float

class TaskSubmission(BaseModel):
    nonce: str
    challenge_type: str
    answer: Optional[str] = None
    result_hash: Optional[str] = None
    runtime_ms: int
    client_fingerprint: str
    trace_hash: Optional[str] = None
    attestation: Optional[str] = None
    autonomy_attestation: Optional[dict] = None

@app.get("/metrics")
async def metrics():
    # Expose Prometheus metrics
    data, content_type = metrics_response()
    return Response(content=data, media_type=content_type)

def extract_client_identity(request: Request, x_client_cert: Optional[str] = None, x_client_cert_sig: Optional[str] = Header(None)):
    """
    Determine a reliable client identity:
    Priority:
    1) If proxy forwarded X-Client-Cert and X-Client-Cert-Signature, verify HMAC and return fingerprint of the cert.
    2) If header X-Client-Fingerprint present (dev), return it (not secure).
    3) Fallback to request.client.host (best-effort).
    """
    # 1) Check signed client cert header
    if x_client_cert:
        if x_client_cert_sig:
            if verify_signed_header(x_client_cert, x_client_cert_sig):
                # compute a fingerprint (SHA256 hex) of the PEM to use as client_id
                import hashlib
                fp = hashlib.sha256(x_client_cert.encode("utf-8")).hexdigest()
                return fp, x_client_cert
            else:
                logger.warning("Invalid client cert signature header.")
                raise HTTPException(status_code=403, detail="invalid client cert header signature")
        else:
            logger.warning("Client cert header provided without signature; rejecting.")
            raise HTTPException(status_code=403, detail="unsigned client cert header not accepted")
    # 2) fallback header (dev only)
    dev_fp = request.headers.get("x-client-fingerprint")
    if dev_fp:
        return dev_fp, None
    # 3) fallback to client host (not secure)
    if request.client and request.client.host:
        return request.client.host, None
    return "unknown", None

@app.exception_handler(Exception)
async def generic_exc_handler(request: Request, exc: Exception):
    logger.exception("Unhandled exception: %s", exc)
    # Do not expose internal errors
    tasks_rejected.inc()
    return JSONResponse(status_code=500, content={"detail": "internal server error"})

@app.get("/challenge", response_model=ChallengeResponse)
async def get_challenge(request: Request, x_client_cert: Optional[str] = Header(None), x_client_cert_sig: Optional[str] = Header(None), challenge_type: str = "reasoning"):
    """
    Issue a verification challenge. Requires a trusted client identity (from signed headers or mTLS).
    Stores challenge in Redis with TTL.
    
    Supports two challenge types:
    - 'reasoning': Semantic analysis and problem-solving tasks
    - 'legacy': Backward compatible hash-based challenges
    """
    client_id, client_cert_pem = extract_client_identity(request, x_client_cert, x_client_cert_sig)
    redis_store = await get_redis_store()

    # Rate limit check (distributed)
    if await redis_store.rate_limit_check(client_id):
        logger.warning({"event": "rate_limited", "client_id": client_id})
        rate_limited.inc()
        raise HTTPException(status_code=429, detail="rate limit exceeded")

    issued_at = time.time()
    nonce = secrets.token_hex(16)
    
    challenge = {
        "nonce": nonce,
        "challenge_type": challenge_type,
        "issued_at": issued_at,
        "client_id": client_id,
    }
    
    if challenge_type == "reasoning":
        # Generate reasoning challenge
        reasoning_challenge = generate_reasoning_challenge()
        challenge.update({
            "question": reasoning_challenge["question"],
            "answer_hash": reasoning_challenge["answer_hash"],
            "seed": reasoning_challenge["seed"],
            "type": reasoning_challenge["type"]
        })
        target_ms = 30000  # 30 seconds for reasoning
        deadline_ts = issued_at + (target_ms / 1000.0)
        challenge["deadline_ts"] = deadline_ts
        challenge["target_ms"] = target_ms
        
        ttl = int((target_ms / 1000.0) + CHALLENGE_TTL_EXTRA)
        await redis_store.set_challenge(nonce, challenge, ttl_seconds=ttl)
        
        challenges_issued.inc()
        logger.info({"event": "challenge_issued", "type": "reasoning", "nonce": nonce, "client_id": client_id})
        return ChallengeResponse(
            nonce=nonce, 
            challenge_type="reasoning",
            question=reasoning_challenge["question"],
            seed=reasoning_challenge["seed"],
            deadline_ts=deadline_ts, 
            issued_at=issued_at
        )
    else:
        # Legacy hash-based challenge
        seed = secrets.token_hex(32)
        iterations = DEFAULT_ITERATIONS
        target_ms = DEFAULT_TARGET_MS
        deadline_ts = issued_at + (target_ms / 1000.0)
        
        challenge.update({
            "seed": seed,
            "iterations": iterations,
            "target_ms": target_ms,
            "deadline_ts": deadline_ts,
        })
        
        ttl = int((target_ms / 1000.0) + CHALLENGE_TTL_EXTRA)
        await redis_store.set_challenge(nonce, challenge, ttl_seconds=ttl)
        
        challenges_issued.inc()
        logger.info({"event": "challenge_issued", "type": "legacy", "nonce": nonce, "client_id": client_id})
        return ChallengeResponse(
            nonce=nonce, 
            challenge_type="legacy",
            seed=seed, 
            iterations=iterations, 
            deadline_ts=deadline_ts, 
            issued_at=issued_at
        )

@app.post("/task")
async def submit_task(submission: TaskSubmission, request: Request, x_client_cert: Optional[str] = Header(None), x_client_cert_sig: Optional[str] = Header(None)):
    """
    Verify submission:
    - Ensure challenge exists and belongs to client identity
    - For reasoning challenges: verify answer correctness and autonomy attestation
    - For legacy challenges: verify result hash matches deterministic iterative hash
    - Check timing (deadline)
    - Use atomic nonce consume to prevent replay (Redis-backed)
    - Optionally verify attestation JWT using agent cert public key
    """
    client_id, client_cert_pem = extract_client_identity(request, x_client_cert, x_client_cert_sig)
    redis_store = await get_redis_store()

    logger.info({"event": "task_submission", "nonce": submission.nonce, "client_id": client_id, "type": submission.challenge_type})

    # Fetch stored challenge
    challenge = await redis_store.get_challenge(submission.nonce)
    if not challenge:
        tasks_rejected.inc()
        logger.warning({"event": "invalid_nonce", "nonce": submission.nonce, "client_id": client_id})
        raise HTTPException(status_code=400, detail="invalid or unknown nonce")

    # Client binding check
    if challenge.get("client_id") != client_id:
        tasks_rejected.inc()
        logger.warning({"event": "client_mismatch", "expected": challenge.get("client_id"), "got": client_id})
        raise HTTPException(status_code=403, detail="client identity mismatch")

    # Timing check: verify arrival before deadline with a small allowed skew
    now = time.time()
    allowed_skew = 0.5  # 500 ms
    if now - challenge["deadline_ts"] > allowed_skew:
        tasks_rejected.inc()
        logger.info({"event": "deadline_missed", "nonce": submission.nonce, "now": now, "deadline": challenge["deadline_ts"]})
        raise HTTPException(status_code=408, detail="submission past deadline")

    # Verify based on challenge type
    if submission.challenge_type == "reasoning":
        # Verify reasoning answer
        if not submission.answer:
            tasks_rejected.inc()
            logger.warning({"event": "missing_answer", "nonce": submission.nonce})
            raise HTTPException(status_code=400, detail="answer required for reasoning challenge")
        
        if not verify_reasoning_answer(submission.answer, challenge.get("answer_hash")):
            tasks_rejected.inc()
            logger.warning({"event": "incorrect_answer", "nonce": submission.nonce, "client_id": client_id})
            raise HTTPException(status_code=400, detail="incorrect answer")
        
        # Validate autonomy attestation
        if submission.autonomy_attestation:
            if not validate_autonomy_attestation(submission.autonomy_attestation):
                tasks_rejected.inc()
                logger.warning({"event": "invalid_autonomy_attestation", "nonce": submission.nonce})
                raise HTTPException(status_code=403, detail="autonomy attestation validation failed")
        else:
            # Require autonomy attestation for reasoning challenges
            tasks_rejected.inc()
            logger.warning({"event": "missing_autonomy_attestation", "nonce": submission.nonce})
            raise HTTPException(status_code=400, detail="autonomy attestation required")
        
    else:
        # Legacy hash-based verification
        if not submission.result_hash:
            tasks_rejected.inc()
            logger.warning({"event": "missing_result_hash", "nonce": submission.nonce})
            raise HTTPException(status_code=400, detail="result_hash required for legacy challenge")
        
        expected_hash = iterative_hash(challenge["seed"], challenge["iterations"])
        if not expected_hash or not submission.result_hash or expected_hash != submission.result_hash:
            tasks_rejected.inc()
            logger.warning({"event": "hash_mismatch", "nonce": submission.nonce, "client_id": client_id})
            raise HTTPException(status_code=400, detail="incorrect result hash")
        
        # Runtime check
        if submission.runtime_ms > challenge["target_ms"] + 200:  # allow margin
            tasks_rejected.inc()
            logger.warning({"event": "runtime_exceeded", "runtime_ms": submission.runtime_ms, "target_ms": challenge["target_ms"]})
            raise HTTPException(status_code=400, detail="runtime exceeds target")

    # Attestation: optional but can be enforced in PROD via REQUIRE_ATTESTATION
    if REQUIRE_ATTESTATION:
        ok = verify_attestation_jwt(submission.attestation, client_cert_pem)
        if not ok:
            tasks_rejected.inc()
            logger.warning({"event": "attestation_failed", "nonce": submission.nonce})
            raise HTTPException(status_code=403, detail="attestation verification failed")

    # Consume nonce atomically to prevent replay
    consumed = await redis_store.consume_nonce(submission.nonce)
    if not consumed:
        tasks_rejected.inc()
        logger.warning({"event": "replay_detected", "nonce": submission.nonce})
        raise HTTPException(status_code=409, detail="replay detected")

    # Optionally delete the challenge record
    await redis_store.delete_challenge(submission.nonce)

    tasks_accepted.inc()
    logger.info({"event": "task_accepted", "nonce": submission.nonce, "client_id": client_id, "type": submission.challenge_type})
    return {"status": "accepted", "nonce": submission.nonce}