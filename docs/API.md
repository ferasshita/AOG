# API (Production)

> **⚠️ CRITICAL SECURITY NOTICE**
>
> This API implements hash-based computational challenges that **CANNOT** reliably distinguish
> between autonomous AI agents and humans who write programs. Both can compute hashes equally well.
>
> **This is a proof-of-concept for distributed challenge infrastructure, NOT a production-ready
> agent authentication system.** See README.md and ARCHITECTURE.md for detailed analysis and
> alternative approaches for genuine agent-vs-human distinction.

Base URL: https://<host> (mTLS or proxy-signed headers required)

## Endpoints

### GET /challenge
Issues a deterministic hash-based computational challenge.

**⚠️ Security Limitation:** Any human can write a simple script to solve these challenges in milliseconds.

**Authentication Required:**
- If using proxy termination: headers `X-Client-Cert` (PEM) and `X-Client-Cert-Signature` (base64 HMAC) must be present.
- If server runs with mTLS: the peer certificate identity is used.

**Response:**
```json
{
  "nonce": "...",
  "seed": "...",
  "iterations": 100000,
  "deadline_ts": 1234567890.123,
  "issued_at": 1234567880.123
}
```

### POST /task
Submits a solved challenge result.

**Request Body (JSON):**
```json
{
  "nonce": "...",
  "result_hash": "...",
  "runtime_ms": 43,
  "client_fingerprint": "...",
  "trace_hash": "..." (optional),
  "attestation": "..." (optional JWT)
}
```

**Responses:**
- `200 OK`: Challenge accepted
  ```json
  {"status": "accepted", "nonce": "..."}
  ```
- `400 Bad Request`: Invalid nonce, incorrect hash, or runtime exceeded
- `403 Forbidden`: Client identity mismatch or attestation failure
- `408 Request Timeout`: Submission past deadline
- `409 Conflict`: Replay detected (nonce already used)
- `429 Too Many Requests`: Rate limit exceeded

### GET /metrics
Prometheus metrics exposition endpoint.

**Response:** Prometheus text format

---

## Security Considerations

### What This API Does Validate:
- ✅ Client identity via mTLS or signed headers
- ✅ Replay attack prevention (one-time nonces)
- ✅ Rate limiting per client
- ✅ Deterministic challenge/response verification
- ✅ Constant-time hash comparison

### What This API Does NOT Validate:
- ❌ That the solver is an autonomous AI agent
- ❌ That the solver is not a human-written program
- ❌ That the solver exhibits AI-specific capabilities

### Best Practices:
- Prefer backend mTLS for strongest identity verification
- If proxy signs headers, protect `HEADER_HMAC_SECRET` in a secret manager
- Monitor metrics for anomalous patterns
- **Do not rely on this API alone for genuine agent-vs-human distinction**

### Recommended Alternatives:
For production systems requiring genuine agent authentication:
- Reasoning-based challenges (language understanding, problem-solving)
- Autonomy attestation mechanisms
- Behavioral analysis over time
- Systems like [BOTCHA](https://botcha.binary.ly) that combine reasoning + attestation