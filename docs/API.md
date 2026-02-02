# API (Production)

Base URL: https://<host> (mTLS or proxy-signed headers required)

GET /challenge
- Issues a challenge. Requires authenticated client identity:
  - If using proxy termination, headers `X-Client-Cert` (PEM) and `X-Client-Cert-Signature` (base64 HMAC) must be present.
  - If server runs with mTLS, the peer certificate identity is used.
- Response: nonce, seed, iterations, deadline_ts, issued_at

POST /task
- Submits a task result.
- Body (JSON):
  - nonce
  - result_hash
  - runtime_ms
  - client_fingerprint
  - trace_hash (optional)
  - attestation (optional JWT)

- Responses:
  - 200 accepted
  - 4xx errors for invalid nonce, mismatch, replay, rate limit, attestation failure

GET /metrics
- Prometheus exposition.

Security:
- Prefer backend mTLS for strongest security.
- If proxy signs headers, protect HEADER_HMAC_SECRET in a secret manager.