# Agent-Only Access Gate (AOG)

A production-ready open-source system that allows only authorized autonomous AI agents to pass deterministic compute challenges. Humans and unsanctioned clients are rejected through a combination of mTLS authentication, signed proxy headers, deterministic compute verification, nonce-based replay protection, distributed rate-limiting, attestation hooks, and robust operational controls.

This repository contains a complete, modular implementation with:
- FastAPI backend (server/) with Redis-backed state and Prometheus metrics.
- Python Agent client (client/) illustrating mTLS and attestation usage.
- Hardened nginx configuration (infra/) for TLS termination and header forwarding.
- Dockerfiles and docker-compose for local testing (infra/docker-compose.yml).
- Scripts for dev certificate generation (scripts/gen_certs.sh).
- Unit, integration, and stress tests using pytest and fakeredis.
- Comprehensive documentation and production hardening guidance (docs/).

Why this exists
- Many systems need to differentiate trusted automated agents from interactive humans and generic clients. AOG enforces strict, reproducible proof-of-work-like puzzles (deterministic compute) bound to cryptographic identity (mTLS, signed headers) and optional attestation to strongly reduce impersonation risk.

Table of contents
- Quick start
- Architecture overview
- Security model
- API
- Certificates and PKI
- Production checklist
- Development and testing
- Contributing and license

Quick start (development)
1. Clone this repo locally:
   git clone https://github.com/<your-account>/<repo>.git
   cd <repo>

2. Generate development certificates (dev-only):
   cd scripts
   chmod +x gen_certs.sh
   ./gen_certs.sh
   cd ..

3. Start the stack (infra/docker-compose.yml):
   cd infra
   HEADER_HMAC_SECRET="$(openssl rand -hex 32)" docker-compose up --build

   - nginx listens on host port 8443 (HTTPS + mTLS).
   - server connects to Redis, exposes metrics on /metrics (via backend).
   - a sample client service demonstrates an agent flow.

4. Run tests:
   From repo root:
     pytest -q

Architecture overview
- Server (FastAPI)
  - GET /challenge: issues a one-time deterministic challenge (nonce, seed, iterations, deadline).
  - POST /task: accepts submissions; verifies deterministic result, timing, client identity, and prevents replay using Redis.
  - /metrics: Prometheus metrics.

- Client (Agent)
  - Uses mTLS client certs to authenticate.
  - Requests a challenge, runs iterative SHA-256 (deterministic), submits result with runtime and trace fingerprint.
  - Optionally creates a signed attestation JWT (dev placeholder).

- Networking
  - nginx (or a cloud load balancer) handles TLS/mTLS termination and forwards the client certificate PEM in a header. For authenticity, a signing mechanism (HMAC) is used to sign forwarded header values; the server verifies that signature with a secret shared via a secure secret manager.

Security model (high level)
- Authentication: mutual TLS or signed client-cert header forwarded from a trusted TLS terminator.
- Nonce & Replay protection: challenges are stored in Redis with TTL; submitted nonces are consumed atomically (SETNX) and kept flagged to prevent reuse.
- Deterministic verification: the server recomputes the iterative hash and compares with the submitted result using constant-time comparison.
- Replay & rate limiting: distributed Redis-based rate limiter and used-nonce store.
- Attestation: optional verification of agent-provided JWT signed by agent key or attestation mechanism (hook is provided).
- Logging: structured logging with sensitive data redaction.

API (summary)
- GET /challenge
  - Requires trusted client identity (signed header or mTLS).
  - Returns JSON: {nonce, seed, iterations, deadline_ts, issued_at}

- POST /task
  - Body: {nonce, result_hash, runtime_ms, client_fingerprint, trace_hash?, attestation?}
  - Validates: existence, client binding, deadline, recomputed hash, runtime bounds, attestation (optional), and consumes nonce atomically.
  - Responses: 200 accepted or appropriate 4xx/5xx.

- GET /metrics
  - Prometheus exposition of metrics.

Certificates and PKI
- Dev script: scripts/gen_certs.sh (creates CA, server, client certs for local testing).
- Production: do NOT use dev certs. Use enterprise PKI (Vault PKI, step-ca, or managed CA). Use short-lived certs, CRL/OCSP, and secrets manager for header HMAC and other secrets.

Production hardening checklist (essentials)
- Use a secure PKI and rotate keys regularly.
- Enforce mTLS at the backend or signed header authenticity at the proxy (with header HMAC secret).
- Replace in-memory stores with Redis (already implemented).
- Add CRL/OCSP checks and certificate revocation handling.
- Integrate hardware attestation (TPM/SGX) or cloud attestation service for stronger guarantees.
- Add monitoring, alerting, and dashboards for metrics (Prometheus + Grafana).
- Harden nginx TLS ciphers and settings; enable HSTS and HTTP/2 as appropriate.
- Run adversarial load/stress testing and validation.

Development & testing
- Python environment:
  - Install dependencies: pip install -r requirements.txt
- Tests:
  - Unit & integration: pytest tests/unit tests/integration
  - Stress tests: pytest tests/stress
- Linting / formatting: add and run your preferred linters (black/flake8/isort).

Operational notes
- Secret management: use Vault or cloud provider KMS to store HEADER_HMAC_SECRET and production secrets.
- Logging: ensure logs are shipped securely and do not contain seeds or private keys.
- Scaling: run multiple backends behind a load balancer; Redis ensures shared state for consumed nonces and rate-limiting.

Contributing
- Contributions are welcome. Please open issues and PRs against this repo; include tests for all functional changes.
- See docs/ for architecture and operations guides.

License
- This project is provided under the MIT License. See LICENSE for details.

Contact
- For design questions, attack modeling, or production tuning, open an issue or start a discussion in the repository.