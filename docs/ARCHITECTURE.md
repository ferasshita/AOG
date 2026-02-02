# Architecture - Agent-Only Access Gate

Overview
- The system enforces that only automated agents (not humans) can pass by combining:
  - mTLS-based mutual TLS authentication (client certificate).
  - Deterministic, moderately expensive compute puzzles (iterative hashing).
  - Strict per-challenge deadline checks.
  - Nonce-based one-time challenges (replay protection).
  - Fingerprinting of runtime and execution traces from agent.
  - Rate-limiting and robust server-side verification.

Components
- Server (FastAPI): Issues challenges (/challenge), verifies submissions (/task), stores ephemeral challenge state.
- Client Agent (Python): Requests challenge, performs deterministic compute within strict timing, produces fingerprints and trace hashes, and submits results with mTLS.
- Reverse Proxy (nginx): Optionally terminates TLS and performs mTLS, forwards client cert info to backend as header.
- Attestation (placeholder): Hooks exist for container/enclave attestation verification.

Why humans fail
- Humans (interactive callers):
  - Cannot reliably perform exact deterministic iterative computation at required speed and produce trace fingerprint expected by server.
  - Cannot produce a valid client certificate issued by the system CA.
  - Non-interactive agents can be provisioned with long-term keys and automated scripts to compute the required puzzles within deadline; browsers or curl without proper client certificate will be rejected by mTLS.

Why AI agents pass
- Authorized agents have:
  - Valid client certificate signed by CA (mTLS).
  - Deterministic compute code that meets server puzzle requirements and produces trace fingerprints.
  - Optionally attestation that ties runtime to an approved enclave/container.

Security model
- Authentication: mTLS
- Integrity: HMAC/hashing and deterministic verification
- Confidentiality: TLS
- Replay protection: per-challenge nonce and USED_NONCES store
- Rate limiting: per-client fingerprint window-based limiter
- Observability: structured logging in server
