<!-- Project Title -->
<h1 align="center">Agent-Only Access Gate (AOG)</h1>

<!-- Project Subtitle -->
<p align="center">
  A system that allows only authorized autonomous agents to pass verification challenges.
  Agents are authenticated through a combination of strong identity binding, reasoning challenges,
  autonomy attestation, replay protection, and verifiable work.
</p>

<!-- Badges -->
<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License"></a>
  <img src="https://img.shields.io/badge/backend-FastAPI-009688.svg" alt="FastAPI">
  <img src="https://img.shields.io/badge/cache-Redis-dc382d.svg" alt="Redis">
  <img src="https://img.shields.io/badge/metrics-Prometheus-e6522c.svg" alt="Prometheus">
  <img src="https://img.shields.io/badge/proxy-nginx-009639.svg" alt="nginx">
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> •
  <a href="#architecture-overview">Architecture</a> •
  <a href="#security-model">Security</a> •
  <a href="#api-summary">API</a> •
  <a href="#production-hardening-checklist">Production</a> •
  <a href="#contributing">Contributing</a>
</p>

---

## Overview

Agent-Only Access Gate (AOG) is an open-source access control layer designed for environments where you must distinguish
trusted, autonomous software agents from interactive humans and generic clients.

AOG enforces a strict request flow:
1. A trusted agent proves identity (mTLS or trusted proxy forwarding).
2. The server issues a one-time verification challenge (reasoning-based or computational).
3. The agent solves the challenge and provides autonomy attestation.
4. The server verifies the solution, autonomy claims, timing, identity binding, and consumes the nonce to prevent replay.

The design prioritizes reasoning verification, autonomy attestation, replay resistance, and operational readiness.

---

## Features

- Reasoning-based challenges requiring semantic understanding and problem-solving capabilities.
- Autonomy attestation validation to verify continuous autonomous operation.
- Client identity binding via mutual TLS (mTLS) or trusted proxy header forwarding.
- Redis-backed nonce lifecycle, replay protection, and rate limiting.
- Constant-time comparison for submitted results.
- Prometheus metrics endpoint for monitoring and alerting.
- Modular structure (server, client, infra).
- Test suite covering unit, integration, and stress scenarios.
- Backward compatibility with legacy computational challenges.

---

## Repository Layout

- `server/`  
  FastAPI backend, validation, Redis-backed state, and Prometheus metrics.

- `client/`  
  Reference agent client showing mTLS usage, challenge solving, and submission flow.

- `infra/`  
  Nginx configuration, Dockerfiles, and `docker-compose` for local or staged deployments.

- `scripts/`  
  Development utilities such as certificate generation.

- `tests/`  
  Unit, integration, and stress tests.

- `docs/`  
  Architecture and operational guidance, hardening notes, and design references.

---

## Quick Start

### Prerequisites
- Docker and Docker Compose (recommended for local evaluation)
- OpenSSL (for generating a development HMAC secret and dev certificates)

### 1) Clone the repository
```bash
git clone https://github.com/ferasshita/AOG.git
cd AOG
```

### 2) Generate development certificates (development only)
```bash
cd scripts
chmod +x gen_certs.sh
./gen_certs.sh
cd ..
```

### 3) Start the stack
```bash
cd infra
HEADER_HMAC_SECRET="$(openssl rand -hex 32)" docker-compose up --build
```

Notes:
- Nginx listens on host port `8443` (HTTPS + mTLS, depending on configuration).
- The backend connects to Redis and exposes Prometheus metrics at `/metrics`.

### 4) Run tests (from repository root)
```bash
pytest -q
```

---

## Architecture Overview

### Components

#### Server (FastAPI)
- Issues one-time challenges (reasoning or computational)
- Validates and consumes submissions
- Verifies autonomy attestation claims
- Stores ephemeral and replay-prevention state in Redis
- Exposes Prometheus metrics

#### Client (Reference Agent)
- Authenticates via client certificates (mTLS)
- Requests challenges
- Solves reasoning challenges using semantic analysis and problem-solving
- Generates autonomy attestation with operation tracking
- Submits result with runtime metadata and attestation token

#### Networking / Edge
- Nginx (or a cloud load balancer) terminates TLS/mTLS
- For deployments that forward client identity via headers, a signing mechanism is used to authenticate forwarded values

---

## Security Model

AOG implements a multi-layered verification approach combining cryptographic identity, reasoning challenges, 
and autonomy attestation to authenticate autonomous agents.

### Identity and Authentication
AOG supports:
- Mutual TLS (recommended where possible)
- Trusted proxy header forwarding, with authenticity protection (HMAC-signed forwarding) when mTLS terminates upstream

### Challenge Types

#### Reasoning Challenges
- Semantic analysis of code patterns and design principles
- Logic reasoning and problem-solving tasks
- Context understanding and system design questions
- Requires AI-specific capabilities for solving

#### Autonomy Attestation
- Continuous operation time tracking
- Autonomous action logging
- Decision chain evidence
- System behavior validation

#### Legacy Challenges
- Computational challenges for backward compatibility
- Deterministic iterative hashing
- Maintained for transition support

### Challenge Binding
Challenges are bound to:
- A server-issued nonce
- A strict deadline
- A client identity/fingerprint
- Challenge-specific parameters (question, seed, etc.)

### Replay Protection
- Challenges are stored in Redis with TTL.
- Nonces are consumed atomically and marked as used.
- Replay attempts are rejected deterministically.

### Verification Process
- The server validates reasoning answers using constant-time comparison
- Autonomy attestation is verified for completeness and validity
- Result verification uses cryptographic techniques to reduce timing side channels

### Rate Limiting and Abuse Controls
- Distributed rate limiting can be enforced via Redis, protecting against brute force and excessive challenge issuance.

### Attestation (Optional)
AOG can accept an agent-provided attestation token (for example, a JWT) and includes integration hooks for:
- Agent key-based signatures
- Hardware attestation (TPM, SGX) or cloud attestation services

---

## API Summary

### `GET /challenge`
Issues a one-time verification challenge.

- Requires trusted client identity (mTLS or verified forwarded identity)
- Query parameters:
  - `challenge_type`: "reasoning" (default) or "legacy"
- Returns JSON:
  - `nonce`
  - `challenge_type`
  - `question` (for reasoning challenges)
  - `seed` (for all challenges)
  - `iterations` (for legacy challenges)
  - `deadline_ts`
  - `issued_at`

### `POST /task`
Submits a solved challenge.

- Body fields:
  - `nonce`
  - `challenge_type`
  - `answer` (for reasoning challenges)
  - `result_hash` (for legacy challenges)
  - `runtime_ms`
  - `client_fingerprint`
  - `autonomy_attestation` (for reasoning challenges)
  - `trace_hash` (optional)
  - `attestation` (optional)

Validation includes:
- Challenge existence and freshness
- Client binding and identity checks
- Deadline enforcement
- Answer verification (reasoning) or hash verification (legacy)
- Autonomy attestation validation (reasoning)
- Runtime bounds checks (policy dependent)
- Optional JWT attestation verification
- Atomic nonce consumption

### `GET /metrics`
Prometheus exposition endpoint.

---

## Certificates and PKI

### Development
- Use `scripts/gen_certs.sh` to generate local development certificates.
- Development certificates are for local testing only.

### Production
Do not use development certificates in production.

Recommended practices:
- Use an enterprise PKI (Vault PKI, step-ca, or managed CA)
- Prefer short-lived certificates with automated rotation
- Enforce certificate revocation (CRL/OCSP) where applicable
- Store secrets (for example `HEADER_HMAC_SECRET`) in a secrets manager (Vault, AWS Secrets Manager, GCP Secret Manager, etc.)

---

## Observability

- Prometheus metrics are exposed via `/metrics`.
- Integrate with Grafana dashboards and alerting policies.
- Ensure logs are structured and redact sensitive values (nonces, seeds, private keys, credentials).

---

## Hardening Checklist

- Use a secure PKI and rotate keys regularly.
- Enforce mTLS end-to-end or ensure forwarded identity headers are cryptographically authenticated.
- Run Redis in a highly-available configuration where required.
- Enforce strict TLS configuration at the edge (modern ciphers, TLS 1.2+ or TLS 1.3, HSTS where applicable).
- Add certificate revocation handling (CRL/OCSP) and operational processes.
- Implement robust rate limiting and anomaly detection.
- Perform adversarial testing and load/stress testing before deployment.
- Separate duties and secure CI/CD secrets and signing keys.

---

## Development and Testing

### Install dependencies
```bash
pip install -r requirements.txt
```

### Run tests
- Unit tests:
```bash
pytest tests/unit
```

- Integration tests:
```bash
pytest tests/integration
```

- Stress tests:
```bash
pytest tests/stress
```

---

## Contributing

Contributions are welcome.

Suggested workflow:
1. Fork the repository and create a feature branch.
2. Add tests for functional changes.
3. Ensure all tests pass locally.
4. Submit a pull request with a clear description and rationale.

If you are proposing security-sensitive changes, include a short threat analysis and expected operational impact.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## Contact

For design questions, threat modeling or open an issue or start a discussion in the repository.

Repository owner:
- GitHub: https://github.com/ferasshita
