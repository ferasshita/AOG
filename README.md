<!-- Project Title -->
<h1 align="center">Agent-Only Access Gate (AOG)</h1>

<!-- Project Subtitle -->
<p align="center">
  A AOC is a system that allows only authorized autonomous agents to pass deterministic compute challenges.
  Human users and unsanctioned clients are rejected through a combination of strong identity binding, replay protection,
  and verifiable deterministic work.
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
2. The server issues a one-time deterministic compute challenge.
3. The agent performs deterministic work and submits the result.
4. The server verifies the work, timing, identity binding, and consumes the nonce to prevent replay.

The design prioritizes deterministic verification, replay resistance, and operational readiness.

---

## Features

- Deterministic compute challenges bound to client identity.
- Mutual TLS (mTLS) support and/or trusted proxy header forwarding with authenticity protection.
- Redis-backed nonce lifecycle, replay protection, and rate limiting.
- Constant-time comparison for submitted results.
- Prometheus metrics endpoint for monitoring and alerting.
- Modular structure (server, client, infra).
- Test suite covering unit, integration, and stress scenarios.

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
- Issues one-time challenges
- Validates and consumes submissions
- Stores ephemeral and replay-prevention state in Redis
- Exposes Prometheus metrics

#### Client (Reference Agent)
- Authenticates via client certificates (mTLS)
- Requests challenges
- Performs deterministic iterative hashing
- Submits result with runtime metadata and optional attestation token

#### Networking / Edge
- Nginx (or a cloud load balancer) terminates TLS/mTLS
- For deployments that forward client identity via headers, a signing mechanism is used to authenticate forwarded values

---

## Security Model

### Identity and Authentication
AOG supports:
- Mutual TLS (recommended where possible)
- Trusted proxy header forwarding, with authenticity protection (HMAC-signed forwarding) when mTLS terminates upstream

### Challenge Binding
Challenges are bound to:
- A server-issued nonce
- A deterministic seed and iteration count
- A strict deadline
- A client identity/fingerprint

### Replay Protection
- Challenges are stored in Redis with TTL.
- Nonces are consumed atomically and marked as used.
- Replay attempts are rejected deterministically.

### Deterministic Verification
- The server recomputes the deterministic work using the provided parameters.
- Result verification uses constant-time comparison to reduce timing side channels.

### Rate Limiting and Abuse Controls
- Distributed rate limiting can be enforced via Redis, protecting against brute force and excessive challenge issuance.

### Attestation (Optional)
AOG can accept an agent-provided attestation token (for example, a JWT) and includes integration hooks for:
- Agent key-based signatures
- Hardware attestation (TPM, SGX) or cloud attestation services

---

## API Summary

### `GET /challenge`
Issues a one-time deterministic challenge.

- Requires trusted client identity (mTLS or verified forwarded identity)
- Returns JSON:
  - `nonce`
  - `seed`
  - `iterations`
  - `deadline_ts`
  - `issued_at`

### `POST /task`
Submits a solved challenge.

- Body (example fields):
  - `nonce`
  - `result_hash`
  - `runtime_ms`
  - `client_fingerprint`
  - `trace_hash` (optional)
  - `attestation` (optional)

Validation typically includes:
- Challenge existence and freshness
- Client binding and identity checks
- Deadline enforcement
- Deterministic recomputation and constant-time match
- Runtime bounds checks (policy dependent)
- Optional attestation verification
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
