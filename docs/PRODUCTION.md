# Production Hardening and Deployment Checklist

This document lists required and recommended steps to make Agent-Only Access Gate production-grade.

1) PKI & Certificates
- Use a strong enterprise PKI (Vault PKI, step-ca, or managed CA).
- Use short-lived certificates (rotate frequently).
- Implement revocation (OCSP or CRL) and check it on the server.
- Use hardware security modules for CA keys in production.

2) mTLS and Proxying
- Option A (recommended): Run backend with mTLS (uvicorn) and validate client certificates directly.
- Option B: Terminate mTLS at nginx/load balancer and sign forwarded headers with a secret (use lua or a signing sidecar). Validate HMAC in server (HEADER_HMAC_SECRET).
- Ensure the header-signing key is stored in a secure secret manager.

3) Secret Management
- Do not store secrets in repo or images.
- Use Vault or cloud KMS to inject HEADER_HMAC_SECRET and other secrets at runtime.

4) State & Scaling
- Use Redis (clustered) for challenges and rate limiting.
- Store audit logs in an immutable storage (e.g., append-only logs).
- Ensure atomic nonce consume semantics (we use SETNX).

5) Attestation
- Integrate TPM/SGX attestation or vendor-specific attestation for agent authenticity.
- Verify attestation tokens cryptographically and keep a registry of trusted vendors/keys.

6) Observability & Monitoring
- Export metrics to Prometheus and monitor:
  - challenge issuance rates
  - acceptance / rejection counts
  - rate-limit and replay detections
- Configure alerting on spikes, auth failures, and resource exhaustion.

7) DoS Protection
- Enforce stricter rate limits at the network edge.
- Add request queueing and global concurrency caps.
- Consider offloading expensive checks to a verification queue.

8) Testing & CI
- Add end-to-end tests that run against a staging environment with dev PKI.
- Load test timing behavior to ensure agents on supported hardware can meet deadlines.

9) Governance & Legal
- Evaluate legal and ethical implications of "AI-only" gating.
- Provide support and appeals for legitimate automated users.
