# Operations and Runbook (Essential)

- Start services via docker-compose (dev):
    cd infra
    HEADER_HMAC_SECRET="$(openssl rand -hex 32)" docker-compose up --build

- To rotate HEADER_HMAC_SECRET:
  1. Generate new secret in secret manager
  2. Roll nginx sidecar/signing component and server with new secret in a controlled window
  3. Monitoring should show no auth errors

- To revoke a client certificate:
  - Add the cert serial to CRL or revoke in your CA
  - Optionally store revoked list in Redis and check on submission flow

- In case of suspicious activity:
  - Inspect logs (aog_challenges_issued_total, aog_tasks_rejected_total)
  - Quarantine affected client cert fingerprint(s)