# Certificate generation for development

This folder is ignored for private keys. Use the script below to create a dev CA, server, and client certificate.

Run:
  chmod +x ../scripts/gen_certs.sh
  ../scripts/gen_certs.sh

This will produce:
- ca.key, ca.crt
- server.key, server.crt
- client.key, client.crt

Place them in the `certs/` directory (the script does this by default when run from repo root).

IMPORTANT: These certs are for development only. In production:
- Use a strong PKI
- Protect and rotate private keys
- Implement CRL/OCSP or short-lived certs
- Use secret management (Vault, KMS)