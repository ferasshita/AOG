#!/usr/bin/env bash
set -euo pipefail

OUTDIR="./certs"
mkdir -p "${OUTDIR}"

echo "Generating dev CA, server, and client certs in ${OUTDIR} (dev use only)"

# CA
openssl genrsa -out "${OUTDIR}/ca.key" 4096
openssl req -x509 -new -nodes -key "${OUTDIR}/ca.key" -sha256 -days 3650 -out "${OUTDIR}/ca.crt" -subj "/CN=agent-only-ca"

# Server
openssl genrsa -out "${OUTDIR}/server.key" 2048
openssl req -new -key "${OUTDIR}/server.key" -out "${OUTDIR}/server.csr" -subj "/CN=aog-server"
openssl x509 -req -in "${OUTDIR}/server.csr" -CA "${OUTDIR}/ca.crt" -CAkey "${OUTDIR}/ca.key" -CAcreateserial -out "${OUTDIR}/server.crt" -days 365 -sha256

# Client
openssl genrsa -out "${OUTDIR}/client.key" 2048
openssl req -new -key "${OUTDIR}/client.key" -out "${OUTDIR}/client.csr" -subj "/CN=aog-client"
openssl x509 -req -in "${OUTDIR}/client.csr" -CA "${OUTDIR}/ca.crt" -CAkey "${OUTDIR}/ca.key" -CAcreateserial -out "${OUTDIR}/client.crt" -days 365 -sha256

# Output perms
chmod 600 "${OUTDIR}"/*.key || true
echo "Generated certs in ${OUTDIR}"