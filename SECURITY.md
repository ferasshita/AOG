# Security Policy

## Supported Versions

The following versions of AOG are currently supported with security updates:

| Version | Supported          |
| ------- | ------------------ |
| latest (`main`) | :white_check_mark: |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in AOG, please report it responsibly:

1. **Open a private security advisory** via GitHub:  
   Navigate to **Security → Advisories → Report a vulnerability** in this repository.

2. **Alternatively**, contact the maintainer directly through GitHub:  
   [https://github.com/ferasshita](https://github.com/ferasshita)

### What to Include

When reporting a vulnerability, please provide:

- A description of the vulnerability and its potential impact.
- Steps to reproduce the issue or a proof-of-concept (if available).
- The component(s) affected (e.g., challenge issuance, submission verification, identity binding, replay protection).
- Any suggested mitigations or fixes, if applicable.

### Response Timeline

- You will receive an acknowledgment within **72 hours**.
- We will investigate and aim to provide a resolution or mitigation plan within **14 days** for critical issues.
- You will be kept informed of progress throughout the process.

## Disclosure Policy

We follow a coordinated disclosure process:

- We ask that you give us a reasonable amount of time to investigate and address the issue before any public disclosure.
- Once a fix is available, we will publish a security advisory describing the vulnerability, its impact, and the remediation.
- Credit will be given to reporters who wish to be acknowledged.

## Security Considerations

AOG is designed with security as a core concern. Key areas include:

- **Authentication**: Mutual TLS and HMAC-signed forwarded identity headers.
- **Challenge integrity**: Nonces are bound to client identity and consumed atomically to prevent replay.
- **Cryptographic operations**: Constant-time comparisons are used where applicable.
- **Rate limiting**: Redis-backed rate limiting protects against brute force and abuse.

When contributing changes that touch these areas, please review [CONTRIBUTING.md](CONTRIBUTING.md) for guidance on security-sensitive contributions.
