# Contributing to AOG

Thank you for your interest in contributing to Agent-Only Access Gate (AOG). Contributions are welcome and appreciated.

## Getting Started

1. Fork the repository and clone your fork locally.
2. Create a feature branch from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Make your changes and add tests as appropriate.
5. Run the test suite to verify nothing is broken:
   ```bash
   pytest -q
   ```
6. Commit your changes with a clear, descriptive message.
7. Push your branch and open a pull request.

## Development Setup

### Prerequisites

- Python 3.9+
- Docker and Docker Compose (for integration testing)
- OpenSSL (for generating development certificates)

### Generating Development Certificates

```bash
cd scripts
chmod +x gen_certs.sh
./gen_certs.sh
cd ..
```

### Running the Stack Locally

```bash
cd infra
HEADER_HMAC_SECRET="$(openssl rand -hex 32)" docker-compose up --build
```

## Running Tests

- **Unit tests:**
  ```bash
  pytest tests/unit
  ```
- **Integration tests:**
  ```bash
  pytest tests/integration
  ```
- **Stress tests:**
  ```bash
  pytest tests/stress
  ```

## Pull Request Guidelines

- Keep pull requests focused on a single concern.
- Include a clear description of the change and the motivation behind it.
- Add or update tests for all functional changes.
- Ensure all existing tests pass before submitting.
- Reference any related issues in the pull request description.

## Security-Sensitive Changes

If you are proposing changes that affect authentication, challenge verification, cryptographic operations, or replay protection, please:

1. Include a short threat analysis describing potential risks.
2. Describe the expected operational impact.
3. Consider opening an issue first to discuss the approach before submitting a large pull request.

For reporting security vulnerabilities, see [SECURITY.md](SECURITY.md) — **do not open a public issue for security vulnerabilities**.

## Code Style

- Follow [PEP 8](https://peps.python.org/pep-0008/) for Python code.
- Keep functions small and focused.
- Add docstrings to public functions and classes.
- Avoid committing secrets, certificates, or credentials.

## Code of Conduct

Please note that this project is released with a [Code of Conduct](CODE_OF_CONDUCT.md). By participating in this project you agree to abide by its terms.
