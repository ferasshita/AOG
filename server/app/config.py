"""
Configuration loader for AOG server.

All sensitive values are read from environment variables.
In production, inject these via your secret manager.
"""

import os

REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")
RATE_LIMIT_COUNT = int(os.environ.get("RATE_LIMIT_COUNT", "10"))
RATE_LIMIT_WINDOW = int(os.environ.get("RATE_LIMIT_WINDOW", "60"))  # seconds
HEADER_HMAC_SECRET = os.environ.get("HEADER_HMAC_SECRET", None)  # required if nginx signs client cert header
CHALLENGE_TTL_EXTRA = int(os.environ.get("CHALLENGE_TTL_EXTRA", "60"))  # extra seconds beyond target
METRICS_ENABLED = os.environ.get("METRICS_ENABLED", "1") == "1"
# Iteration defaults for legacy challenges (tune per hardware in production)
DEFAULT_ITERATIONS = int(os.environ.get("DEFAULT_ITERATIONS", "100000"))
DEFAULT_TARGET_MS = int(os.environ.get("DEFAULT_TARGET_MS", "10000"))
# Challenge type: "reasoning" (default) or "legacy"
DEFAULT_CHALLENGE_TYPE = os.environ.get("DEFAULT_CHALLENGE_TYPE", "reasoning")
# Minimum autonomous operation time in seconds for autonomy attestation
MIN_AUTONOMOUS_OPERATION_TIME = float(os.environ.get("MIN_AUTONOMOUS_OPERATION_TIME", "1.0"))
# If true, server will require attestation JWT with submission and attempt to verify it
REQUIRE_ATTESTATION = os.environ.get("REQUIRE_ATTESTATION", "0") == "1"