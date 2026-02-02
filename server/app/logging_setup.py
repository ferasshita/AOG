"""
Structured JSON-like logging setup (simple).
Redacts sensitive fields such as seeds and private keys before logging.
"""

import logging
import os
import json

class RedactingFormatter(logging.Formatter):
    SENSITIVE_KEYS = {"seed", "server_key", "client_key", "private_key"}

    def format(self, record):
        if isinstance(record.msg, dict):
            msg = record.msg.copy()
            for k in list(msg.keys()):
                if k in self.SENSITIVE_KEYS:
                    msg[k] = "<redacted>"
            record.msg = json.dumps(msg)
        return super().format(record)

def setup_logging():
    handler = logging.StreamHandler()
    fmt = '%(asctime)s %(levelname)s %(name)s: %(message)s'
    formatter = RedactingFormatter(fmt)
    handler.setFormatter(formatter)
    root = logging.getLogger()
    if not root.handlers:
        root.addHandler(handler)
    root.setLevel(logging.INFO)

# Ensure configuration is applied on import
setup_logging()