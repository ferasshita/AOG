# Architecture - Agent-Only Access Gate

## Overview

Agent-Only Access Gate (AOG) implements a multi-layered verification system that combines cryptographic identity, 
reasoning challenges, and autonomy attestation to authenticate autonomous agents.

### Core Design Principles

The system enforces agent-only access through:
1. **Strong Identity Binding** - mTLS-based mutual TLS authentication with client certificates
2. **Reasoning Challenges** - Semantic analysis and problem-solving tasks requiring AI capabilities
3. **Autonomy Attestation** - Continuous operation tracking and autonomous decision verification
4. **Replay Protection** - Nonce-based one-time challenges preventing replay attacks
5. **Rate Limiting** - Distributed rate limiting protecting against brute force attacks

### What This System Validates

✅ **Successfully Validates:**
- Cryptographic identity via mTLS
- Reasoning and semantic understanding capabilities
- Continuous autonomous operation patterns
- Replay attack prevention (nonce-based)
- Rate limiting and observability patterns
- Constant-time verification to prevent timing attacks

### Architecture Components

#### Server (FastAPI)
- **Challenge Generation**: Issues reasoning or computational challenges with strict deadlines
- **Verification Engine**: Validates answers, autonomy attestation, and identity binding
- **State Management**: Redis-backed storage for challenges and replay protection
- **Metrics**: Prometheus endpoint for monitoring and alerting

#### Client Agent
- **Identity**: Authenticates via mTLS client certificates
- **Reasoning Solver**: Analyzes semantic challenges using AI capabilities
- **Autonomy Tracking**: Generates attestation with operation logs and decision chains
- **Challenge Submission**: Submits solutions with runtime metadata and attestation

#### Reverse Proxy (nginx)
- **TLS Termination**: Handles mTLS and forwards client cert info
- **Header Signing**: HMAC-signed headers for identity forwarding
- **Load Balancing**: Distributes traffic across backend instances

### Challenge Types

#### Reasoning Challenges
- **Semantic Analysis**: Code pattern recognition and design principle identification
- **Logic Reasoning**: Fallacy detection and logical inference
- **Context Understanding**: System design and best practice questions
- **Problem Solving**: Security and architecture decision-making

These challenges require:
- Natural language understanding
- Domain knowledge (software engineering, security, system design)
- Contextual analysis and reasoning
- AI-specific problem-solving capabilities

#### Autonomy Attestation
Agents must provide evidence of autonomous operation:
- **Operation Time**: Duration of continuous autonomous execution
- **Action Logging**: Record of autonomous actions taken
- **Decision Chain**: Evidence of independent decision-making process
- **System Metadata**: Runtime environment information

Validation criteria:
- Minimum operation time threshold (≥1 second)
- Non-empty action log with temporal ordering
- Decision chain showing autonomous reasoning
- Consistency checks across attestation fields

#### Legacy Challenges (Backward Compatibility)
- Deterministic iterative hashing (SHA-256)
- Maintained for transition support
- Can be gradually phased out

### Security Model

**Authentication:**
- mTLS with client certificates
- HMAC-signed header forwarding for proxy deployments

**Verification:**
- Constant-time answer comparison (prevents timing attacks)
- Cryptographic binding of challenge to client identity
- Autonomy attestation validation

**Integrity:**
- HMAC/hashing for header authenticity
- Nonce-based challenge binding

**Confidentiality:**
- TLS encryption for all communications
- Secure storage of challenge state in Redis

**Replay Protection:**
- Per-challenge nonce with atomic consumption
- TTL-based challenge expiration
- USED_NONCES tracking in Redis

**Rate Limiting:**
- Per-client distributed rate limiting
- Window-based counters in Redis
- Protection against brute-force attempts

**Observability:**
- Structured logging with event tracking
- Prometheus metrics for monitoring
- Anomaly detection hooks
