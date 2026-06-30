"""
bsaap.models.schemas
====================
Pydantic v2 data models for all BSAAP protocol messages and API payloads.
"""

from __future__ import annotations

import time
from typing import List, Optional
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Stage 1 — Registration
# ---------------------------------------------------------------------------

class RegistrationRequest(BaseModel):
    agent_id: str = Field(..., description="Unique agent identifier")
    role: str = Field(..., description="Agent role (e.g. orchestrator, worker)")
    capabilities: List[str] = Field(..., description="Allowed task capability list")
    public_key_pem: str = Field(..., description="ECDSA P-256 public key (PEM)")
    did: str = Field(..., description="W3C DID: did:bsaap:<hex16>")
    timestamp: float = Field(default_factory=time.time)


class RegistrationResponse(BaseModel):
    agent_id: str
    did: str
    certificate_pem: str
    fabric_tx_id: str
    issued_at: float
    expires_at: float
    status: str = "registered"


# ---------------------------------------------------------------------------
# Stage 2 — Authentication Request (Message M1)
# ---------------------------------------------------------------------------

class AuthRequest(BaseModel):
    """Message M1: Agent A → Agent B"""
    agent_id: str
    timestamp: float
    nonce_n1: str = Field(..., description="256-bit CSPRNG nonce (hex)")
    certificate_pem: str
    requested_capability: str
    ephemeral_pub_key: str = Field(..., description="X25519 ephemeral public key (hex)")
    signature: str = Field(..., description="ECDSA signature over payload (hex)")


class AuthRequestResult(BaseModel):
    accepted: bool
    reason: str = ""


# ---------------------------------------------------------------------------
# Stage 3 — Challenge-Response (Messages M2 and M3)
# ---------------------------------------------------------------------------

class ChallengeMessage(BaseModel):
    """Message M2: Agent B → Agent A"""
    challenge_c: str = Field(..., description="256-bit challenge (hex)")
    nonce_n2: str = Field(..., description="256-bit nonce (hex)")
    certificate_pem: str = Field(..., description="Agent B certificate")
    signature: str = Field(..., description="B's ECDSA sig over H(c||n2) (hex)")


class ChallengeResponse(BaseModel):
    """Message M3: Agent A → Agent B"""
    response_r: str = Field(..., description="A's ECDSA sig over H(c||n2) (hex)")
    agent_id: str


class VerificationResult(BaseModel):
    verified: bool
    reason: str = ""


# ---------------------------------------------------------------------------
# Stage 4 — Session Key Establishment
# ---------------------------------------------------------------------------

class EphemeralKeyExchange(BaseModel):
    """Ephemeral X25519 public key from the peer."""
    agent_id: str
    ephemeral_pub_key: str = Field(..., description="X25519 pub key (hex, 32 bytes)")


class SessionToken(BaseModel):
    session_id: str
    agent_a_id: str
    agent_b_id: str
    capability: str
    expires_at: float
    # NOTE: session_key is NEVER transmitted; stored locally only
    fabric_tx_id: str
    status: str = "active"


# ---------------------------------------------------------------------------
# Stage 5 — Secure Communication
# ---------------------------------------------------------------------------

class SecureMessage(BaseModel):
    """Encrypted wire message."""
    session_id: str
    seq_num: int = Field(..., description="Monotonically increasing sequence number")
    iv: str = Field(..., description="AES-GCM IV (hex, 12 bytes)")
    ciphertext: str = Field(..., description="AES-256-GCM ciphertext (hex)")
    gcm_tag: str = Field(..., description="GCM authentication tag (hex)")
    mac: str = Field(..., description="HMAC-SHA256 sequence integrity MAC (hex)")


class SecureMessageResult(BaseModel):
    session_id: str
    seq_num: int
    decrypted: Optional[str] = None
    verified: bool = True


# ---------------------------------------------------------------------------
# Stage 6 — Session Termination and Blockchain Audit
# ---------------------------------------------------------------------------

class SessionCloseRequest(BaseModel):
    session_id: str
    agent_id: str


class AuditRecord(BaseModel):
    """On-chain Merkle-chained audit record R_i."""
    session_id: str
    agent_a_id: str
    agent_b_id: str
    capability: str
    start_time: float
    end_time: float
    prev_hash: str = Field(..., description="h_{i-1}: SHA-256 of previous record")
    record_hash: str = Field(..., description="h_i: SHA-256 of this record")
    fabric_tx_id: str


class AuditTrailResponse(BaseModel):
    total_records: int
    records: List[AuditRecord]
    chain_valid: bool
