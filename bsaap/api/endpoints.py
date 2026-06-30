"""
bsaap.api.endpoints
===================
FastAPI REST endpoints implementing all eight BSAAP API routes.

POST /register          Stage 1 — Agent registration
POST /auth/request      Stage 2 — Authentication request (build M1)
POST /auth/challenge    Stage 3a — Challenge issuance (build M2)
POST /auth/respond      Stage 3b — Response verification (verify M3)
POST /session/create    Stage 4 — Session key establishment
POST /message/send      Stage 5 — Encrypted message send
POST /session/close     Stage 6 — Session termination
GET  /audit/trail       Stage 6 — Retrieve Merkle audit chain
GET  /ledger/stats              — Fabric ledger statistics
"""

from __future__ import annotations

from typing import Dict, Any, Optional
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel

from bsaap.blockchain.fabric_stub import get_ledger
from bsaap.ca.authority import get_ca
from bsaap.models.schemas import (
    AuditTrailResponse,
    AuditRecord,
    RegistrationRequest,
    RegistrationResponse,
    AuthRequest,
    AuthRequestResult,
    ChallengeMessage,
    ChallengeResponse,
    EphemeralKeyExchange,
    SecureMessage,
    SecureMessageResult,
    SessionCloseRequest,
    SessionToken,
    VerificationResult,
)
from bsaap.protocol.bsaap_protocol import (
    AgentState,
    SessionState,
    clear_nonce_cache,
    stage1_register,
    stage2_build_auth_request,
    stage2_verify_auth_request,
    stage3_build_challenge,
    stage3_build_response,
    stage3_verify_response,
    stage4_establish_session,
    stage5_decrypt_message,
    stage5_encrypt_message,
    stage6_close_session,
    stage6_get_audit_trail,
)

# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="BSAAP — Blockchain-Integrated Secure Agent-to-Agent Authentication Protocol",
    version="1.0.0",
    description=(
        "Six-stage cryptographic authentication protocol for multi-agent AI systems. "
        "Implements mutual authentication, capability-scoped access control, "
        "X25519 forward-secret session keys, and Hyperledger Fabric audit logging."
    ),
)

# ---------------------------------------------------------------------------
# In-process agent registry (maps agent_id → AgentState)
# In production: replace with a distributed key-value store or HSM
# ---------------------------------------------------------------------------
_agent_registry: Dict[str, AgentState] = {}

# In-process message buffer for the demo flow (A's pending M1)
_pending_auth_requests: Dict[str, dict] = {}   # agent_id → M1 dict
_pending_challenges: Dict[str, dict] = {}      # agent_id → M2 dict


# ===========================================================================
# Stage 1 — Registration
# ===========================================================================

class RegisterPayload(BaseModel):
    agent_id: str
    role: str = "worker"
    capabilities: list[str]
    trust_level: str = "standard"


@app.post("/register", response_model=RegistrationResponse, status_code=201)
def register_agent(payload: RegisterPayload):
    """Stage 1: Register a new AI agent, issue X.509 cert, anchor DID on Fabric."""
    if payload.agent_id in _agent_registry:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Agent '{payload.agent_id}' already registered.",
        )
    if not payload.capabilities:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Capabilities list must not be empty.",
        )

    agent_state = stage1_register(
        agent_id=payload.agent_id,
        role=payload.role,
        capabilities=payload.capabilities,
        trust_level=payload.trust_level,
    )
    _agent_registry[payload.agent_id] = agent_state

    ca = get_ca()
    _, expires_at = ca.get_cert_validity(agent_state.certificate_pem)

    return RegistrationResponse(
        agent_id=agent_state.agent_id,
        did=agent_state.did,
        certificate_pem=agent_state.certificate_pem,
        fabric_tx_id=agent_state.fabric_tx_id,
        issued_at=__import__("time").time(),
        expires_at=expires_at.timestamp(),
        status="registered",
    )


# ===========================================================================
# Stage 2 — Authentication Request
# ===========================================================================

class AuthRequestPayload(BaseModel):
    initiator_id: str
    target_id: str
    requested_capability: str


@app.post("/auth/request", response_model=AuthRequestResult)
def auth_request(payload: AuthRequestPayload):
    """Stage 2: Agent A builds and submits an authentication request (M1)."""
    agent_a = _get_agent(payload.initiator_id)
    _get_agent(payload.target_id)  # validate target exists

    # Check capability is in agent A's scope
    if payload.requested_capability not in agent_a.capabilities:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Capability '{payload.requested_capability}' not in agent's certificate scope.",
        )

    m1 = stage2_build_auth_request(agent_a, payload.requested_capability)

    # Verify M1 immediately as if Agent B received it
    ok, reason = stage2_verify_auth_request(m1)
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Auth request verification failed: {reason}",
        )

    # Store pending M1 for the challenge step
    _pending_auth_requests[payload.initiator_id] = m1

    return AuthRequestResult(accepted=True, reason="Stage 2 verification passed")


# ===========================================================================
# Stage 3a — Challenge Issuance
# ===========================================================================

class ChallengePayload(BaseModel):
    responder_id: str   # Agent B
    initiator_id: str   # Agent A


@app.post("/auth/challenge", response_model=ChallengeMessage)
def issue_challenge(payload: ChallengePayload):
    """Stage 3a: Agent B generates a challenge (M2) for Agent A."""
    agent_b = _get_agent(payload.responder_id)

    if payload.initiator_id not in _pending_auth_requests:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"No pending auth request from agent '{payload.initiator_id}'.",
        )

    m2 = stage3_build_challenge(agent_b)
    _pending_challenges[payload.initiator_id] = m2

    return ChallengeMessage(
        challenge_c=m2["challenge_c"],
        nonce_n2=m2["nonce_n2"],
        certificate_pem=m2["certificate_pem"],
        signature=m2["signature"],
    )


# ===========================================================================
# Stage 3b — Challenge Response & Verification
# ===========================================================================

class RespondPayload(BaseModel):
    initiator_id: str   # Agent A
    responder_id: str   # Agent B


@app.post("/auth/respond", response_model=VerificationResult)
def challenge_respond(payload: RespondPayload):
    """Stage 3b: Agent A responds to challenge; Agent B verifies PoP."""
    agent_a = _get_agent(payload.initiator_id)

    m1 = _pending_auth_requests.get(payload.initiator_id)
    m2 = _pending_challenges.get(payload.initiator_id)
    if m1 is None or m2 is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No pending challenge for this initiator.",
        )

    # Agent A builds M3
    m3, err = stage3_build_response(m2, agent_a)
    if m3 is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Challenge response build failed: {err}",
        )

    # Agent B verifies M3
    ok, reason = stage3_verify_response(m3, m2, agent_a.certificate_pem)
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Challenge response verification failed: {reason}",
        )

    return VerificationResult(verified=True, reason="Mutual authentication complete")


# ===========================================================================
# Stage 4 — Session Key Establishment
# ===========================================================================

class SessionCreatePayload(BaseModel):
    agent_a_id: str
    agent_b_id: str


@app.post("/session/create", response_model=SessionToken)
def create_session(payload: SessionCreatePayload):
    """Stage 4: Establish forward-secret session key via X25519 ECDH + HKDF."""
    agent_a = _get_agent(payload.agent_a_id)
    agent_b = _get_agent(payload.agent_b_id)

    m1 = _pending_auth_requests.get(payload.agent_a_id)
    m2 = _pending_challenges.get(payload.agent_a_id)
    if m1 is None or m2 is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Authentication must be completed before session creation.",
        )

    capability = m1["requested_capability"]
    sess_a, sess_b = stage4_establish_session(agent_a, agent_b, m1, m2, capability)

    # Clean up pending state
    _pending_auth_requests.pop(payload.agent_a_id, None)
    _pending_challenges.pop(payload.agent_a_id, None)

    return SessionToken(
        session_id=sess_a.session_id,
        agent_a_id=sess_a.agent_a_id,
        agent_b_id=sess_a.agent_b_id,
        capability=sess_a.capability,
        expires_at=sess_a.expires_at,
        fabric_tx_id=sess_a.fabric_create_tx,
        status="active",
    )


# ===========================================================================
# Stage 5 — Secure Message Send
# ===========================================================================

class MessagePayload(BaseModel):
    session_id: str
    sender_id: str
    plaintext: str   # UTF-8 message (base64 in production)


@app.post("/message/send", response_model=SecureMessageResult)
def send_message(payload: MessagePayload):
    """Stage 5: Encrypt and send a message using AES-256-GCM session key."""
    agent = _get_agent(payload.sender_id)
    session = agent.get_session(payload.session_id)
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session '{payload.session_id}' not found for agent '{payload.sender_id}'.",
        )

    wire = stage5_encrypt_message(session, payload.plaintext.encode("utf-8"))
    return SecureMessageResult(
        session_id=wire["session_id"],
        seq_num=wire["seq_num"],
        verified=True,
    )


# ===========================================================================
# Stage 6 — Session Close
# ===========================================================================

@app.post("/session/close")
def close_session(payload: SessionCloseRequest):
    """Stage 6: Terminate session and write Merkle-chained audit record to Fabric."""
    agent = _get_agent(payload.agent_id)
    session = agent.get_session(payload.session_id)
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session '{payload.session_id}' not found.",
        )

    record = stage6_close_session(agent, session)
    return {"status": "closed", "audit_record": record}


# ===========================================================================
# Stage 6 — Audit Trail
# ===========================================================================

@app.get("/audit/trail", response_model=AuditTrailResponse)
def get_audit_trail():
    """Stage 6: Retrieve and verify the full Merkle-chained audit trail."""
    records, chain_valid = stage6_get_audit_trail()

    audit_records = [
        AuditRecord(
            session_id=r["session_id"],
            agent_a_id=r["agent_a_id"],
            agent_b_id=r["agent_b_id"],
            capability=r["capability"],
            start_time=r["start_time"],
            end_time=r["end_time"],
            prev_hash=r.get("prev_hash", "0" * 64),
            record_hash=r.get("record_hash", ""),
            fabric_tx_id=r.get("fabric_tx_id", ""),
        )
        for r in records
    ]
    return AuditTrailResponse(
        total_records=len(audit_records),
        records=audit_records,
        chain_valid=chain_valid,
    )


# ===========================================================================
# Utility endpoints
# ===========================================================================

@app.get("/ledger/stats")
def ledger_stats():
    """Return current Fabric ledger statistics."""
    return get_ledger().ledger_stats()


@app.get("/health")
def health():
    return {"status": "ok", "protocol": "BSAAP", "version": "1.0.0"}


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _get_agent(agent_id: str) -> AgentState:
    agent = _agent_registry.get(agent_id)
    if agent is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent '{agent_id}' not found. Register first via POST /register.",
        )
    return agent
