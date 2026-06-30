"""
bsaap.protocol.bsaap_protocol
==============================
Complete implementation of all six BSAAP protocol stages.

Stage 1  — Agent Registration with On-Chain DID
Stage 2  — Authentication Request
Stage 3  — Challenge-Response Verification
Stage 4  — Ephemeral Session Key Establishment (X25519 + HKDF)
Stage 5  — Secure Authenticated Communication (AES-256-GCM)
Stage 6  — Session Termination and Blockchain Audit Logging
"""

from __future__ import annotations

import hashlib
import os
import secrets
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from bsaap.blockchain.fabric_stub import get_ledger, FabricLedgerStub
from bsaap.ca.authority import get_ca, AuthenticationAuthority
from bsaap.crypto.aes_utils import (
    aes_gcm_encrypt,
    aes_gcm_decrypt,
    build_aad,
    compute_sequence_mac,
    verify_sequence_mac,
)
from bsaap.crypto.ecdh_utils import (
    compute_shared_secret,
    erase_private_key,
    generate_x25519_keypair,
    public_key_to_raw,
    raw_to_public_key,
)
from bsaap.crypto.ecdsa_utils import (
    derive_did,
    generate_keypair,
    pem_to_public_key,
    private_key_to_pem,
    public_key_to_pem,
    sign_ecdsa,
    verify_ecdsa,
)
from bsaap.crypto.hkdf_utils import derive_session_key

# ---------------------------------------------------------------------------
# In-memory nonce cache (replay prevention)
# ---------------------------------------------------------------------------
_nonce_cache: set[str] = set()
_TIMESTAMP_WINDOW_SECONDS: float = 5.0
_SESSION_TTL_SECONDS: float = 3600.0


# ---------------------------------------------------------------------------
# Agent state dataclass
# ---------------------------------------------------------------------------

@dataclass
class AgentState:
    """Holds all runtime state for one BSAAP agent instance."""
    agent_id: str
    role: str
    capabilities: List[str]

    # Long-term ECDSA P-256 keys
    private_key_pem: bytes = field(default_factory=bytes)
    public_key_pem: bytes = field(default_factory=bytes)
    did: str = ""
    certificate_pem: str = ""
    fabric_tx_id: str = ""

    # Per-session state (ephemeral)
    _sessions: Dict[str, "SessionState"] = field(default_factory=dict)

    def get_session(self, sid: str) -> Optional["SessionState"]:
        return self._sessions.get(sid)

    def store_session(self, sid: str, sess: "SessionState") -> None:
        self._sessions[sid] = sess


@dataclass
class SessionState:
    """Ephemeral state for one authenticated BSAAP session."""
    session_id: str
    agent_a_id: str
    agent_b_id: str
    capability: str
    session_key: bytes           # K_s — never transmitted
    start_time: float
    expires_at: float
    seq_num: int = 0             # monotonically increasing
    fabric_create_tx: str = ""
    status: str = "active"


# ===========================================================================
# Stage 1 — Agent Registration with On-Chain DID
# ===========================================================================

def stage1_register(
    agent_id: str,
    role: str,
    capabilities: List[str],
    ca: Optional[AuthenticationAuthority] = None,
    ledger: Optional[FabricLedgerStub] = None,
    trust_level: str = "standard",
) -> AgentState:
    """Execute BSAAP Stage 1: key generation, certificate issuance, DID anchoring.

    Parameters
    ----------
    agent_id     : unique agent identifier
    role         : agent role (e.g. "orchestrator", "worker", "analyst")
    capabilities : list of allowed task capability strings
    ca           : CA instance (uses singleton if None)
    ledger       : Fabric ledger stub (uses singleton if None)
    trust_level  : trust classification for certificate

    Returns
    -------
    AgentState with populated keys, DID, certificate, and tx_id.
    """
    ca = ca or get_ca()
    ledger = ledger or get_ledger()

    # Step 1: Generate ECDSA P-256 key pair
    private_key, public_key = generate_keypair()
    sk_pem = private_key_to_pem(private_key)
    pk_pem = public_key_to_pem(public_key)

    # Step 2: Derive DID
    did = derive_did(public_key)

    # Step 3: Obtain certificate from CA (contains capability OID)
    cert_pem = ca.issue_certificate_pem(
        agent_id=agent_id,
        agent_public_key=public_key,
        capabilities=capabilities,
        role=role,
        trust_level=trust_level,
    )

    # Step 4: Anchor DID on Fabric ledger via RegisterAgent chaincode
    tx_id = ledger.register_agent(
        did=did,
        public_key_pem=pk_pem.decode(),
        capabilities=capabilities,
        agent_id=agent_id,
        role=role,
    )

    state = AgentState(
        agent_id=agent_id,
        role=role,
        capabilities=capabilities,
        private_key_pem=sk_pem,
        public_key_pem=pk_pem,
        did=did,
        certificate_pem=cert_pem,
        fabric_tx_id=tx_id,
    )
    return state


# ===========================================================================
# Stage 2 — Authentication Request (Agent A → Agent B)
# ===========================================================================

def stage2_build_auth_request(
    agent_a: AgentState,
    requested_capability: str,
) -> dict:
    """Build Stage 2 Message M1.

    M1 = {agent_id, timestamp, nonce_n1, cert_A, requested_capability,
           ephemeral_pub_key, signature}

    Returns
    -------
    dict with all M1 fields (hex-encoded binary fields).
    """
    private_key = _load_private_key(agent_a.private_key_pem)

    # Generate fresh 256-bit nonce and UTC timestamp
    nonce_n1 = secrets.token_bytes(32)
    timestamp = time.time()

    # Generate ephemeral X25519 key pair (sent in M1 for Stage 4)
    eph_private, eph_public = generate_x25519_keypair()
    eph_pub_raw = public_key_to_raw(eph_public)

    # Build payload and sign: H(agent_id || timestamp || n1 || cert_pem || cap)
    payload = _build_stage2_payload(
        agent_a.agent_id, timestamp, nonce_n1,
        agent_a.certificate_pem, requested_capability
    )
    signature = sign_ecdsa(private_key, payload)

    return {
        "agent_id": agent_a.agent_id,
        "timestamp": timestamp,
        "nonce_n1": nonce_n1.hex(),
        "certificate_pem": agent_a.certificate_pem,
        "requested_capability": requested_capability,
        "ephemeral_pub_key": eph_pub_raw.hex(),
        "signature": signature.hex(),
        # Ephemeral private key stored temporarily for Stage 4
        "_eph_private_key": eph_private,
    }


def stage2_verify_auth_request(
    m1: dict,
    ca: Optional[AuthenticationAuthority] = None,
    ledger: Optional[FabricLedgerStub] = None,
) -> Tuple[bool, str]:
    """Verify Stage 2 Message M1 at Agent B.

    Checks (as per paper §6.2):
      (i)   Timestamp freshness (±5 seconds)
      (ii)  Nonce uniqueness (anti-replay)
      (iii) Certificate valid (chain + expiry + revocation)
      (iv)  ECDSA signature verifies under pk_A
      (v)   CN in cert matches agent_id (anti-impersonation)

    Returns
    -------
    (True, "") on success, (False, reason) on failure.
    """
    ca = ca or get_ca()
    ledger = ledger or get_ledger()

    # (i) Timestamp freshness
    now = time.time()
    if abs(now - m1["timestamp"]) > _TIMESTAMP_WINDOW_SECONDS:
        return False, "Timestamp outside 5-second freshness window"

    # (ii) Replay prevention — nonce uniqueness
    nonce_n1 = m1["nonce_n1"]
    if nonce_n1 in _nonce_cache:
        return False, "Replay detected: nonce already seen"
    _nonce_cache.add(nonce_n1)

    # (iii) Certificate chain validity (signature + expiry)
    cert_pem = m1["certificate_pem"]
    if not ca.verify_certificate(cert_pem):
        return False, "Certificate chain verification failed or expired"

    # Revocation check via Fabric IsRevoked chaincode
    try:
        cert_pk = ca.get_public_key_from_cert(cert_pem)
        did = derive_did(cert_pk)
        if ledger.is_revoked(did):
            return False, f"Agent DID {did} is revoked on Fabric ledger"
    except Exception as e:
        return False, f"Revocation check failed: {e}"

    # (iv) ECDSA signature verification
    try:
        public_key = ca.get_public_key_from_cert(cert_pem)
        nonce_bytes = bytes.fromhex(nonce_n1)
        payload = _build_stage2_payload(
            m1["agent_id"], m1["timestamp"], nonce_bytes,
            cert_pem, m1["requested_capability"]
        )
        sig_bytes = bytes.fromhex(m1["signature"])
        if not verify_ecdsa(public_key, payload, sig_bytes):
            return False, "ECDSA signature verification failed"
    except Exception as e:
        return False, f"Signature verification error: {e}"

    # (v) CN binding — agent_id must match certificate CN
    try:
        cn = ca.get_cn_from_cert(cert_pem)
        if cn != m1["agent_id"]:
            return False, f"CN '{cn}' does not match claimed agent_id '{m1['agent_id']}'"
    except Exception as e:
        return False, f"CN extraction error: {e}"

    return True, ""


def _build_stage2_payload(
    agent_id: str,
    timestamp: float,
    nonce_n1: bytes,
    cert_pem: str,
    capability: str,
) -> bytes:
    """Canonical payload for Stage 2 signature."""
    h = hashlib.sha256()
    h.update(agent_id.encode())
    h.update(str(timestamp).encode())
    h.update(nonce_n1)
    h.update(cert_pem.encode())
    h.update(capability.encode())
    return h.digest()


# ===========================================================================
# Stage 3 — Challenge-Response Verification
# ===========================================================================

def stage3_build_challenge(agent_b: AgentState) -> dict:
    """Build Stage 3 Message M2 (Agent B → Agent A).

    M2 = {challenge_c, nonce_n2, cert_B, signature_B}
    """
    private_key = _load_private_key(agent_b.private_key_pem)

    challenge_c = secrets.token_bytes(32)
    nonce_n2 = secrets.token_bytes(32)

    payload = hashlib.sha256(challenge_c + nonce_n2).digest()
    signature_b = sign_ecdsa(private_key, payload)

    return {
        "challenge_c": challenge_c.hex(),
        "nonce_n2": nonce_n2.hex(),
        "certificate_pem": agent_b.certificate_pem,
        "signature": signature_b.hex(),
    }


def stage3_build_response(
    m2: dict,
    agent_a: AgentState,
    ca: Optional[AuthenticationAuthority] = None,
) -> Tuple[Optional[dict], str]:
    """Build Stage 3 Message M3 (Agent A → Agent B): respond to challenge.

    Verifies B's signature first (MITM guard), then signs with A's key (PoP).

    Returns
    -------
    (M3_dict, "") on success, (None, reason) on failure.
    """
    ca = ca or get_ca()

    # Verify B's challenge signature (MITM detection)
    try:
        b_public_key = ca.get_public_key_from_cert(m2["certificate_pem"])
        if not ca.verify_certificate(m2["certificate_pem"]):
            return None, "Agent B certificate invalid"

        challenge_c = bytes.fromhex(m2["challenge_c"])
        nonce_n2 = bytes.fromhex(m2["nonce_n2"])
        payload = hashlib.sha256(challenge_c + nonce_n2).digest()

        sig_b = bytes.fromhex(m2["signature"])
        if not verify_ecdsa(b_public_key, payload, sig_b):
            return None, "Agent B challenge signature invalid — possible MITM"
    except Exception as e:
        return None, f"Challenge verification error: {e}"

    # Sign the challenge with A's private key (proof-of-possession)
    a_private_key = _load_private_key(agent_a.private_key_pem)
    response_r = sign_ecdsa(a_private_key, payload)

    m3 = {
        "response_r": response_r.hex(),
        "agent_id": agent_a.agent_id,
    }
    return m3, ""


def stage3_verify_response(
    m3: dict,
    m2: dict,
    cert_a_pem: str,
    ca: Optional[AuthenticationAuthority] = None,
) -> Tuple[bool, str]:
    """Verify Stage 3 Message M3 at Agent B.

    Verifies A's ECDSA signature over H(c_B || n2) — proof-of-private-key-possession.

    Returns
    -------
    (True, "") on success, (False, reason) on failure.
    """
    ca = ca or get_ca()

    try:
        a_public_key = ca.get_public_key_from_cert(cert_a_pem)
        challenge_c = bytes.fromhex(m2["challenge_c"])
        nonce_n2 = bytes.fromhex(m2["nonce_n2"])
        payload = hashlib.sha256(challenge_c + nonce_n2).digest()

        sig_r = bytes.fromhex(m3["response_r"])
        if not verify_ecdsa(a_public_key, payload, sig_r):
            return False, "Response signature invalid — private key not possessed"
    except Exception as e:
        return False, f"Response verification error: {e}"

    return True, ""


# ===========================================================================
# Stage 4 — Ephemeral Session Key Establishment (X25519 + HKDF)
# ===========================================================================

def stage4_establish_session(
    agent_a: AgentState,
    agent_b: AgentState,
    m1: dict,
    m2: dict,
    requested_capability: str,
    ledger: Optional[FabricLedgerStub] = None,
) -> Tuple[SessionState, SessionState]:
    """Establish a shared session key using X25519 ECDH + HKDF-SHA-256.

    Implements Equations (4)-(5) from the BSAAP paper:
      SS  = X25519(ek_A, eK_B) = X25519(ek_B, eK_A)
      K_s = HKDF-SHA256(SS, n1||n2, "BSAAP-v1-session")

    Both agent states are updated with the session token.
    Ephemeral private keys are erased after K_s derivation.

    Returns
    -------
    (session_state_a, session_state_b)
    """
    ledger = ledger or get_ledger()

    # Agent A: use ephemeral key from M1; generate B's ephemeral key
    eph_private_a = m1.get("_eph_private_key")
    eph_pub_a_raw = bytes.fromhex(m1["ephemeral_pub_key"])

    # Agent B: generate ephemeral X25519 key pair
    eph_private_b, eph_public_b = generate_x25519_keypair()
    eph_pub_b_raw = public_key_to_raw(eph_public_b)

    # Compute shared secrets from both sides
    eph_pub_a = raw_to_public_key(eph_pub_a_raw)

    # If _eph_private_key is available (same process), compute directly
    if eph_private_a is not None:
        ss_a = compute_shared_secret(eph_private_a, eph_public_b)
        ss_b = compute_shared_secret(eph_private_b, eph_pub_a)
        assert ss_a == ss_b, "ECDH shared secret mismatch — protocol error"
        shared_secret = ss_a
    else:
        # Cross-process: only B computes; A must do the same externally
        shared_secret = compute_shared_secret(eph_private_b, eph_pub_a)

    # Nonces from Stage 2 and Stage 3
    nonce_n1 = bytes.fromhex(m1["nonce_n1"])
    nonce_n2 = bytes.fromhex(m2["nonce_n2"])

    # Derive session key K_s
    session_key = derive_session_key(
        shared_secret=shared_secret,
        nonce_a=nonce_n1,
        nonce_b=nonce_n2,
    )

    # Erase ephemeral private keys immediately (forward secrecy)
    if eph_private_a is not None:
        erase_private_key(eph_private_a)
    erase_private_key(eph_private_b)

    # Generate session ID
    sid_raw = hashlib.sha256(
        agent_a.agent_id.encode() +
        agent_b.agent_id.encode() +
        nonce_n1 + nonce_n2
    ).hexdigest()[:32]

    now = time.time()
    expires_at = now + _SESSION_TTL_SECONDS

    # Create session on Fabric ledger
    fabric_tx = ledger.create_session(
        session_id=sid_raw,
        agent_a_id=agent_a.agent_id,
        agent_b_id=agent_b.agent_id,
        capability=requested_capability,
        expires_at=expires_at,
    )

    # Build session state for both agents
    sess_a = SessionState(
        session_id=sid_raw,
        agent_a_id=agent_a.agent_id,
        agent_b_id=agent_b.agent_id,
        capability=requested_capability,
        session_key=session_key,
        start_time=now,
        expires_at=expires_at,
        fabric_create_tx=fabric_tx,
    )
    sess_b = SessionState(
        session_id=sid_raw,
        agent_a_id=agent_a.agent_id,
        agent_b_id=agent_b.agent_id,
        capability=requested_capability,
        session_key=session_key,
        start_time=now,
        expires_at=expires_at,
        fabric_create_tx=fabric_tx,
    )

    # Store sessions in agent state
    agent_a.store_session(sid_raw, sess_a)
    agent_b.store_session(sid_raw, sess_b)

    return sess_a, sess_b


# ===========================================================================
# Stage 5 — Secure Authenticated Communication (AES-256-GCM)
# ===========================================================================

def stage5_encrypt_message(
    session: SessionState,
    plaintext: bytes,
) -> dict:
    """Encrypt and MAC a message for transmission.

    Wire format: {sid, seq_num, iv, ciphertext, gcm_tag, mac}

    The GCM tag authenticates the ciphertext + AAD.
    The outer HMAC-SHA-256 MAC binds the message to session + seqNum.
    """
    if session.status != "active":
        raise ValueError(f"Session {session.session_id} is not active")
    if time.time() > session.expires_at:
        raise ValueError("Session has expired")

    session.seq_num += 1
    aad = build_aad(session.session_id, session.seq_num)

    iv, ciphertext, tag = aes_gcm_encrypt(
        key=session.session_key,
        plaintext=plaintext,
        aad=aad,
    )

    mac = compute_sequence_mac(
        key=session.session_key,
        sid=session.session_id,
        seq_num=session.seq_num,
        iv=iv,
        ciphertext=ciphertext,
    )

    return {
        "session_id": session.session_id,
        "seq_num": session.seq_num,
        "iv": iv.hex(),
        "ciphertext": ciphertext.hex(),
        "gcm_tag": tag.hex(),
        "mac": mac.hex(),
    }


def stage5_decrypt_message(
    session: SessionState,
    wire_msg: dict,
) -> Tuple[Optional[bytes], str]:
    """Decrypt and verify a received wire message.

    Verifications:
      1. Session ID matches
      2. Sequence number is as expected (monotonic)
      3. HMAC-SHA-256 MAC verifies (sequence integrity)
      4. AES-256-GCM tag verifies (ciphertext integrity + AAD)

    Returns
    -------
    (plaintext, "") on success, (None, reason) on failure.
    """
    if wire_msg["session_id"] != session.session_id:
        return None, "Session ID mismatch"

    expected_seq = session.seq_num + 1
    if wire_msg["seq_num"] != expected_seq:
        return None, f"Sequence number mismatch: expected {expected_seq}, got {wire_msg['seq_num']}"

    iv = bytes.fromhex(wire_msg["iv"])
    ciphertext = bytes.fromhex(wire_msg["ciphertext"])
    tag = bytes.fromhex(wire_msg["gcm_tag"])
    received_mac = bytes.fromhex(wire_msg["mac"])

    # Verify outer HMAC-SHA-256 MAC first (fast, cheap)
    if not verify_sequence_mac(
        key=session.session_key,
        sid=session.session_id,
        seq_num=wire_msg["seq_num"],
        iv=iv,
        ciphertext=ciphertext,
        received_mac=received_mac,
    ):
        return None, "HMAC-SHA-256 sequence MAC verification failed"

    # Verify GCM tag and decrypt
    aad = build_aad(session.session_id, wire_msg["seq_num"])
    plaintext = aes_gcm_decrypt(
        key=session.session_key,
        iv=iv,
        ciphertext=ciphertext,
        tag=tag,
        aad=aad,
    )
    if plaintext is None:
        return None, "AES-256-GCM authentication tag verification failed"

    session.seq_num = wire_msg["seq_num"]
    return plaintext, ""


# ===========================================================================
# Stage 6 — Session Termination and Blockchain Audit Logging
# ===========================================================================

def stage6_close_session(
    agent_b: AgentState,
    session: SessionState,
    ledger: Optional[FabricLedgerStub] = None,
) -> dict:
    """Terminate session and write Merkle-chained audit record to Fabric.

    Audit record R_i = (sid, id_A, id_B, t_start, t_end, cap, h_{i-1})
    h_i = SHA256(JSON_canonical(R_i))

    Returns the written audit record dict.
    """
    ledger = ledger or get_ledger()

    end_time = time.time()
    session.status = "closed"

    # Build audit record
    record = {
        "session_id": session.session_id,
        "agent_a_id": session.agent_a_id,
        "agent_b_id": session.agent_b_id,
        "capability": session.capability,
        "start_time": session.start_time,
        "end_time": end_time,
    }

    # Close session on Fabric
    ledger.close_session(session.session_id)

    # Write Merkle-chained audit record
    tx_id = ledger.write_audit_record(record)
    record["fabric_tx_id"] = tx_id

    return record


def stage6_get_audit_trail(
    ledger: Optional[FabricLedgerStub] = None,
) -> Tuple[List[dict], bool]:
    """Retrieve and verify the full Merkle-chained audit trail.

    Returns
    -------
    (records, chain_valid)
    """
    ledger = ledger or get_ledger()
    records = ledger.get_audit_trail()
    chain_valid = ledger.verify_audit_chain()
    return records, chain_valid


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _load_private_key(private_key_pem: bytes):
    from cryptography.hazmat.primitives import serialization
    return serialization.load_pem_private_key(private_key_pem, password=None)


def clear_nonce_cache() -> None:
    """Clear nonce cache (testing only)."""
    global _nonce_cache
    _nonce_cache.clear()
