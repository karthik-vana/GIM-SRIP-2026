"""
tests/test_stage2_auth_request.py
==================================
Stage 2 — Authentication Request Tests (6 cases)

T2.1  Valid M1 is built and accepted
T2.2  Replay attack blocked (nonce reuse)
T2.3  Expired timestamp rejected
T2.4  Invalid certificate (tampered) rejected
T2.5  CN mismatch (impersonation) rejected
T2.6  Revoked agent rejected by Fabric IsRevoked check
"""

import time
import secrets
import pytest
from unittest.mock import patch

from bsaap.blockchain.fabric_stub import get_ledger, reset_ledger
from bsaap.ca.authority import get_ca, reset_ca
from bsaap.protocol.bsaap_protocol import (
    clear_nonce_cache,
    stage1_register,
    stage2_build_auth_request,
    stage2_verify_auth_request,
)


@pytest.fixture(autouse=True)
def reset_state():
    reset_ca()
    reset_ledger()
    clear_nonce_cache()
    yield
    reset_ca()
    reset_ledger()
    clear_nonce_cache()


@pytest.fixture
def registered_agent():
    return stage1_register(
        agent_id="agent_A",
        role="orchestrator",
        capabilities=["data_pipeline", "summarisation"],
    )


# ---------------------------------------------------------------------------
# T2.1 — Valid M1 is built and passes verification
# ---------------------------------------------------------------------------
def test_T2_1_valid_auth_request_accepted(registered_agent):
    m1 = stage2_build_auth_request(registered_agent, "data_pipeline")
    ok, reason = stage2_verify_auth_request(m1)
    assert ok, f"Valid M1 should be accepted. Reason: {reason}"
    assert reason == ""


# ---------------------------------------------------------------------------
# T2.2 — Replay attack: same nonce submitted twice
# ---------------------------------------------------------------------------
def test_T2_2_replay_attack_blocked(registered_agent):
    m1 = stage2_build_auth_request(registered_agent, "data_pipeline")

    # First submission OK
    ok1, _ = stage2_verify_auth_request(m1)
    assert ok1, "First M1 submission should be accepted"

    # Second submission (replay) must be rejected
    ok2, reason2 = stage2_verify_auth_request(m1)
    assert not ok2, "Replayed M1 should be rejected"
    assert "replay" in reason2.lower() or "nonce" in reason2.lower(), \
        f"Rejection reason should mention replay/nonce. Got: {reason2}"


# ---------------------------------------------------------------------------
# T2.3 — Expired timestamp rejected
# ---------------------------------------------------------------------------
def test_T2_3_expired_timestamp_rejected(registered_agent):
    m1 = stage2_build_auth_request(registered_agent, "data_pipeline")
    # Forge an old timestamp (6 seconds in the past — outside 5s window)
    m1["timestamp"] = time.time() - 6.0
    # Use fresh nonce so replay check doesn't trigger first
    m1["nonce_n1"] = secrets.token_bytes(32).hex()

    ok, reason = stage2_verify_auth_request(m1)
    assert not ok, "Expired timestamp should be rejected"
    assert "freshness" in reason.lower() or "timestamp" in reason.lower(), \
        f"Rejection reason should mention timestamp. Got: {reason}"


# ---------------------------------------------------------------------------
# T2.4 — Tampered certificate rejected
# ---------------------------------------------------------------------------
def test_T2_4_tampered_certificate_rejected(registered_agent):
    m1 = stage2_build_auth_request(registered_agent, "data_pipeline")
    # Tamper: replace a byte in the PEM certificate
    original_cert = m1["certificate_pem"]
    tampered_cert = original_cert.replace("MIIB", "MIIC", 1)
    m1["certificate_pem"] = tampered_cert
    m1["nonce_n1"] = secrets.token_bytes(32).hex()

    ok, reason = stage2_verify_auth_request(m1)
    assert not ok, "Tampered certificate should be rejected"


# ---------------------------------------------------------------------------
# T2.5 — CN mismatch (impersonation attempt) rejected
# ---------------------------------------------------------------------------
def test_T2_5_cn_mismatch_rejected():
    # Register two agents
    agent_real = stage1_register(
        agent_id="agent_real",
        role="worker",
        capabilities=["compute"],
    )
    agent_fake = stage1_register(
        agent_id="agent_fake",
        role="worker",
        capabilities=["compute"],
    )

    # Build M1 for agent_fake but claim to be agent_real
    m1 = stage2_build_auth_request(agent_fake, "compute")
    m1["agent_id"] = "agent_real"   # CN mismatch attack
    m1["nonce_n1"] = secrets.token_bytes(32).hex()
    m1["timestamp"] = time.time()

    ok, reason = stage2_verify_auth_request(m1)
    assert not ok, "CN mismatch impersonation should be rejected"
    assert "cn" in reason.lower() or "mismatch" in reason.lower() or \
           "agent_id" in reason.lower() or "signature" in reason.lower(), \
        f"Rejection reason: {reason}"


# ---------------------------------------------------------------------------
# T2.6 — Revoked agent rejected by Fabric IsRevoked chaincode
# ---------------------------------------------------------------------------
def test_T2_6_revoked_agent_rejected(registered_agent):
    # Revoke the agent on Fabric
    ledger = get_ledger()
    ledger.revoke_agent(registered_agent.did)
    assert ledger.is_revoked(registered_agent.did), "Agent should be marked revoked"

    m1 = stage2_build_auth_request(registered_agent, "data_pipeline")
    ok, reason = stage2_verify_auth_request(m1)
    assert not ok, "Revoked agent should be rejected"
    assert "revoked" in reason.lower(), \
        f"Rejection reason should mention revocation. Got: {reason}"
