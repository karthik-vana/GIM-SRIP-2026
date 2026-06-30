"""
tests/test_stage4_session_key.py
==================================
Stage 4 — Session Key Establishment Tests (5 cases)

T4.1  Session key is derived and identical on both sides (ECDH symmetry)
T4.2  Session key is 32 bytes (AES-256 width)
T4.3  Two sessions produce different keys (nonce binding)
T4.4  Session token stored in both agent states
T4.5  Fabric CreateSession chaincode called; session visible in ledger
"""

import pytest
from bsaap.blockchain.fabric_stub import get_ledger, reset_ledger
from bsaap.ca.authority import reset_ca
from bsaap.protocol.bsaap_protocol import (
    clear_nonce_cache,
    stage1_register,
    stage2_build_auth_request,
    stage2_verify_auth_request,
    stage3_build_challenge,
    stage3_build_response,
    stage3_verify_response,
    stage4_establish_session,
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


def _full_handshake(agent_a, agent_b, capability="compute"):
    """Run Stages 1-3 and return (m1, m2) for Stage 4."""
    m1 = stage2_build_auth_request(agent_a, capability)
    ok, reason = stage2_verify_auth_request(m1)
    assert ok, f"Stage 2 failed: {reason}"
    m2 = stage3_build_challenge(agent_b)
    m3, err = stage3_build_response(m2, agent_a)
    assert m3 is not None, f"Stage 3b failed: {err}"
    ok3, r3 = stage3_verify_response(m3, m2, agent_a.certificate_pem)
    assert ok3, f"Stage 3 verify failed: {r3}"
    return m1, m2


# ---------------------------------------------------------------------------
# T4.1 — Session keys are equal on both sides (ECDH symmetry)
# ---------------------------------------------------------------------------
def test_T4_1_session_keys_equal_on_both_sides():
    agent_a = stage1_register("a1", "orchestrator", ["compute"])
    agent_b = stage1_register("b1", "worker", ["compute"])

    m1, m2 = _full_handshake(agent_a, agent_b)
    sess_a, sess_b = stage4_establish_session(agent_a, agent_b, m1, m2, "compute")

    assert sess_a.session_key == sess_b.session_key, \
        "Session keys must be identical on both sides"


# ---------------------------------------------------------------------------
# T4.2 — Session key is exactly 32 bytes (suitable for AES-256)
# ---------------------------------------------------------------------------
def test_T4_2_session_key_is_32_bytes():
    agent_a = stage1_register("a2", "orchestrator", ["analysis"])
    agent_b = stage1_register("b2", "worker", ["analysis"])

    m1, m2 = _full_handshake(agent_a, agent_b, "analysis")
    sess_a, _ = stage4_establish_session(agent_a, agent_b, m1, m2, "analysis")

    assert len(sess_a.session_key) == 32, \
        f"Session key must be 32 bytes, got {len(sess_a.session_key)}"


# ---------------------------------------------------------------------------
# T4.3 — Two sessions produce different keys (nonce randomness)
# ---------------------------------------------------------------------------
def test_T4_3_different_sessions_have_different_keys():
    agent_a = stage1_register("a3", "orchestrator", ["nlp"])
    agent_b = stage1_register("b3", "worker", ["nlp"])

    m1_first, m2_first = _full_handshake(agent_a, agent_b, "nlp")
    sess_a1, _ = stage4_establish_session(agent_a, agent_b, m1_first, m2_first, "nlp")

    # Second session — need fresh nonce, so re-run handshake
    m1_second, m2_second = _full_handshake(agent_a, agent_b, "nlp")
    sess_a2, _ = stage4_establish_session(agent_a, agent_b, m1_second, m2_second, "nlp")

    assert sess_a1.session_key != sess_a2.session_key, \
        "Different sessions must produce different session keys"
    assert sess_a1.session_id != sess_a2.session_id, \
        "Different sessions must have different session IDs"


# ---------------------------------------------------------------------------
# T4.4 — Session token stored in agent state
# ---------------------------------------------------------------------------
def test_T4_4_session_stored_in_agent_state():
    agent_a = stage1_register("a4", "orchestrator", ["forecast"])
    agent_b = stage1_register("b4", "worker", ["forecast"])

    m1, m2 = _full_handshake(agent_a, agent_b, "forecast")
    sess_a, sess_b = stage4_establish_session(agent_a, agent_b, m1, m2, "forecast")

    # Both agents should be able to retrieve the session
    retrieved_a = agent_a.get_session(sess_a.session_id)
    retrieved_b = agent_b.get_session(sess_b.session_id)

    assert retrieved_a is not None, "Agent A should have session stored"
    assert retrieved_b is not None, "Agent B should have session stored"
    assert retrieved_a.session_id == sess_a.session_id
    assert retrieved_b.session_id == sess_b.session_id
    assert retrieved_a.status == "active"


# ---------------------------------------------------------------------------
# T4.5 — Fabric CreateSession called; session visible on ledger
# ---------------------------------------------------------------------------
def test_T4_5_session_anchored_on_fabric_ledger():
    agent_a = stage1_register("a5", "orchestrator", ["etl"])
    agent_b = stage1_register("b5", "worker", ["etl"])

    m1, m2 = _full_handshake(agent_a, agent_b, "etl")
    sess_a, _ = stage4_establish_session(agent_a, agent_b, m1, m2, "etl")

    ledger = get_ledger()
    ledger_session = ledger.get_session(sess_a.session_id)

    assert ledger_session is not None, \
        "Session should be present in Fabric ledger"
    assert ledger_session["agent_a_id"] == "a5"
    assert ledger_session["agent_b_id"] == "b5"
    assert ledger_session["capability"] == "etl"
    assert ledger_session["status"] == "active"
    assert sess_a.fabric_create_tx.startswith("tx_"), \
        "Fabric tx_id should be set after CreateSession"
