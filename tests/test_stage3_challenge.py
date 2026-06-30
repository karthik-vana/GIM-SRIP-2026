"""
tests/test_stage3_challenge.py
================================
Stage 3 — Challenge-Response Verification Tests (6 cases)

T3.1  Valid challenge-response round trip succeeds
T3.2  MITM detection: B's challenge signature tampered
T3.3  Bad response signature (wrong private key) rejected
T3.4  Proof-of-possession: only holder of sk_A can produce valid response
T3.5  Agent B certificate validation in Stage 3
T3.6  Full Stage 2 → Stage 3 sequential flow succeeds
"""

import secrets
import pytest

from bsaap.blockchain.fabric_stub import reset_ledger
from bsaap.ca.authority import get_ca, reset_ca
from bsaap.protocol.bsaap_protocol import (
    clear_nonce_cache,
    stage1_register,
    stage2_build_auth_request,
    stage2_verify_auth_request,
    stage3_build_challenge,
    stage3_build_response,
    stage3_verify_response,
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
def two_agents():
    agent_a = stage1_register("agentA", "orchestrator", ["ml_inference"])
    agent_b = stage1_register("agentB", "worker", ["ml_inference"])
    return agent_a, agent_b


# ---------------------------------------------------------------------------
# T3.1 — Valid challenge-response round trip
# ---------------------------------------------------------------------------
def test_T3_1_valid_challenge_response_roundtrip(two_agents):
    agent_a, agent_b = two_agents

    # Stage 3a: B issues challenge
    m2 = stage3_build_challenge(agent_b)
    assert "challenge_c" in m2
    assert "nonce_n2" in m2
    assert "certificate_pem" in m2
    assert "signature" in m2

    # Stage 3b: A responds
    m3, err = stage3_build_response(m2, agent_a)
    assert m3 is not None, f"Response build should succeed. Error: {err}"
    assert "response_r" in m3
    assert m3["agent_id"] == "agentA"

    # Stage 3b: B verifies response
    ok, reason = stage3_verify_response(m3, m2, agent_a.certificate_pem)
    assert ok, f"Valid response should be accepted. Reason: {reason}"


# ---------------------------------------------------------------------------
# T3.2 — MITM detection: tampered challenge signature
# ---------------------------------------------------------------------------
def test_T3_2_mitm_tampered_challenge_signature_rejected(two_agents):
    agent_a, agent_b = two_agents

    m2 = stage3_build_challenge(agent_b)
    # Tamper with B's signature (MITM attack)
    orig_sig = m2["signature"]
    tampered_sig = orig_sig[:-4] + "dead"
    m2["signature"] = tampered_sig

    m3, err = stage3_build_response(m2, agent_a)
    assert m3 is None, "Tampered B signature should cause A to abort"
    assert "mitm" in err.lower() or "invalid" in err.lower() or \
           "signature" in err.lower(), f"Error should mention MITM/signature. Got: {err}"


# ---------------------------------------------------------------------------
# T3.3 — Wrong response signature (wrong agent responds)
# ---------------------------------------------------------------------------
def test_T3_3_wrong_response_signature_rejected(two_agents):
    agent_a, agent_b = two_agents
    # Register a third rogue agent
    agent_rogue = stage1_register("agent_rogue", "worker", ["ml_inference"])

    m2 = stage3_build_challenge(agent_b)
    # Rogue agent tries to respond using its OWN private key
    m3_rogue, _ = stage3_build_response(m2, agent_rogue)
    assert m3_rogue is not None

    # B verifies against agent_A's certificate — must fail
    ok, reason = stage3_verify_response(m3_rogue, m2, agent_a.certificate_pem)
    assert not ok, "Response from wrong agent must be rejected"
    assert "invalid" in reason.lower() or "signature" in reason.lower(), \
        f"Reason: {reason}"


# ---------------------------------------------------------------------------
# T3.4 — Proof-of-possession: only sk_A can produce valid response
# ---------------------------------------------------------------------------
def test_T3_4_proof_of_possession_enforced(two_agents):
    agent_a, agent_b = two_agents

    m2 = stage3_build_challenge(agent_b)
    m3, _ = stage3_build_response(m2, agent_a)

    # Correct PoP: should verify against agent_a's cert
    ok, _ = stage3_verify_response(m3, m2, agent_a.certificate_pem)
    assert ok, "Valid PoP should succeed"

    # Wrong cert: agent_b's cert should reject agent_a's signature
    ok_wrong, reason_wrong = stage3_verify_response(m3, m2, agent_b.certificate_pem)
    assert not ok_wrong, "PoP should fail when verified against wrong agent's cert"


# ---------------------------------------------------------------------------
# T3.5 — Agent B certificate must be valid in Stage 3
# ---------------------------------------------------------------------------
def test_T3_5_invalid_agent_b_certificate_rejected(two_agents):
    agent_a, agent_b = two_agents

    m2 = stage3_build_challenge(agent_b)
    # Replace B's certificate with completely garbage PEM (unparseable)
    m2["certificate_pem"] = (
        "-----BEGIN CERTIFICATE-----\n"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\n"
        "-----END CERTIFICATE-----\n"
    )

    m3, err = stage3_build_response(m2, agent_a)
    assert m3 is None, "Completely invalid B certificate should cause A to reject challenge"
    assert err != "", f"Error message should be non-empty, got: {err!r}"


# ---------------------------------------------------------------------------
# T3.6 — Full sequential Stage 2 → Stage 3 flow
# ---------------------------------------------------------------------------
def test_T3_6_full_stage2_to_stage3_flow(two_agents):
    agent_a, agent_b = two_agents

    # Stage 2
    m1 = stage2_build_auth_request(agent_a, "ml_inference")
    ok2, reason2 = stage2_verify_auth_request(m1)
    assert ok2, f"Stage 2 must succeed: {reason2}"

    # Stage 3a
    m2 = stage3_build_challenge(agent_b)

    # Stage 3b
    m3, err3 = stage3_build_response(m2, agent_a)
    assert m3 is not None, f"Stage 3b response build must succeed: {err3}"

    ok3, reason3 = stage3_verify_response(m3, m2, agent_a.certificate_pem)
    assert ok3, f"Stage 3 full flow must succeed: {reason3}"
