"""
tests/test_stage5_secure_comm.py
==================================
Stage 5 — Secure Authenticated Communication Tests (4 cases)

T5.1  Encrypt/decrypt round trip recovers original plaintext
T5.2  GCM tag tamper detected — decryption returns None
T5.3  Sequence number mismatch (reorder/replay) rejected
T5.4  AAD binding: wrong session ID breaks GCM tag
"""

import pytest
from bsaap.blockchain.fabric_stub import reset_ledger
from bsaap.ca.authority import reset_ca
from bsaap.crypto.aes_utils import build_aad
from bsaap.protocol.bsaap_protocol import (
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
)
import time


@pytest.fixture(autouse=True)
def reset_state():
    reset_ca()
    reset_ledger()
    clear_nonce_cache()
    yield
    reset_ca()
    reset_ledger()
    clear_nonce_cache()


def _setup_session(cap="inference"):
    """Convenience: run full Stages 1-4 and return (sess_a, sess_b)."""
    agent_a = stage1_register("sa", "orchestrator", [cap])
    agent_b = stage1_register("sb", "worker", [cap])

    m1 = stage2_build_auth_request(agent_a, cap)
    ok, r = stage2_verify_auth_request(m1)
    assert ok, r

    m2 = stage3_build_challenge(agent_b)
    m3, e = stage3_build_response(m2, agent_a)
    assert m3 is not None, e
    ok3, r3 = stage3_verify_response(m3, m2, agent_a.certificate_pem)
    assert ok3, r3

    sess_a, sess_b = stage4_establish_session(agent_a, agent_b, m1, m2, cap)
    return sess_a, sess_b


# ---------------------------------------------------------------------------
# T5.1 — Encrypt/decrypt round trip recovers original plaintext
# ---------------------------------------------------------------------------
def test_T5_1_encrypt_decrypt_roundtrip():
    sess_a, sess_b = _setup_session()
    original = b"BSAAP secure payload: task_id=42, action=execute_pipeline"

    wire = stage5_encrypt_message(sess_a, original)

    # Verify wire format fields
    assert wire["session_id"] == sess_a.session_id
    assert wire["seq_num"] == 1
    assert len(wire["iv"]) == 24          # 12 bytes hex = 24 chars
    assert len(wire["gcm_tag"]) == 32     # 16 bytes hex = 32 chars
    assert wire["mac"] != ""

    plaintext, err = stage5_decrypt_message(sess_b, wire)
    assert plaintext is not None, f"Decryption should succeed. Error: {err}"
    assert plaintext == original, \
        f"Decrypted content mismatch. Got: {plaintext!r}, expected: {original!r}"


# ---------------------------------------------------------------------------
# T5.2 — GCM tag tamper detected
# ---------------------------------------------------------------------------
def test_T5_2_gcm_tag_tamper_detected():
    sess_a, sess_b = _setup_session("vision")

    wire = stage5_encrypt_message(sess_a, b"sensitive agent payload")

    # Tamper with the GCM authentication tag
    orig_tag = wire["gcm_tag"]
    tampered_tag = orig_tag[:-4] + (
        "0000" if orig_tag[-4:] != "0000" else "ffff"
    )
    wire["gcm_tag"] = tampered_tag

    plaintext, err = stage5_decrypt_message(sess_b, wire)
    assert plaintext is None, "Tampered GCM tag should cause decryption failure"
    assert err != ""


# ---------------------------------------------------------------------------
# T5.3 — Out-of-order sequence number rejected
# ---------------------------------------------------------------------------
def test_T5_3_wrong_sequence_number_rejected():
    sess_a, sess_b = _setup_session("summarise")

    wire = stage5_encrypt_message(sess_a, b"message one")
    wire["seq_num"] = 999  # Force wrong sequence number

    plaintext, err = stage5_decrypt_message(sess_b, wire)
    assert plaintext is None, "Wrong sequence number should be rejected"
    assert "sequence" in err.lower() or "mismatch" in err.lower(), \
        f"Error should mention sequence number. Got: {err}"


# ---------------------------------------------------------------------------
# T5.4 — AAD binding: wrong session ID invalidates GCM tag
# ---------------------------------------------------------------------------
def test_T5_4_wrong_session_id_breaks_gcm_tag():
    sess_a, sess_b = _setup_session("classify")

    wire = stage5_encrypt_message(sess_a, b"confidential payload")

    # Modify session_id in the wire message (breaks AAD → breaks GCM tag)
    wire["session_id"] = "ffffffffffffffffffffffffffffffff"

    plaintext, err = stage5_decrypt_message(sess_b, wire)
    # GCM tag will fail because AAD = sid||seqNum changed
    assert plaintext is None, \
        "Wrong session ID in AAD should cause GCM authentication failure"
