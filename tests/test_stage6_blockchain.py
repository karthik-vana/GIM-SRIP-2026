"""
tests/test_stage6_blockchain.py
================================
Stage 6 — Blockchain Audit Logging Tests (4 cases)

T6.1  Audit record written to Fabric on session close
T6.2  Merkle chain is valid after multiple session closures
T6.3  Tampered audit record invalidates chain
T6.4  Revocation via Fabric immediately blocks re-authentication
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
    stage6_close_session,
    stage6_get_audit_trail,
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


def _run_full_session(agent_id_a="audit_a", agent_id_b="audit_b", cap="audit_task"):
    """Run full Stage 1-4 and return (agent_b, session)."""
    agent_a = stage1_register(agent_id_a, "orchestrator", [cap])
    agent_b = stage1_register(agent_id_b, "worker", [cap])

    m1 = stage2_build_auth_request(agent_a, cap)
    ok, r = stage2_verify_auth_request(m1)
    assert ok, r

    m2 = stage3_build_challenge(agent_b)
    m3, e = stage3_build_response(m2, agent_a)
    assert m3 is not None, e
    ok3, r3 = stage3_verify_response(m3, m2, agent_a.certificate_pem)
    assert ok3, r3

    sess_a, sess_b = stage4_establish_session(agent_a, agent_b, m1, m2, cap)
    return agent_b, sess_b


# ---------------------------------------------------------------------------
# T6.1 — Audit record written to Fabric on session close
# ---------------------------------------------------------------------------
def test_T6_1_audit_record_written_on_close():
    agent_b, session = _run_full_session("a61", "b61", "task_alpha")

    record = stage6_close_session(agent_b, session)

    # Verify record fields
    assert record["session_id"] == session.session_id
    assert record["agent_a_id"] == "a61"
    assert record["agent_b_id"] == "b61"
    assert record["capability"] == "task_alpha"
    assert record["end_time"] > record["start_time"]
    assert "fabric_tx_id" in record
    assert record["fabric_tx_id"].startswith("tx_")

    # Session marked closed on ledger
    ledger = get_ledger()
    ledger_sess = ledger.get_session(session.session_id)
    assert ledger_sess["status"] == "closed"

    # Audit trail contains exactly one record
    records, chain_valid = stage6_get_audit_trail()
    assert len(records) == 1
    assert chain_valid, "Merkle chain should be valid after one record"


# ---------------------------------------------------------------------------
# T6.2 — Merkle chain valid after multiple session closures
# ---------------------------------------------------------------------------
def test_T6_2_merkle_chain_valid_multiple_sessions():
    NUM_SESSIONS = 4
    for i in range(NUM_SESSIONS):
        agent_b, session = _run_full_session(
            f"ma_{i}", f"mb_{i}", f"cap_{i}"
        )
        stage6_close_session(agent_b, session)

    records, chain_valid = stage6_get_audit_trail()
    assert len(records) == NUM_SESSIONS, \
        f"Expected {NUM_SESSIONS} audit records, got {len(records)}"
    assert chain_valid, "Merkle chain should be valid after multiple sessions"

    # Verify Merkle linkage manually
    prev_hash = "0" * 64
    for r in records:
        assert r["prev_hash"] == prev_hash, "Merkle prev_hash chain broken"
        prev_hash = r["record_hash"]
        assert len(r["record_hash"]) == 64, "Record hash must be 64-char hex"


# ---------------------------------------------------------------------------
# T6.3 — Tampered audit record invalidates Merkle chain
# ---------------------------------------------------------------------------
def test_T6_3_tampered_record_invalidates_chain():
    agent_b, session = _run_full_session("ta", "tb", "tamper_test")
    stage6_close_session(agent_b, session)

    ledger = get_ledger()

    # Directly tamper with audit log (simulates insider attack)
    with ledger._lock:
        if ledger._audit_log:
            ledger._audit_log[0]["capability"] = "TAMPERED_CAPABILITY"

    # Chain verification must now fail
    chain_valid = ledger.verify_audit_chain()
    assert not chain_valid, \
        "Tampered audit record should invalidate Merkle chain"


# ---------------------------------------------------------------------------
# T6.4 — Revocation immediately blocks re-authentication
# ---------------------------------------------------------------------------
def test_T6_4_revocation_blocks_reauthentication():
    agent_a = stage1_register("rev_a", "orchestrator", ["secure_task"])
    agent_b = stage1_register("rev_b", "worker", ["secure_task"])

    # First authentication should succeed
    m1 = stage2_build_auth_request(agent_a, "secure_task")
    ok, reason = stage2_verify_auth_request(m1)
    assert ok, f"Initial auth should succeed: {reason}"

    # Revoke agent_a on Fabric ledger
    ledger = get_ledger()
    ledger.revoke_agent(agent_a.did)
    assert ledger.is_revoked(agent_a.did), "Agent should now be revoked"

    # Re-authentication attempt must be blocked
    m1_new = stage2_build_auth_request(agent_a, "secure_task")
    ok_after, reason_after = stage2_verify_auth_request(m1_new)
    assert not ok_after, "Revoked agent must be blocked on re-authentication"
    assert "revoked" in reason_after.lower(), \
        f"Rejection reason should mention revocation. Got: {reason_after}"
