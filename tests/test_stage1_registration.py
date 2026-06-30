"""
tests/test_stage1_registration.py
==================================
Stage 1 — Agent Registration Tests (5 cases)

T1.1  Successful registration returns valid AgentState
T1.2  DID format is correct (did:bsaap:<hex16>)
T1.3  Certificate is valid and signed by CA
T1.4  Custom OID capability extension is present and correct
T1.5  Fabric ledger anchors the agent DID on-chain
"""

import pytest
from bsaap.blockchain.fabric_stub import get_ledger, reset_ledger
from bsaap.ca.authority import get_ca, reset_ca
from bsaap.protocol.bsaap_protocol import clear_nonce_cache, stage1_register


@pytest.fixture(autouse=True)
def reset_state():
    """Fresh CA and ledger for every test."""
    reset_ca()
    reset_ledger()
    clear_nonce_cache()
    yield
    reset_ca()
    reset_ledger()


# ---------------------------------------------------------------------------
# T1.1 — Successful registration returns complete AgentState
# ---------------------------------------------------------------------------
def test_T1_1_registration_returns_valid_state():
    state = stage1_register(
        agent_id="agent_alpha",
        role="orchestrator",
        capabilities=["data_analysis", "report_generation"],
    )

    assert state.agent_id == "agent_alpha"
    assert state.role == "orchestrator"
    assert state.capabilities == ["data_analysis", "report_generation"]
    assert state.private_key_pem != b""
    assert state.public_key_pem != b""
    assert state.certificate_pem != ""
    assert state.did != ""
    assert state.fabric_tx_id != ""


# ---------------------------------------------------------------------------
# T1.2 — DID format: did:bsaap:<16 hex characters>
# ---------------------------------------------------------------------------
def test_T1_2_did_format_correct():
    state = stage1_register(
        agent_id="agent_beta",
        role="worker",
        capabilities=["sentiment_analysis"],
    )

    did = state.did
    assert did.startswith("did:bsaap:"), f"DID does not start with 'did:bsaap:': {did}"
    hex_part = did[len("did:bsaap:"):]
    assert len(hex_part) == 16, f"DID hex part length should be 16, got {len(hex_part)}"
    assert all(c in "0123456789abcdef" for c in hex_part), \
        f"DID hex part contains non-hex characters: {hex_part}"


# ---------------------------------------------------------------------------
# T1.3 — Issued certificate is valid and CA-signed
# ---------------------------------------------------------------------------
def test_T1_3_certificate_is_ca_signed_and_valid():
    state = stage1_register(
        agent_id="agent_gamma",
        role="analyst",
        capabilities=["forecasting"],
    )

    ca = get_ca()
    assert ca.verify_certificate(state.certificate_pem), \
        "Certificate should be valid and CA-signed"

    # CN must match agent_id
    cn = ca.get_cn_from_cert(state.certificate_pem)
    assert cn == "agent_gamma", f"CN mismatch: expected 'agent_gamma', got '{cn}'"


# ---------------------------------------------------------------------------
# T1.4 — Capability OID extension is present and correctly encoded
# ---------------------------------------------------------------------------
def test_T1_4_capability_oid_extension_correct():
    caps = ["nlp_inference", "data_viz", "sql_query"]
    state = stage1_register(
        agent_id="agent_delta",
        role="worker",
        capabilities=caps,
    )

    ca = get_ca()
    extracted_caps = ca.get_capabilities_from_cert(state.certificate_pem)
    assert set(extracted_caps) == set(caps), \
        f"Capability OID mismatch: expected {caps}, got {extracted_caps}"


# ---------------------------------------------------------------------------
# T1.5 — DID is anchored on Fabric ledger
# ---------------------------------------------------------------------------
def test_T1_5_did_anchored_on_fabric_ledger():
    state = stage1_register(
        agent_id="agent_epsilon",
        role="worker",
        capabilities=["translation"],
    )

    ledger = get_ledger()

    # Agent DID must be present in ledger
    assert ledger.agent_exists(state.did), \
        f"DID {state.did} should be anchored on Fabric ledger"

    # Agent must NOT be revoked
    assert not ledger.is_revoked(state.did), \
        "Newly registered agent should not be revoked"

    # Fabric tx_id format validation
    assert state.fabric_tx_id.startswith("tx_"), \
        f"Fabric tx_id should start with 'tx_', got: {state.fabric_tx_id}"

    # Ledger stats reflect the registration
    stats = ledger.ledger_stats()
    assert stats["agents"] >= 1
    assert stats["block_number"] >= 1
