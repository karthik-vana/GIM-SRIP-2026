"""
bsaap.blockchain.fabric_stub
============================
In-memory simulation of Hyperledger Fabric chaincode functions for BSAAP.

Simulated chaincode functions:
  - RegisterAgent(did, pk_pem, capabilities) → tx_id
  - RevokeAgent(did)                          → tx_id
  - IsRevoked(did)                            → bool
  - CreateSession(sid, id_a, id_b, cap, exp)  → tx_id
  - CloseSession(sid)                         → tx_id
  - WriteAuditRecord(record_dict, hash)       → tx_id
  - GetAuditTrail()                           → list[AuditRecord]

In production: replace with Hyperledger Fabric Python SDK calls
via the `hfc` (hyperledger-fabric-client) library connecting to
a live bsaap-channel with endorsement peers.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
import uuid
from typing import Any, Dict, List, Optional


class FabricLedgerStub:
    """Thread-safe in-memory simulation of Hyperledger Fabric ledger state."""

    def __init__(self) -> None:
        self._lock = threading.Lock()

        # World state (mimics CouchDB state DB)
        self._agents: Dict[str, Dict[str, Any]] = {}       # did → agent record
        self._revoked: set[str] = set()                     # revoked DIDs
        self._sessions: Dict[str, Dict[str, Any]] = {}      # sid → session record
        self._audit_log: List[Dict[str, Any]] = []          # ordered audit records
        self._block_number: int = 0

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _commit_tx(self) -> str:
        """Simulate Fabric transaction commit. Returns a fake txID."""
        with self._lock:
            self._block_number += 1
            tx_id = f"tx_{self._block_number:06d}_{uuid.uuid4().hex[:8]}"
        return tx_id

    def _sha256(self, data: str) -> str:
        return hashlib.sha256(data.encode()).hexdigest()

    # ------------------------------------------------------------------
    # Chaincode: Agent Identity
    # ------------------------------------------------------------------

    def register_agent(
        self,
        did: str,
        public_key_pem: str,
        capabilities: List[str],
        agent_id: str,
        role: str,
    ) -> str:
        """RegisterAgent chaincode function.

        Anchors agent DID, public key, and capability list on ledger.
        Idempotent: re-registration updates the record.
        """
        with self._lock:
            self._agents[did] = {
                "did": did,
                "agent_id": agent_id,
                "role": role,
                "public_key_pem": public_key_pem,
                "capabilities": capabilities,
                "registered_at": time.time(),
                "status": "active",
            }
        return self._commit_tx()

    def revoke_agent(self, did: str) -> str:
        """RevokeAgent chaincode function.

        Marks agent DID as revoked. Immediate effect — no CRL polling.
        """
        with self._lock:
            self._revoked.add(did)
            if did in self._agents:
                self._agents[did]["status"] = "revoked"
        return self._commit_tx()

    def is_revoked(self, did: str) -> bool:
        """IsRevoked chaincode query. O(1) lookup."""
        with self._lock:
            return did in self._revoked

    def agent_exists(self, did: str) -> bool:
        """Check whether a DID is registered."""
        with self._lock:
            return did in self._agents

    def get_agent(self, did: str) -> Optional[Dict[str, Any]]:
        """Retrieve agent record by DID."""
        with self._lock:
            return self._agents.get(did)

    # ------------------------------------------------------------------
    # Chaincode: Session Management
    # ------------------------------------------------------------------

    def create_session(
        self,
        session_id: str,
        agent_a_id: str,
        agent_b_id: str,
        capability: str,
        expires_at: float,
    ) -> str:
        """CreateSession chaincode function."""
        with self._lock:
            self._sessions[session_id] = {
                "session_id": session_id,
                "agent_a_id": agent_a_id,
                "agent_b_id": agent_b_id,
                "capability": capability,
                "created_at": time.time(),
                "expires_at": expires_at,
                "status": "active",
            }
        return self._commit_tx()

    def close_session(self, session_id: str) -> str:
        """CloseSession chaincode function."""
        with self._lock:
            if session_id in self._sessions:
                self._sessions[session_id]["status"] = "closed"
                self._sessions[session_id]["closed_at"] = time.time()
        return self._commit_tx()

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._sessions.get(session_id)

    # ------------------------------------------------------------------
    # Chaincode: Merkle-Chained Audit Log
    # ------------------------------------------------------------------

    def write_audit_record(self, record: Dict[str, Any]) -> str:
        """WriteAuditRecord chaincode function.

        Appends a Merkle-linked record to the immutable audit log.
        h_i = SHA256(JSON_canonical(R_i))
        h_0 = "0" * 64 (genesis hash)
        """
        with self._lock:
            prev_hash = (
                self._audit_log[-1]["record_hash"]
                if self._audit_log
                else "0" * 64
            )
            record["prev_hash"] = prev_hash
            # Snapshot the record NOW before any post-return mutations
            snapshot = {k: v for k, v in record.items()}
            canonical = json.dumps(snapshot, sort_keys=True, separators=(",", ":"))
            record_hash = hashlib.sha256(canonical.encode()).hexdigest()
            snapshot["record_hash"] = record_hash
            record["record_hash"] = record_hash   # also update caller's dict
            self._audit_log.append(snapshot)      # store immutable snapshot
        tx_id = self._commit_tx()
        return tx_id

    def get_audit_trail(self) -> List[Dict[str, Any]]:
        """Return full audit trail (ordered)."""
        with self._lock:
            return list(self._audit_log)

    def verify_audit_chain(self) -> bool:
        """Verify Merkle chain integrity.

        Recomputes every h_i and checks linkage.
        Returns True if chain is intact, False if tampered.
        """
        with self._lock:
            log = list(self._audit_log)

        # Fields NOT in the canonical hash (added post-write)
        _EXCLUDE = {"record_hash", "fabric_tx_id"}

        prev_hash = "0" * 64
        for record in log:
            r_copy = {k: v for k, v in record.items() if k not in _EXCLUDE}
            if r_copy.get("prev_hash") != prev_hash:
                return False
            canonical = json.dumps(r_copy, sort_keys=True, separators=(",", ":"))
            expected_hash = hashlib.sha256(canonical.encode()).hexdigest()
            if record.get("record_hash") != expected_hash:
                return False
            prev_hash = record["record_hash"]
        return True

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def ledger_stats(self) -> Dict[str, int]:
        with self._lock:
            return {
                "agents": len(self._agents),
                "revoked": len(self._revoked),
                "sessions": len(self._sessions),
                "audit_records": len(self._audit_log),
                "block_number": self._block_number,
            }

    def reset(self) -> None:
        """Reset ledger state (for testing only)."""
        with self._lock:
            self._agents.clear()
            self._revoked.clear()
            self._sessions.clear()
            self._audit_log.clear()
            self._block_number = 0


# ---------------------------------------------------------------------------
# Singleton ledger instance (shared across all protocol stages)
# ---------------------------------------------------------------------------
_ledger_instance: Optional[FabricLedgerStub] = None


def get_ledger() -> FabricLedgerStub:
    """Return the singleton Fabric ledger stub."""
    global _ledger_instance
    if _ledger_instance is None:
        _ledger_instance = FabricLedgerStub()
    return _ledger_instance


def reset_ledger() -> None:
    """Reset ledger (testing only)."""
    global _ledger_instance
    if _ledger_instance is not None:
        _ledger_instance.reset()
