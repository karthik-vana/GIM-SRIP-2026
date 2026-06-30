"""
bsaap.crypto.ecdh_utils
=======================
X25519 ephemeral Diffie-Hellman key exchange for BSAAP Stage 4.

Protocol property: forward secrecy.
  - Each session generates a fresh ephemeral keypair.
  - Private keys are erased immediately after shared-secret computation.
  - Knowledge of long-term (sk_A, sk_B) after session close does NOT
    reveal K_s (under the DDH assumption on Curve25519).
"""

from __future__ import annotations

from typing import Tuple

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives import serialization


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------

def generate_x25519_keypair() -> Tuple[X25519PrivateKey, X25519PublicKey]:
    """Generate a fresh ephemeral X25519 key pair.

    Returns
    -------
    (ephemeral_private_key, ephemeral_public_key)
    The private key MUST be erased after shared-secret computation.
    """
    private_key: X25519PrivateKey = X25519PrivateKey.generate()
    return private_key, private_key.public_key()


# ---------------------------------------------------------------------------
# Shared secret computation
# ---------------------------------------------------------------------------

def compute_shared_secret(
    own_private_key: X25519PrivateKey,
    peer_public_key: X25519PublicKey,
) -> bytes:
    """Compute X25519 shared secret.

    SS = X25519(own_private, peer_public)
       = X25519(peer_private, own_public)   [Diffie-Hellman symmetry]

    Parameters
    ----------
    own_private_key  : this agent's ephemeral private key
    peer_public_key  : peer agent's ephemeral public key

    Returns
    -------
    32-byte shared secret (raw bytes, NOT a key — feed into HKDF).
    """
    shared_secret: bytes = own_private_key.exchange(peer_public_key)
    return shared_secret


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------

def public_key_to_raw(public_key: X25519PublicKey) -> bytes:
    """Serialise X25519 public key to 32 raw bytes."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def raw_to_public_key(raw_bytes: bytes) -> X25519PublicKey:
    """Deserialise 32 raw bytes to an X25519PublicKey."""
    return X25519PublicKey.from_public_bytes(raw_bytes)


def erase_private_key(private_key: X25519PrivateKey) -> None:
    """Signal intent to erase ephemeral private key material.

    CPython does not expose direct memory zeroing for managed objects;
    this function documents the erasure point for audit purposes.
    In production, use HSM or Rust-backed libraries for guaranteed erasure.
    """
    del private_key
