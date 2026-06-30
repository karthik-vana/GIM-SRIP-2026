"""
bsaap.crypto.ecdsa_utils
========================
ECDSA P-256 (SECP256R1) key generation, signing, and verification.
Uses the `cryptography` hazmat layer (v42+).
All signing uses SHA-256 as the digest algorithm.
"""

from __future__ import annotations

import hashlib
from typing import Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
    ECDH,
)
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.exceptions import InvalidSignature


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------

def generate_keypair() -> Tuple[EllipticCurvePrivateKey, EllipticCurvePublicKey]:
    """Generate an ECDSA P-256 key pair.

    Returns
    -------
    (private_key, public_key)
    """
    private_key: EllipticCurvePrivateKey = ec.generate_private_key(ec.SECP256R1())
    return private_key, private_key.public_key()


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------

def private_key_to_pem(private_key: EllipticCurvePrivateKey) -> bytes:
    """Serialise private key to unencrypted PEM bytes."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def public_key_to_pem(public_key: EllipticCurvePublicKey) -> bytes:
    """Serialise public key to PEM bytes."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def pem_to_private_key(pem: bytes) -> EllipticCurvePrivateKey:
    return serialization.load_pem_private_key(pem, password=None)


def pem_to_public_key(pem: bytes) -> EllipticCurvePublicKey:
    return serialization.load_pem_public_key(pem)


# ---------------------------------------------------------------------------
# Sign / Verify
# ---------------------------------------------------------------------------

def sign_ecdsa(private_key: EllipticCurvePrivateKey, message: bytes) -> bytes:
    """Sign *message* with ECDSA-P256-SHA256.

    Parameters
    ----------
    private_key : ECDSA P-256 private key
    message     : raw bytes to sign (pre-hashing is performed internally)

    Returns
    -------
    DER-encoded signature bytes
    """
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    return signature


def verify_ecdsa(
    public_key: EllipticCurvePublicKey,
    message: bytes,
    signature: bytes,
) -> bool:
    """Verify an ECDSA-P256-SHA256 signature.

    Returns
    -------
    True if valid, False otherwise (never raises on bad signatures).
    """
    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


# ---------------------------------------------------------------------------
# DID derivation
# ---------------------------------------------------------------------------

def derive_did(public_key: EllipticCurvePublicKey) -> str:
    """Derive a BSAAP DID from a public key.

    did:bsaap:<first-16-hex-chars-of-SHA256(SPKI)>
    """
    spki = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashlib.sha256(spki).hexdigest()
    return f"did:bsaap:{digest[:16]}"
