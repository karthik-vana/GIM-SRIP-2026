"""
bsaap.crypto.hkdf_utils
=======================
HKDF-SHA-256 key derivation for BSAAP Stage 4 (session key) and
any other key material needs (e.g., AAD binding keys).

Follows RFC 5869:
  PRK  = HMAC-SHA256(salt, IKM)
  K    = HMAC-SHA256(PRK,  info || 0x01)
"""

from __future__ import annotations

import hashlib
import hmac


# ---------------------------------------------------------------------------
# HKDF implementation using standard library (no hazmat dependency here)
# ---------------------------------------------------------------------------

_HASH_LEN = 32  # SHA-256 output length in bytes


def _hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract step (RFC 5869 §2.2).

    PRK = HMAC-SHA256(salt, IKM)

    Parameters
    ----------
    salt : non-secret random value (nonces n1 || n2 in BSAAP)
    ikm  : input key material (X25519 shared secret in BSAAP)
    """
    if not salt:
        salt = b"\x00" * _HASH_LEN
    return _hmac_sha256(salt, ikm)


def hkdf_expand(prk: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF-Expand step (RFC 5869 §2.3).

    OKM = T(1) || T(2) || ... where T(i) = HMAC-SHA256(PRK, T(i-1) || info || i)

    Parameters
    ----------
    prk    : pseudorandom key from hkdf_extract
    info   : context string (e.g. b"BSAAP-v1-session")
    length : desired output key length in bytes (default 32 for AES-256)
    """
    if length > 255 * _HASH_LEN:
        raise ValueError("HKDF-Expand: requested length too large")

    okm = b""
    t_prev = b""
    counter = 1
    while len(okm) < length:
        t_prev = _hmac_sha256(prk, t_prev + info + bytes([counter]))
        okm += t_prev
        counter += 1
    return okm[:length]


def hkdf_sha256(
    ikm: bytes,
    salt: bytes,
    info: bytes = b"BSAAP-v1-session",
    length: int = 32,
) -> bytes:
    """Full HKDF-SHA-256 (extract + expand).

    Parameters
    ----------
    ikm    : input key material (X25519 shared secret)
    salt   : nonce material (n1 || n2 from BSAAP Stages 2 & 3)
    info   : context string binding key to protocol & version
    length : output key length in bytes

    Returns
    -------
    ``length``-byte session key K_s
    """
    prk = hkdf_extract(salt=salt, ikm=ikm)
    return hkdf_expand(prk=prk, info=info, length=length)


def derive_session_key(
    shared_secret: bytes,
    nonce_a: bytes,
    nonce_b: bytes,
    info: bytes = b"BSAAP-v1-session",
) -> bytes:
    """Derive BSAAP session key K_s.

    K_s = HKDF-SHA256(IKM=SS, salt=n1||n2, info="BSAAP-v1-session")

    Parameters
    ----------
    shared_secret : X25519 output (32 bytes)
    nonce_a       : n1 from Stage 2 Auth Request (bytes)
    nonce_b       : n2 from Stage 3 Challenge (bytes)
    info          : protocol binding string
    """
    salt = nonce_a + nonce_b
    return hkdf_sha256(ikm=shared_secret, salt=salt, info=info, length=32)
