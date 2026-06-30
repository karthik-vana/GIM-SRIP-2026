"""
bsaap.crypto.aes_utils
======================
AES-256-GCM authenticated encryption for BSAAP Stage 5.

Properties (NIST SP 800-38D):
  - IND-CCA2 security under standard model
  - 128-bit authentication tag authenticates both ciphertext and AAD
  - Decryption returns None on tag mismatch (never raises to callers)
  - Monotonically increasing seqNum embedded in AAD prevents replay/reorder
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
from typing import Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

IV_LENGTH = 12      # 96-bit IV (NIST recommended for GCM)
TAG_LENGTH = 16     # 128-bit authentication tag
KEY_LENGTH = 32     # 256-bit AES key


# ---------------------------------------------------------------------------
# Encrypt
# ---------------------------------------------------------------------------

def aes_gcm_encrypt(
    key: bytes,
    plaintext: bytes,
    aad: bytes,
    iv: Optional[bytes] = None,
) -> Tuple[bytes, bytes, bytes]:
    """Encrypt plaintext with AES-256-GCM.

    Parameters
    ----------
    key       : 32-byte AES-256 session key K_s
    plaintext : application message bytes
    aad       : associated data (sid || seqNum) — authenticated but not encrypted
    iv        : 12-byte IV; generated randomly if None

    Returns
    -------
    (iv, ciphertext, tag)
      iv         : 12-byte nonce
      ciphertext : encrypted bytes (same length as plaintext)
      tag        : 16-byte GCM authentication tag
    """
    if len(key) != KEY_LENGTH:
        raise ValueError(f"AES key must be {KEY_LENGTH} bytes, got {len(key)}")

    if iv is None:
        iv = os.urandom(IV_LENGTH)
    if len(iv) != IV_LENGTH:
        raise ValueError(f"IV must be {IV_LENGTH} bytes")

    aesgcm = AESGCM(key)
    # cryptography library appends tag to ciphertext
    ct_with_tag = aesgcm.encrypt(iv, plaintext, aad)
    ciphertext = ct_with_tag[:-TAG_LENGTH]
    tag = ct_with_tag[-TAG_LENGTH:]
    return iv, ciphertext, tag


# ---------------------------------------------------------------------------
# Decrypt
# ---------------------------------------------------------------------------

def aes_gcm_decrypt(
    key: bytes,
    iv: bytes,
    ciphertext: bytes,
    tag: bytes,
    aad: bytes,
) -> Optional[bytes]:
    """Decrypt and verify AES-256-GCM ciphertext.

    Returns
    -------
    Decrypted plaintext bytes, or None if authentication fails.
    Never raises InvalidTag to callers — returns None instead.
    """
    if len(key) != KEY_LENGTH:
        raise ValueError(f"AES key must be {KEY_LENGTH} bytes")

    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(iv, ciphertext + tag, aad)
        return plaintext
    except Exception:
        return None


# ---------------------------------------------------------------------------
# HMAC-SHA-256 sequence integrity layer (Stage 5 outer MAC)
# ---------------------------------------------------------------------------

def compute_sequence_mac(
    key: bytes,
    sid: str,
    seq_num: int,
    iv: bytes,
    ciphertext: bytes,
) -> bytes:
    """Compute HMAC-SHA-256 over (sid || seqNum || IV || C).

    This outer MAC binds the GCM ciphertext to the session and sequence
    number, preventing message reordering between sessions.

    Returns
    -------
    32-byte HMAC-SHA-256 digest
    """
    seq_bytes = struct.pack(">Q", seq_num)   # big-endian 8-byte sequence number
    data = sid.encode() + seq_bytes + iv + ciphertext
    return hmac.new(key, data, hashlib.sha256).digest()


def verify_sequence_mac(
    key: bytes,
    sid: str,
    seq_num: int,
    iv: bytes,
    ciphertext: bytes,
    received_mac: bytes,
) -> bool:
    """Constant-time verification of the sequence integrity MAC.

    Returns True if MAC is valid, False otherwise.
    """
    expected = compute_sequence_mac(key, sid, seq_num, iv, ciphertext)
    return hmac.compare_digest(expected, received_mac)


# ---------------------------------------------------------------------------
# AAD builder
# ---------------------------------------------------------------------------

def build_aad(sid: str, seq_num: int) -> bytes:
    """Build Additional Authenticated Data for AES-GCM.

    AAD = sid_bytes || seq_num_bytes (big-endian uint64)
    """
    return sid.encode("utf-8") + struct.pack(">Q", seq_num)
