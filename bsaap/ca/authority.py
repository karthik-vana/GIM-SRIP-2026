"""
bsaap.ca.authority
==================
Authentication Authority (CA) for BSAAP.

Responsibilities:
  - Generate and hold the CA root key pair (ECDSA P-256)
  - Issue X.509 v3 certificates with custom BSAAP OID extensions:
      1.3.6.1.4.1.99999.1.1  capabilityScope  (JSON array)
      1.3.6.1.4.1.99999.1.2  agentRole        (string)
      1.3.6.1.4.1.99999.1.3  agentDID         (string)
      1.3.6.1.4.1.99999.1.4  trustLevel       (string)
  - Validate certificate chains
  - Expose verify_certificate() for use in Stage 2 verification
"""

from __future__ import annotations

import datetime
import json
from typing import List

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.x509.oid import NameOID
from cryptography.x509 import (
    CertificateBuilder,
    NameAttribute,
    random_serial_number,
    load_pem_x509_certificate,
)

from bsaap.crypto.ecdsa_utils import derive_did


# ---------------------------------------------------------------------------
# Custom OID extensions for BSAAP agent certificates
# ---------------------------------------------------------------------------

OID_CAPABILITY_SCOPE = x509.ObjectIdentifier("1.3.6.1.4.1.99999.1.1")
OID_AGENT_ROLE       = x509.ObjectIdentifier("1.3.6.1.4.1.99999.1.2")
OID_AGENT_DID        = x509.ObjectIdentifier("1.3.6.1.4.1.99999.1.3")
OID_TRUST_LEVEL      = x509.ObjectIdentifier("1.3.6.1.4.1.99999.1.4")


# ---------------------------------------------------------------------------
# Certificate helpers
# ---------------------------------------------------------------------------

def _encode_utf8_ext(oid: x509.ObjectIdentifier, value: str) -> x509.UnrecognizedExtension:
    """Encode a string value as an ASN.1 UTF8String in an X.509 extension."""
    # DER encoding: tag 0x0C (UTF8String) + length + value
    val_bytes = value.encode("utf-8")
    length = len(val_bytes)
    if length < 128:
        der = bytes([0x0C, length]) + val_bytes
    else:
        # Multi-byte length (for long capability lists)
        length_bytes = length.to_bytes((length.bit_length() + 7) // 8, "big")
        der = bytes([0x0C, 0x80 | len(length_bytes)]) + length_bytes + val_bytes
    return x509.UnrecognizedExtension(oid=oid, value=der)


# ---------------------------------------------------------------------------
# Authentication Authority
# ---------------------------------------------------------------------------

class AuthenticationAuthority:
    """Singleton CA that issues and verifies BSAAP agent certificates."""

    def __init__(self) -> None:
        # Generate CA root key pair
        self._ca_private_key: EllipticCurvePrivateKey = ec.generate_private_key(
            ec.SECP256R1()
        )
        self._ca_public_key: EllipticCurvePublicKey = (
            self._ca_private_key.public_key()
        )
        # Self-sign a CA certificate
        self._ca_cert: x509.Certificate = self._build_ca_cert()
        # Validity period for issued agent certificates (days)
        self._cert_validity_days: int = 365

    # ------------------------------------------------------------------
    # CA certificate
    # ------------------------------------------------------------------

    def _build_ca_cert(self) -> x509.Certificate:
        subject = issuer = x509.Name([
            NameAttribute(NameOID.COMMON_NAME, "BSAAP-CA"),
            NameAttribute(NameOID.ORGANIZATION_NAME, "BSAAP Trust Authority"),
            NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        ])
        now = datetime.datetime.now(datetime.timezone.utc)
        return (
            CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self._ca_public_key)
            .serial_number(random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                           critical=True)
            .sign(self._ca_private_key, hashes.SHA256())
        )

    # ------------------------------------------------------------------
    # Issue agent certificate
    # ------------------------------------------------------------------

    def issue_certificate(
        self,
        agent_id: str,
        agent_public_key: EllipticCurvePublicKey,
        capabilities: List[str],
        role: str = "worker",
        trust_level: str = "standard",
        validity_days: int = 365,
    ) -> x509.Certificate:
        """Issue an X.509 v3 certificate for an AI agent.

        Parameters
        ----------
        agent_id       : unique agent identifier (becomes the CN)
        agent_public_key : ECDSA P-256 public key
        capabilities   : list of allowed task capability strings
        role           : agent role string
        trust_level    : trust classification string
        validity_days  : certificate validity in days
        """
        did = derive_did(agent_public_key)
        caps_json = json.dumps(capabilities, separators=(",", ":"))
        now = datetime.datetime.now(datetime.timezone.utc)

        builder = (
            CertificateBuilder()
            .subject_name(x509.Name([
                NameAttribute(NameOID.COMMON_NAME, agent_id),
                NameAttribute(NameOID.ORGANIZATION_NAME, "BSAAP"),
                NameAttribute(NameOID.USER_ID, did),
            ]))
            .issuer_name(self._ca_cert.subject)
            .public_key(agent_public_key)
            .serial_number(random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=validity_days))
            # Standard extensions
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=True,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            # Custom BSAAP OID extensions
            .add_extension(
                _encode_utf8_ext(OID_CAPABILITY_SCOPE, caps_json), critical=False
            )
            .add_extension(
                _encode_utf8_ext(OID_AGENT_ROLE, role), critical=False
            )
            .add_extension(
                _encode_utf8_ext(OID_AGENT_DID, did), critical=False
            )
            .add_extension(
                _encode_utf8_ext(OID_TRUST_LEVEL, trust_level), critical=False
            )
        )
        return builder.sign(self._ca_private_key, hashes.SHA256())

    def issue_certificate_pem(
        self,
        agent_id: str,
        agent_public_key: EllipticCurvePublicKey,
        capabilities: List[str],
        role: str = "worker",
        trust_level: str = "standard",
        validity_days: int = 365,
    ) -> str:
        """Issue certificate and return as PEM string."""
        cert = self.issue_certificate(
            agent_id, agent_public_key, capabilities, role, trust_level, validity_days
        )
        return cert.public_bytes(serialization.Encoding.PEM).decode()

    # ------------------------------------------------------------------
    # Certificate verification
    # ------------------------------------------------------------------

    def verify_certificate(self, cert_pem: str) -> bool:
        """Verify that a certificate was signed by this CA.

        Checks:
          (1) Signature under CA public key
          (2) Not yet expired
          (3) Not yet valid (notBefore)
        """
        try:
            cert = load_pem_x509_certificate(cert_pem.encode())
            now = datetime.datetime.now(datetime.timezone.utc)

            # Time validity
            if now < cert.not_valid_before_utc:
                return False
            if now > cert.not_valid_after_utc:
                return False

            # Signature verification under CA public key
            self._ca_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(cert.signature_hash_algorithm),
            )
            return True
        except Exception:
            return False

    def get_cn_from_cert(self, cert_pem: str) -> str:
        """Extract the Common Name (agent_id) from a certificate."""
        cert = load_pem_x509_certificate(cert_pem.encode())
        attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if not attrs:
            raise ValueError("No CN in certificate")
        return attrs[0].value

    def get_public_key_from_cert(self, cert_pem: str) -> EllipticCurvePublicKey:
        """Extract the public key from a certificate."""
        cert = load_pem_x509_certificate(cert_pem.encode())
        return cert.public_key()

    def get_capabilities_from_cert(self, cert_pem: str) -> List[str]:
        """Extract capability scope from the custom OID extension."""
        try:
            cert = load_pem_x509_certificate(cert_pem.encode())
            ext = cert.extensions.get_extension_for_oid(OID_CAPABILITY_SCOPE)
            raw = ext.value.value  # DER bytes
            # Strip ASN.1 UTF8String tag and length
            if raw[0] == 0x0C:
                if raw[1] < 128:
                    text = raw[2:].decode("utf-8")
                else:
                    n_len_bytes = raw[1] & 0x7F
                    text = raw[2 + n_len_bytes:].decode("utf-8")
                return json.loads(text)
        except Exception:
            pass
        return []

    def get_cert_validity(self, cert_pem: str):
        """Return (not_valid_before, not_valid_after) as UTC datetimes."""
        cert = load_pem_x509_certificate(cert_pem.encode())
        return cert.not_valid_before_utc, cert.not_valid_after_utc

    @property
    def ca_cert_pem(self) -> str:
        return self._ca_cert.public_bytes(serialization.Encoding.PEM).decode()

    @property
    def ca_public_key(self) -> EllipticCurvePublicKey:
        return self._ca_public_key


# ---------------------------------------------------------------------------
# Singleton CA instance
# ---------------------------------------------------------------------------
_ca_instance: AuthenticationAuthority | None = None


def get_ca() -> AuthenticationAuthority:
    global _ca_instance
    if _ca_instance is None:
        _ca_instance = AuthenticationAuthority()
    return _ca_instance


def reset_ca() -> None:
    global _ca_instance
    _ca_instance = None
