"""Test keys and tokens for the OpenID Connect providers (Microsoft, Yahoo).

Everything is generated in-process: an RSA key plus self-signed certificate
for our client assertion, and a separate "provider" key that signs ID tokens
and is published through a fake JWKS endpoint."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

FIXED_NOW = datetime(2026, 11, 6, 12, 0, 0, tzinfo=UTC)


def rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def self_signed_bundle(key: rsa.RSAPrivateKey) -> tuple[str, x509.Certificate]:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Secureddy test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(FIXED_NOW - timedelta(days=1))
        .not_valid_after(FIXED_NOW + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode() + cert.public_bytes(serialization.Encoding.PEM).decode()
    return pem, cert


def thumbprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA1()).hex().upper()  # noqa: S303


class Signer:
    """A provider's signing key and its JWKS."""

    def __init__(self, kid: str = "prov-1", *, alg: str = "RS256") -> None:
        self.kid = kid
        self.alg = alg
        self.key = ec.generate_private_key(ec.SECP256R1()) if alg == "ES256" else rsa_key()

    def jwk(self) -> dict[str, Any]:
        algo = jwt.algorithms.ECAlgorithm if self.alg == "ES256" else jwt.algorithms.RSAAlgorithm
        data = json.loads(algo.to_jwk(self.key.public_key()))
        return {**data, "kid": self.kid, "use": "sig", "alg": self.alg}

    def jwks(self) -> dict[str, Any]:
        return {"keys": [self.jwk()]}

    def token(self, claims: dict[str, Any], *, kid: str | None = None, alg: str | None = None) -> str:
        return jwt.encode(claims, self.key, algorithm=alg or self.alg, headers={"kid": kid or self.kid})
