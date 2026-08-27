"""Client authentication at the token endpoint.

Four registrable methods, one class each. The method is part of the client's
registration in the ZOREAL dashboard: use the one your client is registered
with, not the one that is convenient.

- :class:`NoAuth` -- a public client (``token_endpoint_auth_method: none``).
  No secret, no key; PKCE is the only proof, which is why a public client can
  only ever have been granted Tier A scopes.
- :class:`ClientSecretBasic` -- confidential. The secret travels as HTTP
  Basic, never as a form field.
- :class:`PrivateKeyJwt` -- confidential (RFC 7523). The library builds and
  signs a short-lived JWT assertion from your private key; the provider
  verifies it against the public keys you registered. The private key never
  travels.
- :class:`TlsClientAuth` -- mutual TLS. Registrable, and the provider does not
  accept it at the token endpoint yet: expect an :class:`ExchangeError` with
  HTTP status 501 until it does. The certificate is wired into the TLS
  handshake here so the configuration is ready the day the provider is.
"""

import base64
import json
import secrets
import ssl
import time
from typing import Any, Dict, Optional, Union

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from .errors import ConfigurationError

PrivateKeyMaterial = Union[
    str, bytes, Dict[str, Any], ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey
]


class ClientAuth:
    """Base class: how the client authenticates at ``POST {issuer}/token``."""


class NoAuth(ClientAuth):
    """A public client. The token request carries ``client_id`` only, and the
    PKCE verifier is the whole proof."""


class ClientSecretBasic(ClientAuth):
    """A confidential client with a shared secret (``zcs_...``).

    The secret travels as the HTTP Basic password with ``client_id`` as the
    user; the form still carries ``client_id`` because the provider matches
    the code against it.
    """

    def __init__(self, client_secret: str) -> None:
        if not client_secret or not client_secret.strip():
            raise ConfigurationError("client_secret is required for client_secret_basic")
        self.client_secret = client_secret

    def authorization_header(self, client_id: str) -> str:
        raw = f"{client_id}:{self.client_secret}".encode("utf-8")
        return "Basic " + base64.b64encode(raw).decode("ascii")


class PrivateKeyJwt(ClientAuth):
    """A confidential client that signs a per-request assertion (RFC 7523).

    ``private_key`` is a PEM string or bytes, a private JWK ``dict``, or a
    ``cryptography`` private key object. A P-256 key signs ES256 (preferred:
    it is the same key shape the provider certifies) and an RSA key signs
    RS256; any other key is refused at construction. ``kid`` is set as the
    assertion's header when given, so the provider can pick the right entry
    from a multi-key JWKS.
    """

    # The provider caps the assertion's life at 60 seconds; 55 leaves headroom
    # for clock skew between this host and the provider.
    ASSERTION_TTL = 55

    def __init__(self, private_key: PrivateKeyMaterial, kid: Optional[str] = None) -> None:
        key = self._load(private_key)
        if isinstance(key, ec.EllipticCurvePrivateKey):
            if not isinstance(key.curve, ec.SECP256R1):
                raise ConfigurationError(
                    "private_key_jwt needs a P-256 (prime256v1) EC key or an RSA key"
                )
            self.algorithm = "ES256"
        elif isinstance(key, rsa.RSAPrivateKey):
            self.algorithm = "RS256"
        else:
            raise ConfigurationError(
                "private_key_jwt needs a PRIVATE key: a P-256 EC key or an RSA key"
            )
        self.key = key
        self.kid = kid

    def build_assertion(self, client_id: str, token_url: str) -> str:
        """The signed client assertion for one token request.

        ``iss`` and ``sub`` are the client_id, ``aud`` is the token endpoint,
        and ``jti`` is fresh random per assertion because the provider
        enforces single use.
        """
        now = int(time.time())
        claims = {
            "iss": client_id,
            "sub": client_id,
            "aud": token_url,
            "exp": now + self.ASSERTION_TTL,
            "iat": now,
            "jti": secrets.token_urlsafe(16),
        }
        headers = {"kid": self.kid} if self.kid else None
        return jwt.encode(claims, self.key, algorithm=self.algorithm, headers=headers)

    @staticmethod
    def _load(
        material: PrivateKeyMaterial,
    ) -> Any:
        if isinstance(material, (ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey)):
            return material
        if isinstance(material, dict):
            kty = material.get("kty")
            algorithms = {
                "EC": jwt.algorithms.ECAlgorithm,
                "RSA": jwt.algorithms.RSAAlgorithm,
            }
            if kty not in algorithms:
                raise ConfigurationError("the private key JWK has an unsupported kty")
            try:
                return algorithms[kty].from_jwk(json.dumps(material))
            except Exception as exc:
                raise ConfigurationError("the private key JWK could not be read") from exc
        if isinstance(material, str):
            material = material.encode("utf-8")
        if isinstance(material, (bytes, bytearray)):
            try:
                return serialization.load_pem_private_key(bytes(material), password=None)
            except Exception as exc:
                raise ConfigurationError(
                    "the private key could not be parsed as PEM"
                ) from exc
        raise ConfigurationError(
            "private_key must be a PEM string, a private JWK dict, "
            "or a cryptography private key object"
        )


class TlsClientAuth(ClientAuth):
    """Mutual TLS: the client certificate authenticates the connection itself.

    ``certificate_file`` is the PEM certificate (or chain) and
    ``private_key_file`` its PEM private key, loaded into the TLS context for
    every call this client makes. The token form carries ``client_id`` only.

    The provider currently answers ``501`` for this method at the token
    endpoint; the refusal surfaces as an :class:`ExchangeError` carrying that
    status and the provider's reason, verbatim.
    """

    def __init__(
        self,
        certificate_file: str,
        private_key_file: str,
        password: Optional[str] = None,
    ) -> None:
        if not certificate_file or not private_key_file:
            raise ConfigurationError(
                "tls_client_auth needs a certificate file and a private key file"
            )
        self.certificate_file = certificate_file
        self.private_key_file = private_key_file
        self.password = password

    def ssl_context(self) -> ssl.SSLContext:
        context = ssl.create_default_context()
        try:
            context.load_cert_chain(
                self.certificate_file, self.private_key_file, self.password
            )
        except (OSError, ssl.SSLError) as exc:
            raise ConfigurationError(
                "the TLS client certificate or key could not be loaded"
            ) from exc
        return context
