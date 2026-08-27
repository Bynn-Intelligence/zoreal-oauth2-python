"""Shared fixtures. Everything here is offline: keys are generated in-process
and the JWKS fetch is monkeypatched, so no test touches the network."""

import time
from typing import Any, Dict, Optional

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from zoreal_oauth2 import ZorealOAuth2Client

ISSUER = "https://id.zoreal.example"
CLIENT_ID = "ast_test_client"
KID = "test-key-1"


def make_p256_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def jwk_for(key: ec.EllipticCurvePrivateKey, kid: str) -> Dict[str, Any]:
    public = jwt.algorithms.ECAlgorithm.to_jwk(key.public_key(), as_dict=True)
    public.update({"kid": kid, "use": "sig", "alg": "ES256"})
    return public


def sign(claims: Dict[str, Any], key: ec.EllipticCurvePrivateKey, kid: str = KID) -> str:
    return jwt.encode(claims, key, algorithm="ES256", headers={"kid": kid})


def base_claims(**overrides: Any) -> Dict[str, Any]:
    now = int(time.time())
    claims: Dict[str, Any] = {
        "iss": ISSUER,
        "sub": "7QK3-9F2M-XR84-B5NP",
        "aud": CLIENT_ID,
        "exp": now + 120,
        "iat": now,
        "nonce": "n-1",
        "acr": "zoreal.device",
    }
    claims.update(overrides)
    return claims


@pytest.fixture
def provider_key() -> ec.EllipticCurvePrivateKey:
    return make_p256_key()


@pytest.fixture
def jwks(provider_key: ec.EllipticCurvePrivateKey) -> Dict[str, Any]:
    return {"keys": [jwk_for(provider_key, KID)]}


@pytest.fixture
def client(jwks: Dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> ZorealOAuth2Client:
    instance = ZorealOAuth2Client(CLIENT_ID, issuer=ISSUER)
    monkeypatch.setattr(instance, "_fetch_jwks", lambda: jwks)
    return instance


def stub_request(
    client_instance: ZorealOAuth2Client,
    monkeypatch: pytest.MonkeyPatch,
    status: int,
    body: bytes,
    captured: Optional[Dict[str, Any]] = None,
) -> None:
    """Replace the client's HTTP layer with a canned answer, optionally
    recording what would have gone on the wire."""

    def fake_request(method, url, data=None, headers=None):
        if captured is not None:
            captured.update(method=method, url=url, data=data, headers=headers or {})
        return status, body

    monkeypatch.setattr(client_instance, "_request", fake_request)
