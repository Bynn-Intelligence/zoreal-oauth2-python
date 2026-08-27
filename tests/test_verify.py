"""ID token verification, entirely offline: the JWKS fetch is monkeypatched
in the ``client`` fixture, so nothing here touches the network."""

import time

import jwt
import pytest

from zoreal_oauth2 import VerificationError, ZorealOAuth2Client
from tests.conftest import (
    CLIENT_ID,
    ISSUER,
    KID,
    base_claims,
    jwk_for,
    make_p256_key,
    sign,
)


def test_valid_token_verifies_and_returns_claims(client, provider_key):
    claims = client.verify_id_token(sign(base_claims(), provider_key), nonce="n-1")
    assert claims["sub"] == "7QK3-9F2M-XR84-B5NP"
    assert claims["acr"] == "zoreal.device"


def test_nonce_mismatch_is_refused(client, provider_key):
    with pytest.raises(VerificationError):
        client.verify_id_token(sign(base_claims(), provider_key), nonce="other")


def test_nonce_is_not_checked_when_caller_has_none(client, provider_key):
    assert client.verify_id_token(sign(base_claims(), provider_key))


def test_wrong_audience_is_refused(client, provider_key):
    token = sign(base_claims(aud="ast_other"), provider_key)
    with pytest.raises(VerificationError):
        client.verify_id_token(token)


def test_wrong_issuer_is_refused(client, provider_key):
    token = sign(base_claims(iss="https://evil.example"), provider_key)
    with pytest.raises(VerificationError):
        client.verify_id_token(token)


def test_expired_token_is_refused(client, provider_key):
    token = sign(base_claims(exp=int(time.time()) - 5), provider_key)
    with pytest.raises(VerificationError):
        client.verify_id_token(token)


def test_foreign_key_is_refused(client):
    other = make_p256_key()
    token = sign(base_claims(), other, kid="foreign-key")
    with pytest.raises(VerificationError):
        client.verify_id_token(token)


def test_foreign_key_with_the_same_kid_is_refused(client):
    # Same kid, different key: the signature check itself has to catch it.
    other = make_p256_key()
    token = sign(base_claims(), other, kid=KID)
    with pytest.raises(VerificationError):
        client.verify_id_token(token)


def test_non_es256_algorithm_is_refused(client):
    token = jwt.encode(base_claims(), "a-shared-secret-of-32-bytes-long", algorithm="HS256")
    with pytest.raises(VerificationError) as excinfo:
        client.verify_id_token(token)
    assert "ES256" in str(excinfo.value)


def test_garbage_token_is_refused(client):
    with pytest.raises(VerificationError):
        client.verify_id_token("not-a-jwt")


def test_unknown_kid_invalidates_the_cache_and_refetches_once(monkeypatch):
    old_key, new_key = make_p256_key(), make_p256_key()
    fetches = {"count": 0}

    def fetch():
        fetches["count"] += 1
        return {"keys": [jwk_for(new_key, "rotated-key")]}

    instance = ZorealOAuth2Client(CLIENT_ID, issuer=ISSUER)
    monkeypatch.setattr(instance, "_fetch_jwks", fetch)
    # Pre-warm the cache with the stale key set, as a long-running process
    # would hold it across a provider rotation.
    instance._cache.set(
        ZorealOAuth2Client.JWKS_CACHE_KEY,
        {"keys": [jwk_for(old_key, KID)]},
        ZorealOAuth2Client.JWKS_TTL,
    )

    token = sign(base_claims(), new_key, kid="rotated-key")
    claims = instance.verify_id_token(token, nonce="n-1")
    assert claims["sub"] == "7QK3-9F2M-XR84-B5NP"
    assert fetches["count"] == 1


def test_a_kid_missing_everywhere_fails_after_one_refetch(monkeypatch, jwks):
    fetches = {"count": 0}

    def fetch():
        fetches["count"] += 1
        return jwks

    instance = ZorealOAuth2Client(CLIENT_ID, issuer=ISSUER)
    monkeypatch.setattr(instance, "_fetch_jwks", fetch)

    token = sign(base_claims(), make_p256_key(), kid="nobody-has-this")
    with pytest.raises(VerificationError):
        instance.verify_id_token(token)
    # One fetch for the empty cache, one for the invalidation. Never a loop.
    assert fetches["count"] == 2
