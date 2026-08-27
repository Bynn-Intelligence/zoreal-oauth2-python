"""The private_key_jwt client assertion: built by the library, decoded here
with the matching public key, and checked claim by claim."""

import json

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from zoreal_oauth2 import ConfigurationError, PrivateKeyJwt
from tests.conftest import CLIENT_ID, ISSUER, make_p256_key

TOKEN_URL = f"{ISSUER}/token"


def decode(assertion: str, key, algorithm: str):
    return jwt.decode(
        assertion,
        key=key.public_key(),
        algorithms=[algorithm],
        audience=TOKEN_URL,
        options={"require": ["exp", "iat", "jti"]},
    )


def test_es256_assertion_carries_the_contract_claims():
    key = make_p256_key()
    auth = PrivateKeyJwt(key)
    claims = decode(auth.build_assertion(CLIENT_ID, TOKEN_URL), key, "ES256")

    assert claims["iss"] == CLIENT_ID
    assert claims["sub"] == CLIENT_ID
    assert claims["aud"] == TOKEN_URL
    assert claims["jti"]
    # The provider refuses assertions living longer than 60 seconds.
    assert 0 < claims["exp"] - claims["iat"] <= 60


def test_jti_is_fresh_per_assertion():
    key = make_p256_key()
    auth = PrivateKeyJwt(key)
    first = decode(auth.build_assertion(CLIENT_ID, TOKEN_URL), key, "ES256")
    second = decode(auth.build_assertion(CLIENT_ID, TOKEN_URL), key, "ES256")
    assert first["jti"] != second["jti"]


def test_kid_header_is_set_when_given():
    key = make_p256_key()
    assertion = PrivateKeyJwt(key, kid="rp-key-7").build_assertion(CLIENT_ID, TOKEN_URL)
    assert jwt.get_unverified_header(assertion)["kid"] == "rp-key-7"

    bare = PrivateKeyJwt(key).build_assertion(CLIENT_ID, TOKEN_URL)
    assert "kid" not in jwt.get_unverified_header(bare)


def test_rsa_key_signs_rs256():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    auth = PrivateKeyJwt(key)
    assert auth.algorithm == "RS256"
    claims = decode(auth.build_assertion(CLIENT_ID, TOKEN_URL), key, "RS256")
    assert claims["iss"] == CLIENT_ID


def test_pem_string_is_accepted():
    from cryptography.hazmat.primitives import serialization

    key = make_p256_key()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")
    auth = PrivateKeyJwt(pem)
    assert auth.algorithm == "ES256"
    # Signed by the parsed key, verifiable with the original public half.
    decode(auth.build_assertion(CLIENT_ID, TOKEN_URL), key, "ES256")


def test_private_jwk_dict_is_accepted():
    key = make_p256_key()
    jwk = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(key))
    auth = PrivateKeyJwt(jwk)
    assert auth.algorithm == "ES256"
    decode(auth.build_assertion(CLIENT_ID, TOKEN_URL), key, "ES256")


def test_non_p256_ec_key_is_refused():
    with pytest.raises(ConfigurationError):
        PrivateKeyJwt(ec.generate_private_key(ec.SECP384R1()))


def test_a_public_key_is_refused():
    with pytest.raises(ConfigurationError):
        PrivateKeyJwt(make_p256_key().public_key())  # type: ignore[arg-type]


def test_garbage_pem_is_refused_without_echoing_it():
    marker = "not a key at all"
    with pytest.raises(ConfigurationError) as excinfo:
        PrivateKeyJwt(marker)
    assert marker not in str(excinfo.value)


def test_assertion_signature_is_the_holders():
    # A verifier holding a DIFFERENT public key must refuse the assertion:
    # proof of possession, not just well-formed claims.
    key, other = make_p256_key(), make_p256_key()
    assertion = PrivateKeyJwt(key).build_assertion(CLIENT_ID, TOKEN_URL)
    with pytest.raises(jwt.InvalidSignatureError):
        jwt.decode(
            assertion,
            key=other.public_key(),
            algorithms=["ES256"],
            audience=TOKEN_URL,
        )
