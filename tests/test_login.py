"""The Login object: claim accessors, and the lazy, memoized userinfo."""

import json

import pytest

from zoreal_oauth2 import Login, ZorealOAuth2Client
from tests.conftest import CLIENT_ID, ISSUER, base_claims, stub_request


class CountingClient:
    """Stands in for the client: counts userinfo calls."""

    def __init__(self, payload):
        self.payload = payload
        self.calls = 0

    def userinfo(self, access_token):
        self.calls += 1
        return self.payload


def test_conveniences_read_the_id_token_claims():
    claims = base_claims(
        age_over_18=True,
        nationality="SWE",
        amr=["hwk", "face", "user"],
        zoreal={"trust_tier": "high"},
    )
    login = Login(client=CountingClient({}), claims=claims, id_token="x")

    assert login.sub == "7QK3-9F2M-XR84-B5NP"
    assert login.acr == "zoreal.device"
    assert login.amr == ["hwk", "face", "user"]
    assert login.age_over(18) is True
    assert login.age_over(65) is None  # not a registered threshold
    assert login.nationality == "SWE"
    assert login.assurance["trust_tier"] == "high"


def test_live_and_satisfies_acr_read_the_ordering():
    live = Login(client=CountingClient({}), claims={"acr": "zoreal.live"}, id_token="x")
    assert live.live is True
    assert live.satisfies_acr("zoreal.device")
    assert not live.satisfies_acr("made.up")  # unknown values satisfy nothing

    device = Login(
        client=CountingClient({}), claims={"acr": "zoreal.device"}, id_token="x"
    )
    assert device.live is False
    assert not device.satisfies_acr("zoreal.live")


def test_userinfo_is_fetched_once_and_memoized():
    stub = CountingClient(
        {
            "sub": "7QK3-9F2M-XR84-B5NP",
            "email": "holder@example.com",
            "email_verified": True,
            "name": "Anna Larsson",
            "given_name": "Anna",
            "family_name": "Larsson",
            "birthdate": "1993-04-12",
            "document_type": "passport",
            "document_number": "X1234567",
            "issuing_country": "SWE",
            "document_expires_on": "2031-04-11",
        }
    )
    login = Login(client=stub, claims=base_claims(), id_token="x", access_token="att_x")

    assert login.email == "holder@example.com"
    assert login.email_verified is True
    assert login.name == "Anna Larsson"
    assert login.given_name == "Anna"
    assert login.family_name == "Larsson"
    assert login.birthdate == "1993-04-12"
    assert login.document_type == "passport"
    assert login.document_number == "X1234567"
    assert login.issuing_country == "SWE"
    assert login.document_expires_on == "2031-04-11"
    # Registrable, not served by the provider yet.
    assert login.portrait is None
    assert stub.calls == 1


def test_no_access_token_means_empty_userinfo_and_no_fetch():
    stub = CountingClient({"email": "never@example.com"})
    login = Login(client=stub, claims=base_claims(), id_token="x")

    assert login.userinfo == {}
    assert login.email is None
    assert login.email_verified is False
    assert stub.calls == 0


def test_authenticate_wires_the_whole_flow(monkeypatch, provider_key, jwks):
    from tests.conftest import sign

    token_body = json.dumps(
        {
            "id_token": sign(base_claims(), provider_key),
            "access_token": "att_x",
            "token_type": "Bearer",
            "expires_in": 600,
            "scope": "openid",
        }
    ).encode()

    client = ZorealOAuth2Client(CLIENT_ID, issuer=ISSUER)
    monkeypatch.setattr(client, "_fetch_jwks", lambda: jwks)
    stub_request(client, monkeypatch, 200, token_body)

    login = client.authenticate("code-1", "verifier-1", nonce="n-1")

    assert login.sub == "7QK3-9F2M-XR84-B5NP"
    assert login.access_token == "att_x"
    assert login.scope == "openid"


def test_authenticate_enforces_the_acr_floor(monkeypatch, provider_key, jwks):
    from tests.conftest import sign
    from zoreal_oauth2 import VerificationError

    # base_claims carries acr zoreal.device; the caller requires zoreal.live.
    token_body = json.dumps({"id_token": sign(base_claims(), provider_key)}).encode()

    client = ZorealOAuth2Client(CLIENT_ID, issuer=ISSUER)
    monkeypatch.setattr(client, "_fetch_jwks", lambda: jwks)
    stub_request(client, monkeypatch, 200, token_body)

    with pytest.raises(VerificationError):
        client.authenticate("code-1", "verifier-1", nonce="n-1", acr="zoreal.live")


def test_authenticate_refuses_a_swapped_nonce(monkeypatch, provider_key, jwks):
    from tests.conftest import sign
    from zoreal_oauth2 import VerificationError

    token_body = json.dumps(
        {"id_token": sign(base_claims(nonce="stolen"), provider_key)}
    ).encode()

    client = ZorealOAuth2Client(CLIENT_ID, issuer=ISSUER)
    monkeypatch.setattr(client, "_fetch_jwks", lambda: jwks)
    stub_request(client, monkeypatch, 200, token_body)

    with pytest.raises(VerificationError):
        client.authenticate("code-1", "verifier-1", nonce="n-1")
