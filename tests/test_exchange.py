"""The token exchange and userinfo, with the HTTP layer stubbed: what goes on
the wire for each client authentication method, and how provider refusals map
to errors."""

import base64
import json
import urllib.parse

import jwt
import pytest

from zoreal_oauth2 import (
    ClientSecretBasic,
    ExchangeError,
    PrivateKeyJwt,
    UserinfoError,
    ZorealOAuth2Client,
)
from tests.conftest import CLIENT_ID, ISSUER, make_p256_key, stub_request

TOKEN_RESPONSE = json.dumps(
    {
        "id_token": "signed-elsewhere",
        "access_token": "att_x",
        "token_type": "Bearer",
        "expires_in": 600,
        "scope": "openid email",
    }
).encode()


def form_of(captured):
    return {k: v[0] for k, v in urllib.parse.parse_qs(captured["data"].decode()).items()}


def test_public_client_sends_the_form_and_no_authorization(monkeypatch):
    client = ZorealOAuth2Client(CLIENT_ID, issuer=ISSUER)
    captured = {}
    stub_request(client, monkeypatch, 200, TOKEN_RESPONSE, captured)

    body = client.exchange("code-1", "verifier-1")

    assert body["id_token"] == "signed-elsewhere"
    assert captured["method"] == "POST"
    assert captured["url"] == f"{ISSUER}/token"
    assert "Authorization" not in captured["headers"]
    form = form_of(captured)
    assert form == {
        "grant_type": "authorization_code",
        "code": "code-1",
        "code_verifier": "verifier-1",
        "client_id": CLIENT_ID,
    }


def test_client_secret_basic_travels_as_the_basic_header(monkeypatch):
    client = ZorealOAuth2Client(
        CLIENT_ID, issuer=ISSUER, auth=ClientSecretBasic("zcs_secret")
    )
    captured = {}
    stub_request(client, monkeypatch, 200, TOKEN_RESPONSE, captured)

    client.exchange("code-1", "verifier-1")

    expected = base64.b64encode(f"{CLIENT_ID}:zcs_secret".encode()).decode()
    assert captured["headers"]["Authorization"] == f"Basic {expected}"
    form = form_of(captured)
    # The secret never rides in the form; the client_id still does, because
    # the provider matches the code against it.
    assert "client_secret" not in form
    assert form["client_id"] == CLIENT_ID


def test_private_key_jwt_adds_a_signed_assertion(monkeypatch):
    key = make_p256_key()
    client = ZorealOAuth2Client(CLIENT_ID, issuer=ISSUER, auth=PrivateKeyJwt(key))
    captured = {}
    stub_request(client, monkeypatch, 200, TOKEN_RESPONSE, captured)

    client.exchange("code-1", "verifier-1")

    form = form_of(captured)
    assert (
        form["client_assertion_type"]
        == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    )
    claims = jwt.decode(
        form["client_assertion"],
        key=key.public_key(),
        algorithms=["ES256"],
        audience=f"{ISSUER}/token",
    )
    assert claims["iss"] == CLIENT_ID
    assert claims["sub"] == CLIENT_ID


def test_provider_refusal_maps_to_exchange_error_verbatim(monkeypatch):
    client = ZorealOAuth2Client(CLIENT_ID, issuer=ISSUER)
    body = json.dumps(
        {"error": "invalid_grant", "error_description": "the code is not valid"}
    ).encode()
    stub_request(client, monkeypatch, 400, body)

    with pytest.raises(ExchangeError) as excinfo:
        client.exchange("code-1", "verifier-1")

    assert excinfo.value.oauth_error == "invalid_grant"
    assert excinfo.value.description == "the code is not valid"
    assert excinfo.value.status == 400


def test_tls_client_auth_501_surfaces_as_the_exchange_error_it_is(monkeypatch):
    client = ZorealOAuth2Client(CLIENT_ID, issuer=ISSUER)
    body = json.dumps(
        {
            "error": "invalid_request",
            "error_description": "tls_client_auth is not implemented at this endpoint yet; "
            "use private_key_jwt or client_secret_basic",
        }
    ).encode()
    stub_request(client, monkeypatch, 501, body)

    with pytest.raises(ExchangeError) as excinfo:
        client.exchange("code-1", "verifier-1")

    assert excinfo.value.status == 501
    assert "not implemented" in str(excinfo.value)


def test_unparseable_error_body_still_reports_the_status(monkeypatch):
    client = ZorealOAuth2Client(CLIENT_ID, issuer=ISSUER)
    stub_request(client, monkeypatch, 502, b"<html>bad gateway</html>")

    with pytest.raises(ExchangeError) as excinfo:
        client.exchange("code-1", "verifier-1")

    assert excinfo.value.oauth_error == "server_error"
    assert excinfo.value.status == 502


def test_a_success_without_an_id_token_is_an_error(monkeypatch):
    client = ZorealOAuth2Client(CLIENT_ID, issuer=ISSUER)
    stub_request(client, monkeypatch, 200, json.dumps({"access_token": "att_x"}).encode())

    with pytest.raises(ExchangeError) as excinfo:
        client.exchange("code-1", "verifier-1")

    assert "id_token" in str(excinfo.value)


def test_blank_code_or_verifier_never_reach_the_wire(monkeypatch):
    client = ZorealOAuth2Client(CLIENT_ID, issuer=ISSUER)
    with pytest.raises(ValueError):
        client.exchange("", "verifier-1")
    with pytest.raises(ValueError):
        client.exchange("code-1", "  ")


def test_userinfo_sends_the_bearer_token(monkeypatch):
    client = ZorealOAuth2Client(CLIENT_ID, issuer=ISSUER)
    captured = {}
    stub_request(
        client,
        monkeypatch,
        200,
        json.dumps({"sub": "7QK3", "email": "holder@example.com"}).encode(),
        captured,
    )

    claims = client.userinfo("att_x")

    assert captured["method"] == "GET"
    assert captured["url"] == f"{ISSUER}/userinfo"
    assert captured["headers"]["Authorization"] == "Bearer att_x"
    assert claims["email"] == "holder@example.com"


def test_userinfo_refusal_maps_to_userinfo_error(monkeypatch):
    client = ZorealOAuth2Client(CLIENT_ID, issuer=ISSUER)
    body = json.dumps(
        {"error": "invalid_token", "error_description": "the access token is not valid"}
    ).encode()
    stub_request(client, monkeypatch, 401, body)

    with pytest.raises(UserinfoError) as excinfo:
        client.userinfo("att_x")

    assert "the access token is not valid" in str(excinfo.value)
