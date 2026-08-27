"""Construction-time validation: everything a client cannot work without
fails at boot, not on the first login."""

import pytest

from zoreal_oauth2 import (
    ClientSecretBasic,
    ConfigurationError,
    TlsClientAuth,
    ZorealOAuth2Client,
)
from tests.conftest import CLIENT_ID, ISSUER


def test_client_id_is_required():
    with pytest.raises(ConfigurationError):
        ZorealOAuth2Client("")
    with pytest.raises(ConfigurationError):
        ZorealOAuth2Client("   ")


def test_issuer_is_required():
    with pytest.raises(ConfigurationError):
        ZorealOAuth2Client(CLIENT_ID, issuer="")


def test_issuer_trailing_slash_is_normalized():
    client = ZorealOAuth2Client(CLIENT_ID, issuer=f"{ISSUER}/")
    assert client.issuer == ISSUER


def test_auth_must_be_a_client_auth():
    with pytest.raises(ConfigurationError):
        ZorealOAuth2Client(CLIENT_ID, auth="zcs_secret")  # type: ignore[arg-type]


def test_client_secret_basic_needs_a_secret():
    with pytest.raises(ConfigurationError):
        ClientSecretBasic("")


def test_tls_client_auth_needs_both_files():
    with pytest.raises(ConfigurationError):
        TlsClientAuth("", "key.pem")
    with pytest.raises(ConfigurationError):
        TlsClientAuth("cert.pem", "")


def test_tls_client_auth_fails_at_boot_on_a_missing_file(tmp_path):
    cert = tmp_path / "missing-cert.pem"
    key = tmp_path / "missing-key.pem"
    with pytest.raises(ConfigurationError):
        ZorealOAuth2Client(
            CLIENT_ID, issuer=ISSUER, auth=TlsClientAuth(str(cert), str(key))
        )
