"""Errors raised by the ZOREAL OAuth2 client.

Token values never appear in error messages: an exception message ends up in
logs, and a log line is no place for a bearer credential.
"""

from typing import Optional


class ZorealOAuth2Error(Exception):
    """Base class for every error this library raises on purpose."""


class ConfigurationError(ZorealOAuth2Error):
    """The client was built without something it cannot work without."""


class ExchangeError(ZorealOAuth2Error):
    """The provider refused the code exchange.

    ``oauth_error`` is the RFC 6749 error code and ``description`` the
    provider's own reason, verbatim: the provider's words are the only signal
    that says WHY (a consumed code, a PKCE mismatch, a lapsed sector), and
    rewriting them hides it. ``status`` is the HTTP status when there was one.
    """

    def __init__(
        self,
        oauth_error: str,
        description: Optional[str] = None,
        status: Optional[int] = None,
    ) -> None:
        self.oauth_error = oauth_error
        self.description = description
        self.status = status
        super().__init__(": ".join(part for part in (oauth_error, description) if part))


class VerificationError(ZorealOAuth2Error):
    """The ID token did not verify: bad signature, wrong issuer or audience,
    expired, an algorithm other than ES256, or a nonce that was not the one
    this login started with."""


class UserinfoError(ZorealOAuth2Error):
    """``/userinfo`` answered with anything but the claims. Callers that can
    live without personal data (a returning user matched by ``sub``) may catch
    this and continue; callers that need the email should not."""
