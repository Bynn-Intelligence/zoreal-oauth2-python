"""Login with ZOREAL for Python backends.

The relying-party half of the flow the browser SDK starts: the code exchange
with your client authentication, ES256 verification of the ID token against
the provider's JWKS, and the ``/userinfo`` read for personal claims.
"""

from .auth import (
    ClientAuth,
    ClientSecretBasic,
    NoAuth,
    PrivateKeyJwt,
    TlsClientAuth,
)
from .client import DEFAULT_ISSUER, ZorealOAuth2Client
from .errors import (
    ConfigurationError,
    ExchangeError,
    UserinfoError,
    VerificationError,
    ZorealOAuth2Error,
)
from .login import Login

__version__ = "0.1.2"

__all__ = [
    "ClientAuth",
    "ClientSecretBasic",
    "ConfigurationError",
    "DEFAULT_ISSUER",
    "ExchangeError",
    "Login",
    "NoAuth",
    "PrivateKeyJwt",
    "TlsClientAuth",
    "UserinfoError",
    "VerificationError",
    "ZorealOAuth2Client",
    "ZorealOAuth2Error",
    "__version__",
]
