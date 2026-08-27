"""The relying-party client: exchange, verify, userinfo."""

import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional, Tuple

import jwt

from .auth import ClientAuth, ClientSecretBasic, NoAuth, PrivateKeyJwt, TlsClientAuth
from .errors import ConfigurationError, ExchangeError, UserinfoError, VerificationError
from .login import Login

DEFAULT_ISSUER = "https://id.zoreal.com"

CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


class _MemoryCache:
    """The fallback JWKS cache: one process, TTL respected, no eviction beyond
    overwrite, because it only ever holds the one key set."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._store: Dict[str, Tuple[Any, float]] = {}

    def get(self, key: str) -> Any:
        with self._lock:
            value, expires_at = self._store.get(key, (None, 0.0))
            return value if expires_at > time.monotonic() else None

    def set(self, key: str, value: Any, timeout: Optional[float]) -> None:
        with self._lock:
            self._store[key] = (value, time.monotonic() + (timeout or 0))


class ZorealOAuth2Client:
    """The relying-party client. One instance per registered ZOREAL client;
    thread-safe, so build it once at boot and share it.

    ::

        ZOREAL_OAUTH = ZorealOAuth2Client(
            client_id=os.environ["ZOREAL_CLIENT_ID"],
            auth=ClientSecretBasic(os.environ["ZOREAL_CLIENT_SECRET"]),
            issuer=os.environ.get("ZOREAL_ISSUER", "https://id.zoreal.com"),
        )

        login = ZOREAL_OAUTH.authenticate(
            code=payload["code"],
            code_verifier=payload["code_verifier"],
            nonce=payload["nonce"],
        )
        login.sub       # the pairwise subject: your stable user key
        login.userinfo  # Tier B claims (email, name, ...), fetched once

    ``auth`` is one of :class:`NoAuth` (the default: a public client),
    :class:`ClientSecretBasic`, :class:`PrivateKeyJwt` or
    :class:`TlsClientAuth`.

    ``cache`` takes anything with ``get(key)`` and ``set(key, value, timeout)``
    (Django's cache object is the intended shape). Without one, an in-process
    store is used; that is fine for one process and means each process of a
    multi-process server fetches the JWKS for itself.
    """

    # The provider serves its JWKS with a 10-minute public cache; mirroring it
    # here keeps a busy relying party off the endpoint without holding a
    # rotated-out key longer than the provider itself would.
    JWKS_TTL = 600
    JWKS_CACHE_KEY = "zoreal_oauth2_jwks"

    def __init__(
        self,
        client_id: str,
        issuer: str = DEFAULT_ISSUER,
        auth: Optional[ClientAuth] = None,
        cache: Optional[Any] = None,
        timeout: float = 10.0,
    ) -> None:
        if _blank(client_id):
            raise ConfigurationError("client_id is required")
        if _blank(issuer):
            raise ConfigurationError("issuer is required")
        if auth is not None and not isinstance(auth, ClientAuth):
            raise ConfigurationError(
                "auth must be NoAuth, ClientSecretBasic, PrivateKeyJwt or TlsClientAuth"
            )

        self.client_id = client_id
        self.issuer = issuer.rstrip("/")
        self.auth = auth or NoAuth()
        self._cache = cache if cache is not None else _MemoryCache()
        self._timeout = timeout
        # Built once, at boot, so a bad certificate path fails here and not on
        # the first login of the day.
        self._ssl_context = (
            self.auth.ssl_context() if isinstance(self.auth, TlsClientAuth) else None
        )

    def authenticate(
        self, code: str, code_verifier: str, nonce: Optional[str] = None
    ) -> Login:
        """The whole login, in order: exchange the code (with the PKCE
        verifier the browser SDK handed over), verify the ID token against the
        JWKS, check the nonce when the caller has it. Returns a
        :class:`Login`; personal data is NOT fetched here, because the ID
        token never carries it and not every caller wants it --
        ``Login.userinfo`` fetches on first use."""
        tokens = self.exchange(code, code_verifier)
        claims = self.verify_id_token(tokens["id_token"], nonce=nonce)
        return Login(
            client=self,
            claims=claims,
            id_token=tokens["id_token"],
            access_token=tokens.get("access_token"),
            scope=tokens.get("scope"),
        )

    def exchange(self, code: str, code_verifier: str) -> Dict[str, Any]:
        """``POST {issuer}/token``. The verifier is mandatory: PKCE is
        required for every ZOREAL client, and the browser SDK that generated
        it hands it to your frontend precisely so your backend can present it
        here."""
        if _blank(code):
            raise ValueError("code is required")
        if _blank(code_verifier):
            raise ValueError("code_verifier is required")

        token_url = f"{self.issuer}/token"
        form: Dict[str, str] = {
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": code_verifier,
            "client_id": self.client_id,
        }
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }
        if isinstance(self.auth, ClientSecretBasic):
            # client_secret_basic: the secret travels as the Basic password,
            # never as a form field.
            headers["Authorization"] = self.auth.authorization_header(self.client_id)
        elif isinstance(self.auth, PrivateKeyJwt):
            form["client_assertion_type"] = CLIENT_ASSERTION_TYPE
            form["client_assertion"] = self.auth.build_assertion(
                self.client_id, token_url
            )

        status, raw = self._request(
            "POST",
            token_url,
            data=urllib.parse.urlencode(form).encode("ascii"),
            headers=headers,
        )
        body = _parse_json(raw)
        if not 200 <= status < 300:
            raise ExchangeError(
                body.get("error") or "server_error",
                body.get("error_description") or f"the provider answered {status}",
                status=status,
            )
        if _blank(body.get("id_token")):
            raise ExchangeError("server_error", "no id_token in the token response")
        return body

    def verify_id_token(
        self, id_token: str, nonce: Optional[str] = None
    ) -> Dict[str, Any]:
        """ES256 against the provider's JWKS, plus ``iss`` (exact string
        equality), ``aud``, ``exp`` and -- when the caller passes the nonce the
        SDK generated -- the nonce binding. Returns the claims. There is no
        RS256 fallback on purpose: ZOREAL signs nothing else, and accepting a
        second algorithm is how algorithm confusion starts."""
        try:
            header = jwt.get_unverified_header(id_token)
        except jwt.PyJWTError as exc:
            raise VerificationError(str(exc)) from exc
        if header.get("alg") != "ES256":
            raise VerificationError("the ID token is not signed with ES256")

        key = self._signing_key(header.get("kid"))
        try:
            claims = jwt.decode(
                id_token,
                key=key,
                algorithms=["ES256"],
                issuer=self.issuer,
                audience=self.client_id,
                options={"require": ["exp", "iss", "aud"]},
            )
        except jwt.PyJWTError as exc:
            raise VerificationError(str(exc)) from exc

        if not _blank(nonce) and claims.get("nonce") != nonce:
            raise VerificationError(
                "the ID token nonce is not the one this login started with"
            )
        return claims

    def userinfo(self, access_token: str) -> Dict[str, Any]:
        """``GET {issuer}/userinfo`` with the Bearer access token from the
        exchange. This is the only place personal claims (email, profile.*)
        are served, and the access token lives ten minutes, so call it as part
        of handling the login rather than storing the token for later."""
        if _blank(access_token):
            raise ValueError("access_token is required")

        status, raw = self._request(
            "GET",
            f"{self.issuer}/userinfo",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json",
            },
        )
        body = _parse_json(raw)
        if not 200 <= status < 300:
            raise UserinfoError(
                body.get("error_description") or f"userinfo answered {status}"
            )
        return body

    # -- internal ----------------------------------------------------------

    def _signing_key(self, kid: Optional[str]) -> Any:
        """The verification key for this token: from the cached JWKS, and on
        an unknown ``kid`` the cache is invalidated and fetched once more, so
        a freshly rotated provider key verifies without a ten-minute outage."""
        key = _select_key(self._jwks(), kid)
        if key is None:
            self._cache.set(self.JWKS_CACHE_KEY, None, 0)
            key = _select_key(self._jwks(), kid)
        if key is None:
            raise VerificationError(
                "no key in the provider JWKS matches the ID token"
            )
        return key

    def _jwks(self) -> Dict[str, Any]:
        cached = self._cache.get(self.JWKS_CACHE_KEY)
        if cached:
            return cached
        keys = self._fetch_jwks()
        self._cache.set(self.JWKS_CACHE_KEY, keys, self.JWKS_TTL)
        return keys

    def _fetch_jwks(self) -> Dict[str, Any]:
        try:
            status, raw = self._request(
                "GET", f"{self.issuer}/jwks", headers={"Accept": "application/json"}
            )
        except OSError as exc:
            raise VerificationError(
                f"could not fetch the provider JWKS: {exc}"
            ) from exc
        if not 200 <= status < 300:
            raise VerificationError(f"could not fetch the provider JWKS ({status})")
        try:
            return json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise VerificationError(
                "the provider JWKS was not valid JSON"
            ) from exc

    def _request(
        self,
        method: str,
        url: str,
        data: Optional[bytes] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Tuple[int, bytes]:
        """One HTTP call, returning ``(status, body)``. Provider error
        statuses come back as values -- the callers map them -- while network
        failures raise ``urllib.error.URLError`` (an ``OSError``)."""
        request = urllib.request.Request(
            url, data=data, headers=headers or {}, method=method
        )
        try:
            with urllib.request.urlopen(
                request, timeout=self._timeout, context=self._ssl_context
            ) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, exc.read()


def _select_key(jwks: Any, kid: Optional[str]) -> Any:
    keys = jwks.get("keys") if isinstance(jwks, dict) else None
    candidates = [k for k in keys or [] if isinstance(k, dict)]
    if kid is not None:
        candidates = [k for k in candidates if k.get("kid") == kid]
    for candidate in candidates:
        try:
            return jwt.PyJWK.from_dict(candidate).key
        except jwt.PyJWTError:
            continue
    return None


def _parse_json(raw: bytes) -> Dict[str, Any]:
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _blank(value: Optional[str]) -> bool:
    return value is None or not str(value).strip()
