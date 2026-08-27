# zoreal-oauth2

Login with ZOREAL for Python backends: the relying-party half of the flow that
[`@zoreal/oauth2-react`](https://github.com/Bynn-Intelligence/zoreal-oauth2-react)
starts in the browser.

The browser SDK runs the pairing (QR or app link), and hands your frontend an
authorization `code` plus the `code_verifier` and `nonce` it generated. Your
frontend posts all three to your backend, and this package does the rest: the
code exchange with your client authentication, ES256 verification of the ID
token against the provider's JWKS, and the `/userinfo` read for personal
claims.

```
zoreal-oauth2 (this package)   your backend: exchange, verify, userinfo
@zoreal/oauth2-react           your frontend: the button, the QR, the polling
```

## Install

```sh
# until the package is on PyPI, install from the git source:
pip install "zoreal-oauth2 @ git+https://github.com/Bynn-Intelligence/zoreal-oauth2-python"
```

Python >= 3.9. One dependency: `PyJWT[crypto]`. Framework-agnostic: the same
client works from Django, FastAPI, Flask, or anything else that can receive a
POST. The package ships type hints and a `py.typed` marker.

## Quick start

Build one client at boot and share it; it is thread-safe.

```python
import os
from zoreal_oauth2 import ClientSecretBasic, ZorealOAuth2Client

ZOREAL_OAUTH = ZorealOAuth2Client(
    client_id=os.environ["ZOREAL_CLIENT_ID"],                    # ast_...
    auth=ClientSecretBasic(os.environ["ZOREAL_CLIENT_SECRET"]),
    issuer=os.environ.get("ZOREAL_ISSUER", "https://id.zoreal.com"),
    cache=None,  # optional, for the JWKS; Django's cache object fits as-is
)
```

The endpoint your frontend posts to (any framework; the body is the
`{code, code_verifier, nonce}` the browser SDK handed over):

```python
login = ZOREAL_OAUTH.authenticate(
    code=payload["code"],
    code_verifier=payload["code_verifier"],  # PKCE is mandatory; the SDK hands it over
    nonce=payload["nonce"],                  # binds the ID token to this login
)

login.sub            # "TC5X-JN7G-YTSE-6E63" — pairwise, stable for YOUR domain
login.acr            # "zoreal.live" | "zoreal.device" | "zoreal.session"
login.assurance      # uniqueness basis, verification month, chip liveness, trust tier
login.email          # from /userinfo, when your client has the email scope
login.email_verified
login.name           # from /userinfo, profile.name scope
```

Account matching, the shape that works:

```python
user = User.objects.filter(provider="zoreal", uid=login.sub).first()
if user is None:
    if login.email_verified:  # claim, don't collide
        user = User.objects.filter(email=login.email).first()
    user = user or User(email=login.email)
    user.provider, user.uid = "zoreal", login.sub
    user.save()
```

## Client authentication

Four methods, one class each. Use the one your client is registered with in
the ZOREAL dashboard.

```python
from zoreal_oauth2 import (
    ClientSecretBasic, NoAuth, PrivateKeyJwt, TlsClientAuth, ZorealOAuth2Client,
)

# A public client: no secret, no key. PKCE is the only proof, which is why a
# public client can only ever have been granted Tier A scopes.
ZorealOAuth2Client(client_id, auth=NoAuth())  # auth=None means the same

# Confidential, shared secret. The secret travels as HTTP Basic, never as a
# form field.
ZorealOAuth2Client(client_id, auth=ClientSecretBasic(client_secret))

# Confidential, private_key_jwt (RFC 7523). The library builds and signs a
# fresh 55-second assertion per exchange (iss/sub = client_id, aud = the token
# endpoint, single-use jti); your private key never travels. A P-256 key signs
# ES256 (preferred — it is the same key shape ZOREAL certifies), an RSA key
# signs RS256. PEM string, private JWK dict, or a cryptography key object.
ZorealOAuth2Client(client_id, auth=PrivateKeyJwt(pem_or_key, kid="rp-key-1"))

# Mutual TLS: the certificate and key are loaded into the TLS context for
# every call this client makes. Registrable, but the provider does not accept
# it at the token endpoint yet — the 501 it answers surfaces as an
# ExchangeError with that status, verbatim, rather than being papered over.
ZorealOAuth2Client(client_id, auth=TlsClientAuth("cert.pem", "key.pem"))
```

## What each call does

| Call | What happens |
|---|---|
| `authenticate(code, code_verifier, nonce=None)` | `exchange` + `verify_id_token`, returns a `Login` |
| `exchange(code, code_verifier)` | `POST {issuer}/token` with your client authentication |
| `verify_id_token(id_token, nonce=None)` | ES256 against `{issuer}/jwks`, checks `iss`, `aud`, `exp`, and `nonce` when given |
| `userinfo(access_token)` | `GET {issuer}/userinfo` with the Bearer token |
| `Login.userinfo` | the above, once, memoized; `{}` when there is no access token |

`Login` reads the verified claims for you: `sub`, `acr`, `amr`, `assurance`,
`age_over(threshold)`, `nationality` from the ID token; `email`,
`email_verified`, `name`, `given_name`, `family_name`, `birthdate`,
`document_type`, `document_number`, `issuing_country`, `document_expires_on`
and `portrait` from `/userinfo`, fetched lazily.

Errors: `ConfigurationError`, `ExchangeError` (carries the provider's OAuth
error code and reason, verbatim, plus the HTTP status), `VerificationError`,
`UserinfoError`. A returning user matched on `sub` can survive a caught
`UserinfoError`; a signup that needs the email cannot. Token values never
appear in error messages.

## Things worth knowing before you integrate

- **The ID token never carries personal data.** `sub`, timing, `acr`/`amr`,
  the assurance block, and — if registered — `age_over_*` booleans and
  `nationality`. Email, names, birthdate and document fields come only from
  `/userinfo`, which is why `authenticate` alone is not enough for a signup.
- **The access token lives 10 minutes.** Read `/userinfo` while handling the
  login; do not store the token for later.
- **`sub` is pairwise per verified domain.** It is the right account key and
  it is derived from your registered sector: changing your asset's domain
  rotates every `sub` you have stored. Plan domain changes as a migration.
- **ES256 only.** The provider signs with nothing else, and this package
  refuses other algorithms rather than negotiating.
- **Always pass the nonce through.** The SDK generates it and gives it to your
  frontend in `onSuccess`; without it your backend cannot tell a substituted
  ID token from the real one.
- **Email is a deliberate choice.** It is a Tier B scope precisely because a
  shared email defeats the unlinkability the pairwise `sub` provides. Request
  it because you need it, not because the checkbox is familiar.
- **Sandbox clients accept localhost origins; production clients do not.**
  Registration lives in the ZOREAL dashboard on the asset's OAuth2 tab; Tier B
  scopes (email, profile.\*) need a confidential client on a verified domain.
- **Pick the client authentication your posture needs.** A public client
  (`NoAuth`) is for exchanges that happen where a secret cannot live;
  `ClientSecretBasic` is the ordinary confidential setup;
  `PrivateKeyJwt` replaces the shared secret with proof of possession of a
  key that never travels, and is the method ZOREAL's certificate path is
  built around; `TlsClientAuth` is registrable but the provider answers 501
  at the token endpoint today, and this library surfaces that rather than
  faking it.
- **`profile.portrait` is registrable but not served yet.** `Login.portrait`
  exists so your code does not change when it ships; expect `None` until then.

## Development against a local provider

Point `issuer` at your provider instance. The issuer value must match the
`iss` inside the tokens exactly — it is compared, not normalized.

## Development on this package

```sh
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest
```

The tests are offline: keys are generated in-process and the JWKS fetch is
stubbed.

## The ZOREAL OAuth2 library family

| Repository | Package | Role |
|---|---|---|
| zoreal-oauth2-react | @zoreal/oauth2-react (npm) | React frontend: the button, the QR, the polling |
| zoreal-oauth2-js | @zoreal/oauth2-js (npm) | Framework-free browser core |
| zoreal-oauth2-react-native | @zoreal/oauth2-react-native (npm) | React Native frontend |
| zoreal-oauth2-node | @zoreal/oauth2-node (npm) | Node.js backend |
| zoreal-oauth2-ruby | zoreal-oauth2 (RubyGems) | Ruby backend |
| zoreal-oauth2-python | zoreal-oauth2 (PyPI) | Python backend |
| zoreal-oauth2-php | zoreal/oauth2 (Packagist) | PHP backend |
| zoreal-oauth2-go | github.com/Bynn-Intelligence/zoreal-oauth2-go | Go backend |
| zoreal-oauth2-java | com.zoreal:oauth2 (Maven Central) | JVM backend |
| zoreal-oauth2-dotnet | Zoreal.OAuth2 (NuGet) | .NET backend |

## License

MIT.
