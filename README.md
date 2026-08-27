# zoreal-oauth2

[![PyPI](https://img.shields.io/pypi/v/zoreal-oauth2)](https://pypi.org/project/zoreal-oauth2/) [![Python versions](https://img.shields.io/pypi/pyversions/zoreal-oauth2)](https://pypi.org/project/zoreal-oauth2/) [![CI](https://img.shields.io/github/actions/workflow/status/Bynn-Intelligence/zoreal-oauth2-python/ci.yml?branch=main&label=CI)](https://github.com/Bynn-Intelligence/zoreal-oauth2-python/actions/workflows/ci.yml) [![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/Bynn-Intelligence/zoreal-oauth2-python/badge)](https://scorecard.dev/viewer/?uri=github.com/Bynn-Intelligence/zoreal-oauth2-python) [![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

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
pip install zoreal-oauth2
```

Python >= 3.9. One dependency: `PyJWT[crypto]`. Framework-agnostic: the same
client works from Django, FastAPI, Flask, or anything else that can receive a
POST. The package ships type hints and a `py.typed` marker.

## Getting your credentials

Everything the client constructor needs comes from a ZOREAL **asset**.

1. Create an account at **https://zoreal.com** and open **Assets**.
2. **Create an asset** — a *website* (a domain you own) or an *app bundle* (a
   reverse-DNS bundle id). An asset is the thing users log in to; its token is
   your `client_id` and it looks like `ast_...`.
3. On the asset, open the **OAuth2** tab and set:
   - the **redirect URIs** and **JavaScript origins** your app uses (requests
     from anything not registered are rejected — this is the core control),
   - the **scopes** the client is allowed to request (see the catalogue below),
   - your **client authentication**: generate a **client secret**
     (`client_secret_basic`), or register a **JWKS** for `private_key_jwt`. A
     public client authenticates with PKCE alone and no secret.
4. A website asset must **verify its domain** (a DNS or meta-tag proof, shown in
   the dashboard) before it can request personal-data scopes or sign users in;
   the verified domain is what your users' `sub` is pairwise against.

The `client_id` is public (it ships in your frontend). The client secret is a
server-side secret — keep it in your process's secret store, never in the
browser.

### There is no test-identity sandbox — and that is deliberate

ZOREAL **never issues fake or sandbox humans**: a pool of test identities would
be a fraud vector against the exact thing the product proves. So you always
authenticate **real** ZOREAL IDs.

To develop and test, **create a free ZOREAL ID for yourself** (enrol in the
ZOREAL ID app) and sign in with it. Mark your asset's environment **sandbox**
in the dashboard while building — a sandbox asset may register `http://localhost`
origins and redirect URIs that a production asset may not — and flip it to
production when you ship. The identities are real either way; only the allowed
origins differ.

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

## Assurance levels — `acr`, and requiring a liveness check

### What `acr` is

`acr` is an OpenID Connect standard claim — *Authentication Context Class
Reference*. It is a single string in the ID token that says **how strongly this
particular login was authenticated**. Every ZOREAL login carries one, and it is
the difference between "someone who once enrolled this identity is behind this
request" and "a live human, verified to be the right one, is behind this request
right now".

It answers a question the `sub` cannot. `sub` tells you *who* (a stable, pairwise
identifier for this person at your site). `acr` tells you *how sure ZOREAL is that
the person is really there for this login*. A stolen, unlocked phone can still
produce a `sub`; it cannot produce a fresh `zoreal.live`.

### The three levels

Ordered weakest to strongest. Each is what actually happened, never what was
requested — a login that could only reach a weaker level says so honestly rather
than claiming the level you asked for.

| `acr` | What the holder did | `amr` | What it proves | What it does **not** prove |
|---|---|---|---|---|
| `zoreal.session` | Nothing — a returning holder at a site they have used before, resumed silently from an existing ZOREAL session, no phone interaction | `[]` | Continuity: the same browser/session ZOREAL already knew | That the holder is present, or even awake |
| `zoreal.device` | Approved the login on their enrolled phone: a signature from a key in the phone's secure element, released by a local biometric or passcode unlock | `["hwk","user"]` | Possession of the enrolled device **and** a local unlock on it | That a live face was captured for *this* login — an unlocked phone in the wrong hands still signs |
| `zoreal.live` | All of the above **plus** a fresh face capture this login: a flash-plus-zoom video scored for presentation attacks and screen replay (moire), matched 1:1 against the government document read at enrolment | `["hwk","face","user"]` | A live, real, unique human, verified to be the enrolled person, **at the moment of this login** | — (this is the strongest level) |

`amr` (*Authentication Methods References*) is the companion claim listing the
factors used: `hwk` a hardware key, `user` a user-presence/unlock gesture, `face`
a face biometric. `zoreal.live` is exactly `zoreal.device` with `face` added,
because a live login is a device approval with a capture on top. It is on the
`Login` as `login.amr`.

The **default is `zoreal.device`**, never `zoreal.session`: a login that asks for
nothing still requires the enrolled phone and a local unlock. Silence has to be
explicitly asked for (`prompt=none`), and it succeeds only for a returning holder
at a site whose consent they have already given.

### When to require which

- **`zoreal.session`** — you never *require* this; it is what a returning holder
  gets for a low-stakes convenience re-auth when they ask for the silent path.
- **`zoreal.device`** (the default) — a forum, a community, a normal account
  login. Possession of the enrolled phone plus a local unlock is a high bar
  already; most sites want exactly this and should pass no `acr` at all.
- **`zoreal.live`** — a bank onboarding, a high-value transaction, an age-gated
  purchase, a first login, a "confirm it is really you" step before a sensitive
  action. Anywhere a *fresh, unforgeable proof of the live, right human* is worth
  the few seconds a face capture costs.

### Requesting versus verifying — the one rule that matters

Requesting a level and verifying it are **two separate steps, and only the second
is security**:

1. **Request** it on the wire, in the frontend, with the SDK's
   `acr_values: "zoreal.live"`. This is what makes the holder's ZOREAL ID app run
   the face capture before it will approve. It is **advisory** — it shapes what
   the holder is asked to do, nothing more. A browser is attacker-controlled; a
   value that only travels through it proves nothing.
2. **Verify** it here, at token exchange, by passing `acr=`. The signed `acr`
   claim in the ID token — minted by ZOREAL, not by the browser — is the proof.

```python
login = ZOREAL_OAUTH.authenticate(
    code=payload["code"],
    code_verifier=payload["code_verifier"],
    nonce=payload["nonce"],
    acr="zoreal.live",  # raises VerificationError unless the signed token says so
)

login.acr                            # "zoreal.live" — what actually happened
login.live                           # convenience: acr == "zoreal.live"
login.satisfies_acr("zoreal.device") # True (live is stronger than device)
```

**An RP that requests `zoreal.live` on the wire but never passes `acr=` here has
checked nothing** — it has only asked the holder nicely and then trusted a value
it never validated.

### How the check behaves

Verification satisfies **upward**: `zoreal.session < zoreal.device <
zoreal.live`, so a requirement of `zoreal.device` accepts a `zoreal.live` token
(the holder gave you *more* assurance than you demanded). A token whose `acr` is
below the requirement, missing entirely, or outside the vocabulary is refused
with `VerificationError`. An unknown *required* value — a typo like
`"zoreal.liveness"` — raises `ConfigurationError` instead, because that is a bug
in your code, not a bad token, and failing every login silently is worse than
saying so.

If you prefer to branch rather than raise, omit `acr=` and inspect the result
with `satisfies_acr`:

```python
login = ZOREAL_OAUTH.authenticate(
    code=payload["code"],
    code_verifier=payload["code_verifier"],
    nonce=payload["nonce"],
)
if not login.satisfies_acr("zoreal.live"):
    # step the user up, or refuse the sensitive action
    ...
```

### `acr` versus the assurance block

Do not confuse `acr` with `login.assurance`. `acr` grades *this login event*.
The **assurance block** (`login.assurance`, a dict) describes the *identity
behind it* — how the person was verified at enrolment (`uniqueness` basis,
`verified_on` month, whether chip liveness was proven, the `trust_tier`, the
device's `key_protection`). One is about now; the other is about who they are. A
high-value flow usually wants both: `acr="zoreal.live"` for presence, and the
assurance block for the strength of the underlying identity proofing. Its schema
is under [The assurance block](#the-assurance-block) below.

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
| `authenticate(code, code_verifier, nonce=None, acr=None)` | `exchange` + `verify_id_token`, returns a `Login` |
| `exchange(code, code_verifier)` | `POST {issuer}/token` with your client authentication |
| `verify_id_token(id_token, nonce=None, acr=None)` | ES256 against `{issuer}/jwks`, checks `iss`, `aud`, `exp`, and `nonce` when given |
| `userinfo(access_token)` | `GET {issuer}/userinfo` with the Bearer token |
| `Login.userinfo` | the above, once, memoized; `{}` when there is no access token |

`Login` reads the verified claims for you: `sub`, `acr`, `amr`, `assurance`,
`age_over(threshold)`, `nationality` from the ID token; `email`,
`email_verified`, `name`, `given_name`, `family_name`, `birthdate`,
`document_type`, `document_number`, `issuing_country`, `document_expires_on`
and `portrait` from `/userinfo`, fetched lazily.

## Scopes and claims

Scopes are requested in the **frontend** (the SDK's `scope` string, always
starting with `openid`), consented to by the holder, and pre-authorized on your
asset. What each grants and where it is delivered:

| Scope | Claims | Delivered in | Tier | Requires |
|---|---|---|---|---|
| `openid` | `sub`, `iss`, `aud`, `exp`, `iat`, `nonce`, `auth_time`, `acr`, `amr`, and the assurance block | ID token | A | any client |
| `zoreal.age` | `age_over_13/16/18/21/65` booleans — only the thresholds you registered, never an age or birthdate | ID token | A | any client |
| `zoreal.nationality` | `nationality` (ISO 3166-1 alpha-3) | ID token | A | any client |
| `email` | `email`, `email_verified` | `/userinfo` | B | confidential client + verified domain |
| `profile.name` | `name`, `given_name`, `family_name` | `/userinfo` | B | confidential client + verified domain |
| `profile.birthdate` | `birthdate` (full ISO 8601 date) | `/userinfo` | B | confidential client + verified domain |
| `profile.document` | `document_type`, `document_number`, `issuing_country`, `document_expires_on` | `/userinfo` | B | confidential client + verified domain |
| `profile.portrait` | `portrait` (the chip's facial image; GDPR Article 9 data) | `/userinfo` | C | confidential client + verified domain — *registrable but not served yet* |

- **Tier A** rides in the ID token and is available to every client, so the
  no-backend browser button can use it. **Tier B and C** are personal data,
  served only from `/userinfo` to a confidential client on a domain you have
  verified, and never placed in a browser token.
- **Age thresholds are a fixed set** — 13, 16, 18, 21, 65 — that you register on
  the asset. `login.age_over(n)` returns `None` for a threshold you did not
  register (no claim was minted), which is different from `False`.

## Error reference

`exchange` and `authenticate` raise `ExchangeError`, which carries the
provider's own `oauth_error` code and `description` verbatim, plus the HTTP
`status`. What you will actually see:

| `oauth_error` | Cause | Retryable? |
|---|---|---|
| `invalid_grant` | The code is spent — unknown, expired (60s), already used, PKCE mismatch, or the asset's domain verification lapsed mid-flow | No. Start a **new** login; the code cannot be reused |
| `invalid_request` | Client authentication failed — wrong secret, a bad `private_key_jwt` assertion, or `tls_client_auth` (not accepted at `/token` yet) | No. Fix your client configuration |
| `unsupported_grant_type` | Something other than `authorization_code` reached `/token` | No. A bug |

Errors that surface in the **frontend** instead, before your backend is
involved (from the SDK's `onError` / `onNonOAuthError` callbacks), so handle
them there:

| Where | Code | Meaning |
|---|---|---|
| `/pair` | `invalid_scope` | A scope not on the asset's allowed list, or a Tier B scope from a public client |
| `/pair` | `invalid_request` | Missing PKCE/nonce, an unverified sector, an unregistered `redirect_uri`, or an unknown `acr_values` |
| `/pair` | `login_required` | `prompt=none` with no silent session to resume — the expected quiet outcome, not a failure |
| pairing | `request_denied` | The holder declined in their ZOREAL ID app — **not an error to alarm on**; offer to try again |
| pairing | `request_expired` | The pairing window elapsed, or a required liveness the device could not meet — offer to try again |

This library's own exceptions, all subclasses of `ZorealOAuth2Error`:

| Exception | Means |
|---|---|
| `ConfigurationError` | You built the client wrong, or asked to verify an `acr` outside the vocabulary — a bug in your code, not a bad token |
| `ExchangeError` | The provider refused the code exchange. Carries `oauth_error`, `description`, and `status` (see the `/token` table above) |
| `VerificationError` | The ID token did not verify: signature, `iss`, `aud`, `exp`, an algorithm other than ES256, the `nonce`, or the `acr` floor |
| `UserinfoError` | The `/userinfo` call failed. A returning user matched on `sub` can survive a caught `UserinfoError`; a signup that needs the email cannot |

Token values never appear in any of these messages: an exception message ends
up in logs, and a log line is no place for a bearer credential.

## The assurance block

`login.assurance` is the ID token's `zoreal` claim — a dict describing the
strength of the *identity* behind this login (distinct from `acr`, which grades
the *login event*). Its keys and their value sets:

| Key | Values | Meaning |
|---|---|---|
| `uniqueness` | `personal_number` \| `document` \| `none` | The anchor the holder is deduplicated on. `personal_number` (a national number from the chip) is strongest; `none` means no reliable anchor |
| `verified_on` | `"YYYY-MM"` | The month the underlying document was verified. Quantised to a month on purpose — a day-precision date is a cross-site correlator |
| `chip_liveness_proven` | `True` \| `False` | Whether the passport chip's active-authentication challenge was proven (a genuine chip, not a clone) |
| `trust_tier` | `high` \| `standard` | `high` when `chip_liveness_proven`, else `standard` |
| `key_protection` | `secure_enclave` \| `strongbox` \| `tee` \| `software` | How the holder's device key is protected. `software` means no hardware attestation |

A high-value flow usually pairs `acr="zoreal.live"` (fresh presence) with a
check on the assurance block (identity strength) — e.g. requiring
`login.assurance["uniqueness"] == "personal_number"` and
`login.assurance["trust_tier"] == "high"`.

## A complete example

A Django view, end to end — the shape a real integration takes. Swap the ORM
and the session calls for your framework's; the ZOREAL half is identical
everywhere.

```python
# urls.py
from django.urls import path
from . import views

urlpatterns = [path("auth/zoreal", views.zoreal_login, name="zoreal_login")]
```

```python
# views.py
import json

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_POST

from zoreal_oauth2 import ExchangeError, UserinfoError, VerificationError

from .accounts import ZOREAL_OAUTH  # the ZorealOAuth2Client built once at boot
from .models import User


# Your frontend's ZorealLogin onSuccess POSTs { code, code_verifier, nonce }
# here over your own TLS. Protect this route with your normal CSRF / same-origin
# controls, exactly as you would any login endpoint — the ZOREAL nonce protects
# the token, not your route. @csrf_protect is doing that job here.
@require_POST
@csrf_protect
def zoreal_login(request):
    payload = json.loads(request.body)

    try:
        login = ZOREAL_OAUTH.authenticate(
            code=payload["code"],
            code_verifier=payload["code_verifier"],
            nonce=payload["nonce"],
            # acr="zoreal.live",  # add for a step-up / high-value login
        )
    except (ExchangeError, VerificationError):
        # A spent code or a token that did not verify: the login must restart.
        return JsonResponse({"error": "sign_in_failed"}, status=401)

    try:
        user = User.objects.filter(provider="zoreal", uid=login.sub).first()
        if user is None:
            # Claim an existing account that owns this verified email rather
            # than colliding on the unique index; otherwise create one. These
            # accessors are the first touch of /userinfo, hence the rescue.
            if login.email_verified:
                user = User.objects.filter(email=login.email).first()
            user = user or User(email=login.email, full_name=login.name)
            user.provider, user.uid = "zoreal", login.sub
            user.save()
    except UserinfoError:
        # Personal data was unreachable. Fine for a returning user matched on
        # sub; fatal for a signup that needs the email.
        return JsonResponse({"error": "sign_in_failed"}, status=401)

    request.session.cycle_key()          # session-fixation defence
    request.session["user_id"] = user.id
    return JsonResponse({"ok": True})
```

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
- **Always pass the nonce through, and protect your own endpoint too.** The SDK
  generates the nonce and gives it to your frontend in `onSuccess`; passing it
  here lets the library confirm the ID token was minted for *this* login rather
  than substituted. Two things it does **not** do: it is not your endpoint's
  CSRF token (protect your login route with your framework's normal CSRF /
  same-origin defence), and PKCE — not the nonce — is what proves whoever
  exchanges the code is whoever started the flow.
- **The `issuer` must match the token's `iss` exactly** — it is compared, not
  normalized. Production is `https://id.zoreal.com`; override `issuer=` only
  when you were given a non-production provider to point at.
- **Email is a deliberate choice.** It is a Tier B scope precisely because a
  shared email defeats the unlinkability the pairwise `sub` provides. Request
  it because you need it, not because the checkbox is familiar.
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

## Development on this package

```sh
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest
```

The tests are offline: keys are generated in-process and the JWKS fetch is
stubbed.

## Verifying this release

Every version is published from GitHub Actions by [trusted publishing](https://docs.pypi.org/trusted-publishers/): the workflow authenticates to PyPI over OIDC with no long-lived API token stored anywhere, and ships [PEP 740](https://peps.python.org/pep-0740/) digital attestations — a [Sigstore](https://www.sigstore.dev/) signature over each artifact, recorded in a public transparency log. The release page on pypi.org shows the verified GitHub repository and workflow that built the files; to check an attestation yourself, see [`pypi-attestations`](https://pypi.org/project/pypi-attestations/).

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
