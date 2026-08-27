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
pip install zoreal-oauth2
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
assurance block for the strength of the underlying identity proofing.

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
