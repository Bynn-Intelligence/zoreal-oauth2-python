"""One verified login."""

import threading
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:  # pragma: no cover
    from .client import ZorealOAuth2Client


class Login:
    """One verified login. The ID token claims are already checked when this
    exists; userinfo is fetched on first use, because the ID token never
    carries personal data and not every login needs any."""

    def __init__(
        self,
        client: "ZorealOAuth2Client",
        claims: Dict[str, Any],
        id_token: str,
        access_token: Optional[str] = None,
        scope: Optional[str] = None,
    ) -> None:
        #: The verified ID token claims and the raw compact JWT they came from.
        self.claims = claims
        self.id_token = id_token
        #: From the token response. The access token lives ten minutes.
        self.access_token = access_token
        self.scope = scope
        self._client = client
        self._userinfo: Optional[Dict[str, Any]] = None
        self._userinfo_lock = threading.Lock()

    @property
    def sub(self) -> Optional[str]:
        """The pairwise subject: stable for your verified domain, meaningless
        to anyone else. This is the value to key accounts on -- and it is
        derived from YOUR registered sector, so changing your asset's domain
        rotates every sub you have stored."""
        return self.claims.get("sub")

    @property
    def acr(self) -> Optional[str]:
        """How the login was authenticated: ``zoreal.live``,
        ``zoreal.device`` or ``zoreal.session``. Describes what happened,
        never what was requested."""
        return self.claims.get("acr")

    @property
    def live(self) -> bool:
        """A fresh liveness capture backed this login. The convenience
        spelling of ``acr == "zoreal.live"``; for enforcement, pass ``acr``
        to ``authenticate`` and let verification refuse the token instead of
        checking after."""
        return self.acr == "zoreal.live"

    def satisfies_acr(self, required: str) -> bool:
        """Equal or stronger satisfies, on the client's ordering
        (``zoreal.session`` < ``zoreal.device`` < ``zoreal.live``). Unknown
        values satisfy nothing."""
        # Imported here, not at the top: the client module imports this one.
        from .client import _acr_rank

        actual = _acr_rank(self.acr)
        wanted = _acr_rank(required)
        return actual is not None and wanted is not None and actual >= wanted

    @property
    def amr(self) -> Optional[List[str]]:
        return self.claims.get("amr")

    @property
    def assurance(self) -> Optional[Dict[str, Any]]:
        """The assurance block: uniqueness basis, verification month, chip
        liveness, trust tier, key protection."""
        return self.claims.get("zoreal")

    def age_over(self, threshold: int) -> Optional[bool]:
        """``zoreal.age`` scope: the registered thresholds arrive as booleans
        (``age_over_18`` and so on), never an age. ``None`` when the
        threshold is not registered for your client."""
        return self.claims.get(f"age_over_{int(threshold)}")

    @property
    def nationality(self) -> Optional[str]:
        """``zoreal.nationality`` scope: ISO 3166-1 alpha-3, read from the
        chip."""
        return self.claims.get("nationality")

    @property
    def userinfo(self) -> Dict[str, Any]:
        """The Tier B claims, from ``/userinfo``, fetched once and memoized.
        Raises :class:`UserinfoError` when the endpoint refuses -- catch it if
        your flow can continue without personal data, as a returning user
        matched on ``sub`` can. An empty dict when the exchange carried no
        access token."""
        if self._userinfo is None:
            with self._userinfo_lock:
                if self._userinfo is None:
                    self._userinfo = (
                        self._client.userinfo(self.access_token)
                        if self.access_token
                        else {}
                    )
        return self._userinfo

    @property
    def email(self) -> Optional[str]:
        return self.userinfo.get("email")

    @property
    def email_verified(self) -> bool:
        return self.userinfo.get("email_verified") is True

    @property
    def name(self) -> Optional[str]:
        return self.userinfo.get("name")

    @property
    def given_name(self) -> Optional[str]:
        return self.userinfo.get("given_name")

    @property
    def family_name(self) -> Optional[str]:
        return self.userinfo.get("family_name")

    @property
    def birthdate(self) -> Optional[str]:
        """ISO 8601, from the ``profile.birthdate`` scope."""
        return self.userinfo.get("birthdate")

    @property
    def document_type(self) -> Optional[str]:
        """``profile.document`` scope, with the three below."""
        return self.userinfo.get("document_type")

    @property
    def document_number(self) -> Optional[str]:
        return self.userinfo.get("document_number")

    @property
    def issuing_country(self) -> Optional[str]:
        return self.userinfo.get("issuing_country")

    @property
    def document_expires_on(self) -> Optional[str]:
        """ISO 8601, from the ``profile.document`` scope."""
        return self.userinfo.get("document_expires_on")

    @property
    def portrait(self) -> Optional[str]:
        """``profile.portrait`` scope. The scope is registrable but the
        provider does not serve the claim yet, so expect ``None`` until it
        does; this accessor exists so your code does not change when it
        ships."""
        return self.userinfo.get("portrait")
