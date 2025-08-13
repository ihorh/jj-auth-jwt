"""Example OAuth2 provider."""

from datetime import UTC, datetime
from typing import Any

from authlib.integrations.starlette_client import OAuth
from authlib.integrations.starlette_client.apps import StarletteOAuth2App
from authlib.oauth2.rfc6749 import OAuth2Token
from jj_jwt_token_factory.id_user_info import BaseJwtIdentifiedUserInfo, UserIdentificationProvider
from jj_jwt_token_factory.jwt_claims import JwtClaimsPub, JwtClaimsStd

type OAuth2ProviderToken = OAuth2Token | dict[str, Any]


class OAuth2Provider:
    """Incapsulates both oath2 client for authentication with 3rd party and parsing 3rd party response into app's model.

    Ideally it **should be provider-agnostic**. However, at present
    `token_to_user_identification_info` method is only tested with Google,
    other provider may use different set of JWT Claims (except standard JWT claims)
    """

    def __init__(self, name: str, oauth: OAuth, *, server_metadata_url: str, redirect_url: str) -> None:
        self.redirect_url = redirect_url
        self._name = name
        self._oauth = oauth
        self._oauth.register(
            name=name,
            # try if server_metadata_url can be moved to starlette_config
            server_metadata_url=server_metadata_url,
            # try if client_kwargs.scope can be moved to starlette_config
            client_kwargs={"scope": "openid email profile"},
        )

    def get_oauth2_app(self) -> StarletteOAuth2App:
        """Based on configuration stored in `self` creates new (always?) or returns existing oauth2 client."""
        candidate = getattr(self._oauth, self._name)
        if isinstance(candidate, StarletteOAuth2App):
            return candidate
        msg = f"Cannot create oauth2 client for: {self._name}"
        raise RuntimeError(msg)

    def token_to_user_identification_info(self, access_token: OAuth2ProviderToken) -> BaseJwtIdentifiedUserInfo:
        """Map JWT claims from provider's token to app model.

        Example implementation for Google.
        """
        return self._extract_user_identification_info(access_token["userinfo"])

    def _extract_user_identification_info(self, token_user_data: Any) -> BaseJwtIdentifiedUserInfo:
        return BaseJwtIdentifiedUserInfo(
            UserIdentificationProvider.GOOGLE,
            token_user_data[JwtClaimsStd.ISS],
            token_user_data[JwtClaimsStd.SUB],
            token_user_data[JwtClaimsPub.EMAIL],
            _any_to_bool(token_user_data[JwtClaimsPub.EMAIL_VERIFIED]),
            token_user_data.get(JwtClaimsPub.NAME),
            token_user_data.get(JwtClaimsPub.GIVEN_NAME),
            token_user_data.get(JwtClaimsPub.FAMILY_NAME),
            token_user_data[JwtClaimsStd.AUD],
            _parse_timestamp_utc(token_user_data[JwtClaimsStd.IAT]),
            _parse_timestamp_utc(token_user_data[JwtClaimsStd.EXP]),
        )


def _any_to_bool(any_bool: Any) -> bool:
    return any_bool and str(any_bool).lower() == "true"


def _parse_timestamp_utc(timestamp: Any) -> datetime:
    """TODO move somewhere to common module."""
    return datetime.fromtimestamp(timestamp, UTC)
