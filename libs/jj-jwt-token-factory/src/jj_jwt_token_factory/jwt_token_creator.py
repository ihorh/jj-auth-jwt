"""Helpers for creating JWT access tokens."""

import random
import sys
from collections.abc import Iterable, MutableSequence, Sequence
from datetime import UTC, datetime, timedelta
from enum import StrEnum, auto
from typing import Any, Final

import jwt
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from jj_jwt_token_factory import LOG
from jj_jwt_token_factory.jwt_claims import JwtClaimsPrv, JwtClaimsPub, JwtClaimsStd, JwtClaimsUnion


class JwtTokenType(StrEnum):
    """JWT Token Type."""

    ACCESS = auto()
    REFRESH = auto()


class JwtTokenExpType(StrEnum):
    """Expiration time keys for different types and subtypes of JWT tokens."""

    DEFAULT = auto()
    """Temporary constant to specify exp time for all token types"""
    ACCESS_NORMAL = auto()
    """Standard (normal) access token (usually shortest exp time)"""
    ACCESS_EXTENDED = auto()
    """Access token with slightly longer expiration time (e.g. for testing)"""
    ACCESS_FRESH = auto()
    """Fresh access token, it may need slighly longer expiration time to give
    user the opportunity to complete operations which require fresh token."""
    REFRESH_NORMAL = auto()
    """Standard / Normal refresh token."""


class JwtTokenError(Exception):
    """Used by JwtTokenCreator to indicate errors, e.g. validation error."""


class JwtExpiredSignatureError(JwtTokenError):
    """Error to indicate expired signature."""


class JwtInvalidTokenError(JwtTokenError):
    """Indicate invalid token."""


class JwtTokenFactory:
    """Convenient factory which can be used in app to streamline JWT tokens generation."""

    _ALG_HS256: Final = "HS256"
    _ALG_RS256: Final = "RS256"

    EXP_15_MINS: dict[JwtTokenExpType, timedelta] = {JwtTokenExpType.DEFAULT: timedelta(minutes=15)}

    def __init__(
        self,
        *,
        secret_key: RSAPrivateKey | str,
        algorithm: str,
        issuer: str,
        tokens_exp: dict[JwtTokenExpType, timedelta] = EXP_15_MINS.copy(),
        dec_require_claims: Sequence[JwtClaimsUnion] = [*JwtClaimsStd],
        enc_extra_claims: dict[JwtClaimsUnion, Any] | None = None,
        dec_extra_claims: dict[JwtClaimsUnion, Any] | None = None,
        dec_return_claims: Sequence[JwtClaimsUnion] | None = None,
    ) -> None:
        self._jwt_iss = issuer
        self._access_token_ttl_min: timedelta = tokens_exp[JwtTokenExpType.DEFAULT]
        self._enc_secret_key = self._check_secret_key(algorithm, secret_key)
        if algorithm not in [self._ALG_HS256, self._ALG_RS256]:
            msg = f"Unsupported algorithm: {algorithm}"
            raise RuntimeError(msg)
        self._algorithm = algorithm
        self._jwt_dec_require_claims = self._cp_or_assign(dec_require_claims)
        self._enc_extra_claims = None if enc_extra_claims is None else enc_extra_claims.copy()
        self._dec_extra_claims = None if dec_extra_claims is None else dec_extra_claims.copy()
        self.dec_return_claims = self._cp_or_assign(dec_return_claims)

        claims_std: dict[str, Any] = {JwtClaimsStd.ISS: self._jwt_iss}
        claims_extra = self._enc_extra_claims or {}
        self._payload_common: dict[str, Any] = claims_std | claims_extra

    def _cp_or_assign(self, sequence: Sequence[JwtClaimsUnion] | None) -> Sequence[JwtClaimsUnion]:
        if sequence is None:
            return []
        if isinstance(sequence, MutableSequence):
            return list(sequence)
        return sequence

    def _create_payload_common(self, token_type: JwtTokenType) -> dict[str, Any]:
        payload = self._payload_common.copy()
        issued_at = datetime.now(UTC)
        payload.update(
            {
                JwtClaimsStd.IAT: issued_at,
                JwtClaimsStd.NBF: issued_at,
                JwtClaimsStd.EXP: issued_at + self._access_token_ttl_min,
                JwtClaimsStd.JTI: random.randint(0, sys.maxsize),  # noqa: S311 TODO: consider better random
                JwtClaimsPrv.A5C_TOKEN_TYPE: token_type,
            }
        )
        return payload

    def create_access_token(
        self,
        sub: str | int,
        *,
        aud: str | list[Any] | None = None,
        claims_pub: dict[JwtClaimsPub, Any] | None = None,
        claims_prv: dict[JwtClaimsPrv, Any] | None = None,
    ) -> str:
        token_data = self._create_payload_common(JwtTokenType.ACCESS)
        token_data[JwtClaimsStd.SUB] = sub
        if aud:
            token_data[JwtClaimsStd.AUD] = aud
        if claims_pub:
            token_data.update(claims_pub.items())
        if claims_prv:
            token_data.update(claims_prv.items())
        LOG.debug("token data as dict: %s", token_data)
        return self._jwt_encode(token_data)

    def create_refresh_token(self) -> str:
        """Not implemented: returns dummy string.

        TODO: of course need to be implemented. But Later.
        """
        return "not_implemented"

    def validate_access_token(
        self, access_token: str, aud: str | Iterable[str] | None = None
    ) -> dict[JwtClaimsUnion, Any]:
        """Decode and validate access token.

        :param access_token: token to decode and validate.
        :param aud: validate if given `access_token` is intended for at least one audience from
        the list provided in `aud` parameter. Since audience check is mandatory by
        `JwtTokenCreator`, missing to specify `aud` will raise JwtTokenErro to indicate
        validation failure.
        :return: `dict` of claim names / values for claims specified in `self.dec_return_claims`
        Error will be thrown if `access_token` is missing any of `self.dec_return_claims`.
        :raises RuntimeError: mostly to describe misconfiguration of `JwtTokenCreator`
        :raises JwtTokenError: notifies about token decoding or validation error
        """
        payload = self._jwt_decode(access_token, aud)
        self._validate_extra_claims(payload)
        try:
            return {key: payload[key] for key in self.dec_return_claims}
        except KeyError as e:
            LOG.warning("JWT token decode error: %s", e.args)
            raise JwtInvalidTokenError(*e.args) from e

    def _validate_extra_claims(self, payload: Any):
        if self._dec_extra_claims is None:
            return
        for k, v in self._dec_extra_claims.items():
            if payload[k] != v:
                msg = f"missing claim {k}"
                raise JwtInvalidTokenError(msg)

    def _jwt_encode(self, payload: dict[str, Any]) -> str:
        """Encode payload as JWT using configuration from app settings."""
        return jwt.encode(payload, self._enc_secret_key, self._algorithm)

    def _jwt_decode(self, token: str, aud: str | Iterable[str] | None = None) -> Any:
        """Decode AND validate."""
        decode_key = self._jwt_decode_secret_key()
        try:
            payload = jwt.decode(
                token,
                decode_key,
                algorithms=[self._algorithm],
                options={"require": self._jwt_dec_require_claims},
                audience=aud,
                issuer=self._jwt_iss,
            )
            LOG.debug("JWT token payload: %s", payload)
            return payload
        except (jwt.InvalidKeyError, jwt.InvalidAlgorithmError) as e:
            # configuration error
            msg = "JWT configuration error"
            LOG.critical(msg, exc_info=True)
            raise RuntimeError(msg) from e
        except jwt.ExpiredSignatureError as e:
            # this exception is pretty innocent, can happen often and does not
            # necesserily indicated security issue.
            LOG.debug(e)
            raise JwtExpiredSignatureError(*e.args) from e
        except jwt.InvalidTokenError as e:
            # other token decode error may indicate misuse or security issue
            LOG.warning("JWT token decode error: %s", e.args)
            raise JwtInvalidTokenError(*e.args) from e
        except jwt.PyJWTError as e:
            # handle all other cases
            LOG.error("JWT token decode error")
            raise RuntimeError(*e.args) from e

    @classmethod
    def _check_secret_key(cls, algorithm: str, key: RSAPrivateKey | str) -> RSAPrivateKey | str:
        if (algorithm == cls._ALG_HS256 and isinstance(key, str)) or (
            algorithm == cls._ALG_RS256 and isinstance(key, RSAPrivateKey)
        ):
            return key
        else:
            raise RuntimeError(f"invalid key for algorith {algorithm}")

    def _jwt_decode_secret_key(self) -> RSAPublicKey | str:
        key = self._enc_secret_key
        if self._algorithm == self._ALG_HS256 and isinstance(key, str):
            return key
        if self._algorithm == self._ALG_RS256 and isinstance(key, RSAPrivateKey):
            return key.public_key()
        raise RuntimeError(f"invalid key for algorith {self._algorithm}")
