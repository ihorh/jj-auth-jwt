"""Enumerations of JWT claims supported by application."""

from enum import StrEnum
from typing import Any


class JwtClaimsStd(StrEnum):
    """Registered JWT Claims.

    See: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1

    * Issuer Claim (“iss”): which application issued the JWT?
    * Subject Claim (“sub”): who is the user subject of the JWT?
    * Audience Claim (“aud”): which application is the JWT intended for?
    * Expiration Time Claim (“exp”): until what date/time can the JWT be accepted?
    * Not Before Claim (“nbf”): what date/time can the JWT start being accepted?
    * Issued At Claim (“iat”): when was the JWT issued?
    * JWT ID Claim (“jti”): which individual JWT is this?
    """

    ISS = "iss"  # aud_id of auth app
    """The "iss" (issuer) claim identifies the principal that issued the
    JWT. The processing of this claim is generally application specific.
    The "iss" value is a case-sensitive string containing a StringOrURI
    value.  Use of this claim is OPTIONAL.
    """
    SUB = "sub"  # user id (int)
    """The "sub" (subject) claim identifies the principal that is the
    subject of the JWT.  The claims in a JWT are normally statements
    about the subject.  The subject value MUST either be scoped to be
    locally unique in the context of the issuer or be globally unique.
    The processing of this claim is generally application specific.  The
    "sub" value is a case-sensitive string containing a StringOrURI
    value.  Use of this claim is OPTIONAL.
    """
    AUD = "aud"  # array of aud_ud
    """The "aud" (audience) claim identifies the recipients that the JWT is
    intended for.  Each principal intended to process the JWT MUST
    identify itself with a value in the audience claim.  If the principal
    processing the claim does not identify itself with a value in the
    "aud" claim when this claim is present, then the JWT MUST be
    rejected.  In the general case, the "aud" value is an array of case-
    sensitive strings, each containing a StringOrURI value.  In the
    special case when the JWT has one audience, the "aud" value MAY be a
    single case-sensitive string containing a StringOrURI value.  The
    interpretation of audience values is generally application specific.
    Use of this claim is OPTIONAL.
    """
    EXP = "exp"
    """The "exp" (expiration time) claim identifies the expiration time on
    or after which the JWT MUST NOT be accepted for processing.  The
    processing of the "exp" claim requires that the current date/time
    MUST be before the expiration date/time listed in the "exp" claim.
    Implementers MAY provide for some small leeway, usually no more than
    a few minutes, to account for clock skew.  Its value MUST be a number
    containing a NumericDate value.  Use of this claim is OPTIONAL.
    """
    NBF = "nbf"
    """The "nbf" (not before) claim identifies the time before which the JWT
    MUST NOT be accepted for processing.  The processing of the "nbf"
    claim requires that the current date/time MUST be after or equal to
    the not-before date/time listed in the "nbf" claim.  Implementers MAY
    provide for some small leeway, usually no more than a few minutes, to
    account for clock skew.  Its value MUST be a number containing a
    NumericDate value.  Use of this claim is OPTIONAL.
    """
    IAT = "iat"
    """The "iat" (issued at) claim identifies the time at which the JWT was
    issued.  This claim can be used to determine the age of the JWT.  Its
    value MUST be a number containing a NumericDate value.  Use of this
    claim is OPTIONAL.
    """
    JTI = "jti"
    """The "jti" (JWT ID) claim provides a unique identifier for the JWT.
    The identifier value MUST be assigned in a manner that ensures that
    there is a negligible probability that the same value will be
    accidentally assigned to a different data object; if the application
    uses multiple issuers, collisions MUST be prevented among values
    produced by different issuers as well.  The "jti" claim can be used
    to prevent the JWT from being replayed.  The "jti" value is a case-
    sensitive string.  Use of this claim is OPTIONAL.
    """


class JwtClaimsPub(StrEnum):
    """JWt Pub Claims.

    See: https://www.iana.org/assignments/jwt/jwt.xhtml
    """

    EMAIL = "email"
    """Preferred e-mail address."""
    EMAIL_VERIFIED = "email_verified"
    """True if the e-mail address has been verified; otherwise false."""
    NAME = "name"
    """Full name."""
    GIVEN_NAME = "given_name"
    """Given name(s) or first name(s)."""
    FAMILY_NAME = "family_name"
    """Surname(s) or last name(s)."""


class JwtClaimsPrv(StrEnum):
    """Define private JWT claims specific to you project / application.

    > a5c - just example project code.

    This class should not be part of the library, ideally.
    """

    A5C_ENV = "a5c_env"
    """Int values describing environment for A5C_ENV claim:
    - 110 - production
    - 120 - sandbox
    - 130 - staging
    - 140 - testing
    - 150 - dev if applicable
    - 2xx - local dev environments
    - 910 - POC render
    """
    A5C_ACT_TYPE = "a5c_act_type"
    """A5c user account type.

    Values: one of enum constant defined in `UserAccountType`.
    """
    A5C_TOKEN_TYPE = "a5c_token_type"
    """Token type: access or refresh.

    Use enum constants from `JwtTokenType`.
    """


type JwtClaimsUnion = JwtClaimsStd | JwtClaimsPub | JwtClaimsPrv

type JwtClaimsData = dict[JwtClaimsUnion, Any]
