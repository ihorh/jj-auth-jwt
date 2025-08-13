from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum, auto


class UserIdentificationProvider(StrEnum):
    """Supported authentication providers."""

    GOOGLE = auto()


@dataclass(frozen=True, slots=True)
class BaseIdentifiedUserInfo:
    """Base class for identified user info class hierarchy.

    Identified user info classes are not data model or REST API models.
    They are internal API data transfer classes
    """

    id_provider: UserIdentificationProvider
    id_issuer: str  # assume there can be different isssuers from same provider
    user_id: str
    email: str  # TODO (ihor): | None
    email_verified: bool  # TODO (ihor): | None
    display_name: str | None
    first_name: str | None
    last_name: str | None


@dataclass(frozen=True, slots=True)
class BaseJwtIdentifiedUserInfo(BaseIdentifiedUserInfo):
    """Base class for info about token based user identification."""

    identification_audience: str
    issued_at: datetime
    expires_at: datetime
