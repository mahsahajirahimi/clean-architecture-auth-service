from dataclasses import dataclass, field
from uuid import UUID


@dataclass(frozen=True, slots=True)
class IssuedAccessToken:
    access_token: str = field(repr=False)
    expires_in: int


@dataclass(frozen=True, slots=True)
class IdentityUserContext:
    user_id: UUID
    is_active: bool
    group_ids: frozenset[UUID]
