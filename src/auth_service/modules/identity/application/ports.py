
from typing import Protocol
from uuid import UUID

from auth_service.modules.identity.application.dto import IssuedAccessToken
from auth_service.modules.identity.domain.entities.group import Group
from auth_service.modules.identity.domain.entities.membership import GroupMembership
from auth_service.modules.identity.domain.entities.user import User


class UserRepository(Protocol):
    def get_by_id(self, user_id: UUID) -> User | None:
        ...

    def get_by_username(self, username: str) -> User | None:
        ...

    def list(self, limit: int, offset: int) -> list[User]:
        ...

    def save(self, user: User) -> None:
        ...


class GroupRepository(Protocol):
    def get_by_id(self, group_id: UUID) -> Group | None:
        ...

    def get_by_name(self, name: str) -> Group | None:
        ...

    def list(self, limit: int, offset: int) -> list[Group]:
        ...

    def save(self, group: Group) -> None:
        ...


class MembershipRepository(Protocol):
    def list_groups(self, user_id: UUID, limit: int, offset: int) -> list[Group]:
        ...

    def list_users(self, group_id: UUID, limit: int, offset: int) -> list[User]:
        ...

    def list_group_ids(self, user_id: UUID) -> frozenset[UUID]:
        ...

    def exists(self, user_id: UUID, group_id: UUID) -> bool:
        ...

    def remove(self, user_id: UUID, group_id: UUID) -> bool:
        ...

    def save(self, membership: GroupMembership) -> None:
        ...


class PasswordHasher(Protocol):
    def hash(self, password: str) -> str:
        ...

    def verify(self, password: str, password_hash: str) -> bool:
        ...


class AccessTokenIssuer(Protocol):
    def issue(self, user_id: UUID) -> IssuedAccessToken:
        ...


class AccessTokenVerifier(Protocol):
    def verify(self, access_token: str) -> UUID:
        ...


class AdministratorRepository(Protocol):
    def get_user_id(self) -> UUID | None:
        ...

    def initialize(self, user_id: UUID) -> None:
        ...
