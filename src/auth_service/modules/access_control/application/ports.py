from typing import Protocol
from uuid import UUID

from auth_service.modules.access_control.application.dto import UserAccessContext
from auth_service.modules.access_control.domain.entities.grant import Grant
from auth_service.modules.access_control.domain.entities.permission import Permission
from auth_service.modules.access_control.domain.entities.scope import Scope


class ScopeRepository(Protocol):
    def get_by_id(self, scope_id: UUID) -> Scope | None: ...

    def get_by_name(self, name: str) -> Scope | None: ...

    def list_all(self) -> list[Scope]: ...

    def save(self, scope: Scope) -> None: ...


class PermissionRepository(Protocol):
    def get_by_id(self, permission_id: UUID) -> Permission | None: ...

    def get_by_scope_and_name(self, scope_id: UUID, name: str) -> Permission | None: ...

    def list_all(self) -> list[Permission]: ...

    def save(self, permission: Permission) -> None: ...


class GrantRepository(Protocol):
    def exists(self, grant: Grant) -> bool: ...

    def save(self, grant: Grant) -> None: ...

    def remove(self, grant: Grant) -> bool: ...

    def list_for_user(
        self, user_id: UUID, group_ids: frozenset[UUID]
    ) -> list[Grant]: ...


class IdentityReader(Protocol):
    """Current Identity data, supplied through an adapter in a later stage."""

    def get_user_context(self, user_id: UUID) -> UserAccessContext | None: ...

    def group_exists(self, group_id: UUID) -> bool: ...
