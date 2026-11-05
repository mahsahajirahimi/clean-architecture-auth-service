from uuid import UUID

from auth_service.modules.access_control.application.exceptions import (
    ScopeNotFoundError,
)
from auth_service.modules.access_control.application.ports import (
    PermissionRepository,
    ScopeRepository,
)
from auth_service.modules.access_control.application.use_cases._validation import (
    require_uuid,
    validate_pagination,
)
from auth_service.modules.access_control.domain.entities.permission import Permission


class ListPermissions:
    def __init__(self, scopes: ScopeRepository, permissions: PermissionRepository):
        self.scopes = scopes
        self.permissions = permissions

    def execute(
        self, scope_id: UUID, limit: int = 50, offset: int = 0
    ) -> list[Permission]:
        require_uuid(scope_id, "Scope ID")
        validate_pagination(limit, offset)
        if self.scopes.get_by_id(scope_id) is None:
            raise ScopeNotFoundError("Scope not found")
        return self.permissions.list_by_scope(scope_id, limit, offset)
