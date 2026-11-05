from uuid import UUID, uuid4

from auth_service.modules.access_control.application.exceptions import (
    DuplicatePermissionError,
    ScopeNotFoundError,
)
from auth_service.modules.access_control.application.ports import (
    PermissionRepository,
    ScopeRepository,
)
from auth_service.modules.access_control.application.use_cases._validation import (
    normalize_name,
    require_uuid,
)
from auth_service.modules.access_control.domain.entities.permission import Permission


class CreatePermission:
    def __init__(self, scopes: ScopeRepository, permissions: PermissionRepository):
        self.scopes = scopes
        self.permissions = permissions

    def execute(self, scope_id: UUID, name: str) -> Permission:
        require_uuid(scope_id, "Scope ID")
        name = normalize_name(name, "Permission name")
        if self.scopes.get_by_id(scope_id) is None:
            raise ScopeNotFoundError("Scope not found")
        if self.permissions.get_by_scope_and_name(scope_id, name) is not None:
            raise DuplicatePermissionError(
                "Permission name already exists in this scope"
            )
        permission = Permission(uuid4(), scope_id, name)
        self.permissions.save(permission)
        return permission
