from uuid import UUID

from auth_service.modules.access_control.application.use_cases._validation import (
    require_uuid,
)
from auth_service.modules.access_control.application.use_cases.get_effective_permissions import (
    GetEffectivePermissions,
)


class CheckAccess:
    def __init__(self, effective_permissions: GetEffectivePermissions):
        self.effective_permissions = effective_permissions

    def execute(self, user_id: UUID, permission_id: UUID) -> bool:
        require_uuid(permission_id, "Permission ID")
        return permission_id in self.effective_permissions.execute(user_id)
