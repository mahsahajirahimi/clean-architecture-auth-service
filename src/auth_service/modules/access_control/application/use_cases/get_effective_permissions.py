from uuid import UUID

from auth_service.modules.access_control.application.exceptions import (
    IdentityContextError,
    UserNotFoundError,
)
from auth_service.modules.access_control.application.ports import (
    GrantRepository,
    IdentityReader,
    PermissionRepository,
    ScopeRepository,
)
from auth_service.modules.access_control.application.use_cases._validation import (
    require_uuid,
)
from auth_service.modules.access_control.domain.policy import AccessPolicy


class GetEffectivePermissions:
    def __init__(
        self,
        scopes: ScopeRepository,
        permissions: PermissionRepository,
        grants: GrantRepository,
        identity: IdentityReader,
    ):
        self.scopes = scopes
        self.permissions = permissions
        self.grants = grants
        self.identity = identity
        self.policy = AccessPolicy()

    def execute(self, user_id: UUID) -> frozenset[UUID]:
        require_uuid(user_id, "User ID")
        context = self.identity.get_user_context(user_id)
        if context is None:
            raise UserNotFoundError("User not found")
        if context.user_id != user_id:
            raise IdentityContextError(
                "Identity reader returned unexpected user context"
            )
        if not context.is_active:
            return frozenset()
        return self.policy.effective_permissions(
            user_id=user_id,
            user_is_active=context.is_active,
            group_ids=context.group_ids,
            scopes=self.scopes.list_all(),
            permissions=self.permissions.list_all(),
            grants=self.grants.list_for_user(user_id, context.group_ids),
        )
