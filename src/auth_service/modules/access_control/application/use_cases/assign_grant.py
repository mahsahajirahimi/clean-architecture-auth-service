from uuid import UUID

from auth_service.modules.access_control.application.exceptions import (
    GrantAlreadyExistsError,
    IdentityContextError,
    PermissionNotFoundError,
    ScopeNotFoundError,
    SubjectNotFoundError,
)
from auth_service.modules.access_control.application.ports import (
    GrantRepository,
    IdentityReader,
    PermissionRepository,
    ScopeRepository,
)
from auth_service.modules.access_control.application.use_cases._validation import (
    make_grant,
)
from auth_service.modules.access_control.domain.entities.grant import (
    Grant,
    GrantTargetType,
    SubjectType,
)


class AssignGrant:
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

    def execute(
        self,
        subject_type: SubjectType,
        subject_id: UUID,
        target_type: GrantTargetType,
        target_id: UUID,
    ) -> Grant:
        grant = make_grant(subject_type, subject_id, target_type, target_id)
        if subject_type == SubjectType.USER:
            context = self.identity.get_user_context(subject_id)
            if context is None:
                raise SubjectNotFoundError("Grant subject not found")
            if context.user_id != subject_id:
                raise IdentityContextError(
                    "Identity reader returned unexpected user context"
                )
        elif not self.identity.group_exists(subject_id):
            raise SubjectNotFoundError("Grant subject not found")

        if target_type == GrantTargetType.SCOPE:
            scope_id = target_id
        else:
            permission = self.permissions.get_by_id(target_id)
            if permission is None:
                raise PermissionNotFoundError("Permission not found")
            scope_id = permission.scope_id
        if self.scopes.get_by_id(scope_id) is None:
            raise ScopeNotFoundError("Scope not found")
        if self.grants.exists(grant):
            raise GrantAlreadyExistsError("Grant already exists")
        self.grants.save(grant)
        return grant
