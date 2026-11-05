from collections.abc import Iterable
from uuid import UUID

from auth_service.modules.access_control.domain._validation import require_uuid
from auth_service.modules.access_control.domain.entities.grant import (
    Grant,
    GrantTargetType,
    SubjectType,
)
from auth_service.modules.access_control.domain.entities.permission import Permission
from auth_service.modules.access_control.domain.entities.scope import Scope


class AccessPolicy:
    """Evaluate a current snapshot; scope grants cover all permissions in the scope.

    No database access, cross-module imports, or cached authorization decisions.
    The application supplies current user status, memberships, catalog, and grants.
    """

    def effective_permissions(
        self,
        *,
        user_id: UUID,
        user_is_active: bool,
        group_ids: Iterable[UUID],
        scopes: Iterable[Scope],
        permissions: Iterable[Permission],
        grants: Iterable[Grant],
    ) -> frozenset[UUID]:
        require_uuid(user_id, "User ID")
        if type(user_is_active) is not bool:
            raise ValueError("User active status must be a boolean")
        if not user_is_active:
            return frozenset()

        groups = frozenset(group_ids)
        for group_id in groups:
            require_uuid(group_id, "Group ID")
        scope_ids = {scope.id for scope in scopes}
        # Missing/deleted catalog entries cannot confer access via stale grants.
        catalog = [
            permission for permission in permissions if permission.scope_id in scope_ids
        ]
        granted_scopes: set[UUID] = set()
        granted_permissions: set[UUID] = set()
        for grant in grants:
            applies = (
                grant.subject_type == SubjectType.USER and grant.subject_id == user_id
            ) or (
                grant.subject_type == SubjectType.GROUP and grant.subject_id in groups
            )
            if not applies:
                continue
            if grant.target_type == GrantTargetType.SCOPE:
                granted_scopes.add(grant.target_id)
            else:
                granted_permissions.add(grant.target_id)
        return frozenset(
            permission.id
            for permission in catalog
            if permission.id in granted_permissions
            or permission.scope_id in granted_scopes
        )

    def allows(
        self,
        permission_id: UUID,
        *,
        user_id: UUID,
        user_is_active: bool,
        group_ids: Iterable[UUID],
        scopes: Iterable[Scope],
        permissions: Iterable[Permission],
        grants: Iterable[Grant],
    ) -> bool:
        require_uuid(permission_id, "Permission ID")
        return permission_id in self.effective_permissions(
            user_id=user_id,
            user_is_active=user_is_active,
            group_ids=group_ids,
            scopes=scopes,
            permissions=permissions,
            grants=grants,
        )
