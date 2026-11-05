from collections.abc import Callable, Iterator
from typing import Annotated
from uuid import UUID

from fastapi import Depends, FastAPI
from sqlalchemy.orm import Session

from auth_service.modules.access_control.application.use_cases.assign_grant import (
    AssignGrant,
)
from auth_service.modules.access_control.application.use_cases.check_access import (
    CheckAccess,
)
from auth_service.modules.access_control.application.use_cases.create_permission import (
    CreatePermission,
)
from auth_service.modules.access_control.application.use_cases.create_scope import (
    CreateScope,
)
from auth_service.modules.access_control.application.use_cases.get_effective_permissions import (
    GetEffectivePermissions,
)
from auth_service.modules.access_control.application.use_cases.list_grants import (
    ListGrants,
)
from auth_service.modules.access_control.application.use_cases.list_permissions import (
    ListPermissions,
)
from auth_service.modules.access_control.application.use_cases.list_scopes import (
    ListScopes,
)
from auth_service.modules.access_control.application.use_cases.revoke_grant import (
    RevokeGrant,
)
from auth_service.modules.access_control.infrastructure.identity_reader import (
    IdentityReaderAdapter,
)
from auth_service.modules.access_control.infrastructure.persistence.repositories import (
    SqlAlchemyGrantRepository,
    SqlAlchemyPermissionRepository,
    SqlAlchemyScopeRepository,
)
from auth_service.modules.access_control.presentation.admin_routes import (
    create_admin_router,
)
from auth_service.modules.access_control.presentation.errors import (
    register_access_control_errors,
)
from auth_service.modules.access_control.presentation.routes import create_self_router
from auth_service.modules.identity.application.access_queries import (
    IdentityAccessQueries,
)
from auth_service.modules.identity.infrastructure.persistence.repositories import (
    SqlAlchemyGroupRepository,
    SqlAlchemyMembershipRepository,
    SqlAlchemyUserRepository,
)


def make_identity_reader(session: Session) -> IdentityReaderAdapter:
    return IdentityReaderAdapter(
        IdentityAccessQueries(
            SqlAlchemyUserRepository(session),
            SqlAlchemyGroupRepository(session),
            SqlAlchemyMembershipRepository(session),
        )
    )


def configure_access_control(
    app: FastAPI,
    session_dependency: Callable[..., Iterator[Session]],
    current_user_id_dependency: Callable[..., UUID],
    administrator_dependency: Callable[..., object],
) -> None:
    # Reusing the same session dependency shares the request transaction with Identity.
    SessionDependency = Annotated[
        Session, Depends(session_dependency, scope="function")
    ]

    def get_create_scope(session: SessionDependency) -> CreateScope:
        return CreateScope(SqlAlchemyScopeRepository(session))

    def get_list_scopes(session: SessionDependency) -> ListScopes:
        return ListScopes(SqlAlchemyScopeRepository(session))

    def get_create_permission(session: SessionDependency) -> CreatePermission:
        return CreatePermission(
            SqlAlchemyScopeRepository(session), SqlAlchemyPermissionRepository(session)
        )

    def get_list_permissions(session: SessionDependency) -> ListPermissions:
        return ListPermissions(
            SqlAlchemyScopeRepository(session), SqlAlchemyPermissionRepository(session)
        )

    def get_assign_grant(session: SessionDependency) -> AssignGrant:
        return AssignGrant(
            SqlAlchemyScopeRepository(session),
            SqlAlchemyPermissionRepository(session),
            SqlAlchemyGrantRepository(session),
            make_identity_reader(session),
        )

    def get_revoke_grant(session: SessionDependency) -> RevokeGrant:
        return RevokeGrant(SqlAlchemyGrantRepository(session))

    def get_effective(session: SessionDependency) -> GetEffectivePermissions:
        return GetEffectivePermissions(
            SqlAlchemyScopeRepository(session),
            SqlAlchemyPermissionRepository(session),
            SqlAlchemyGrantRepository(session),
            make_identity_reader(session),
        )

    def get_check_access(
        effective: Annotated[GetEffectivePermissions, Depends(get_effective)]
    ) -> CheckAccess:
        return CheckAccess(effective)

    def get_list_grants(session: SessionDependency) -> ListGrants:
        return ListGrants(SqlAlchemyGrantRepository(session))

    app.include_router(
        create_admin_router(
            administrator_dependency,
            get_create_scope,
            get_list_scopes,
            get_create_permission,
            get_list_permissions,
            get_assign_grant,
            get_revoke_grant,
            get_effective,
            get_check_access,
            get_list_grants,
        )
    )
    app.include_router(
        create_self_router(current_user_id_dependency, get_effective, get_check_access)
    )
    register_access_control_errors(app)
