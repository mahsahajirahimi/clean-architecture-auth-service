from collections.abc import Callable
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response

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
from auth_service.modules.access_control.application.use_cases.list_permissions import (
    ListPermissions,
)
from auth_service.modules.access_control.application.use_cases.list_scopes import (
    ListScopes,
)
from auth_service.modules.access_control.application.use_cases.revoke_grant import (
    RevokeGrant,
)
from auth_service.modules.access_control.domain.entities.grant import (
    GrantTargetType,
    SubjectType,
)
from auth_service.modules.access_control.presentation.schemas import (
    CheckAccessRequest,
    CheckAccessResponse,
    CreatePermissionRequest,
    CreateScopeRequest,
    EffectivePermissionsResponse,
    GrantRequest,
    GrantResponse,
    PermissionResponse,
    ScopeResponse,
)


def create_admin_router(
    administrator_dependency: Callable[..., object],
    create_scope_dependency: Callable[..., CreateScope],
    list_scopes_dependency: Callable[..., ListScopes],
    create_permission_dependency: Callable[..., CreatePermission],
    list_permissions_dependency: Callable[..., ListPermissions],
    assign_dependency: Callable[..., AssignGrant],
    revoke_dependency: Callable[..., RevokeGrant],
    effective_dependency: Callable[..., GetEffectivePermissions],
    check_dependency: Callable[..., CheckAccess],
) -> APIRouter:
    router = APIRouter(
        prefix="/access-control",
        tags=["Access Control administration"],
        dependencies=[Depends(administrator_dependency)],
    )

    @router.post("/scopes", response_model=ScopeResponse, status_code=201)
    def create_scope(
        body: CreateScopeRequest,
        response: Response,
        use_case: Annotated[CreateScope, Depends(create_scope_dependency)],
    ) -> ScopeResponse:
        scope = use_case.execute(body.name)
        response.headers["Cache-Control"] = "no-store"
        return ScopeResponse(id=scope.id, name=scope.name)

    @router.get("/scopes", response_model=list[ScopeResponse])
    def list_scopes(
        response: Response,
        use_case: Annotated[ListScopes, Depends(list_scopes_dependency)],
        limit: Annotated[int, Query(ge=1, le=100)] = 50,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> list[ScopeResponse]:
        scopes = use_case.execute(limit, offset)
        response.headers["Cache-Control"] = "no-store"
        return [ScopeResponse(id=scope.id, name=scope.name) for scope in scopes]

    @router.post(
        "/scopes/{scope_id}/permissions",
        response_model=PermissionResponse,
        status_code=201,
    )
    def create_permission(
        scope_id: UUID,
        body: CreatePermissionRequest,
        response: Response,
        use_case: Annotated[CreatePermission, Depends(create_permission_dependency)],
    ) -> PermissionResponse:
        permission = use_case.execute(scope_id, body.name)
        response.headers["Cache-Control"] = "no-store"
        return PermissionResponse(
            id=permission.id, scope_id=permission.scope_id, name=permission.name
        )

    @router.get(
        "/scopes/{scope_id}/permissions", response_model=list[PermissionResponse]
    )
    def list_permissions(
        scope_id: UUID,
        response: Response,
        use_case: Annotated[ListPermissions, Depends(list_permissions_dependency)],
        limit: Annotated[int, Query(ge=1, le=100)] = 50,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> list[PermissionResponse]:
        permissions = use_case.execute(scope_id, limit, offset)
        response.headers["Cache-Control"] = "no-store"
        return [
            PermissionResponse(id=p.id, scope_id=p.scope_id, name=p.name)
            for p in permissions
        ]

    @router.post("/grants", response_model=GrantResponse, status_code=201)
    def assign_grant(
        body: GrantRequest,
        response: Response,
        use_case: Annotated[AssignGrant, Depends(assign_dependency)],
    ) -> GrantResponse:
        grant = use_case.execute(
            body.subject_type, body.subject_id, body.target_type, body.target_id
        )
        response.headers["Cache-Control"] = "no-store"
        return GrantResponse(
            subject_type=grant.subject_type,
            subject_id=grant.subject_id,
            target_type=grant.target_type,
            target_id=grant.target_id,
        )

    @router.delete(
        "/grants/{subject_type}/{subject_id}/{target_type}/{target_id}", status_code=204
    )
    def revoke_grant(
        subject_type: SubjectType,
        subject_id: UUID,
        target_type: GrantTargetType,
        target_id: UUID,
        use_case: Annotated[RevokeGrant, Depends(revoke_dependency)],
    ) -> Response:
        use_case.execute(subject_type, subject_id, target_type, target_id)
        return Response(status_code=204, headers={"Cache-Control": "no-store"})

    @router.get(
        "/users/{user_id}/permissions", response_model=EffectivePermissionsResponse
    )
    def effective_permissions(
        user_id: UUID,
        response: Response,
        use_case: Annotated[GetEffectivePermissions, Depends(effective_dependency)],
    ) -> EffectivePermissionsResponse:
        permission_ids = use_case.execute(user_id)
        response.headers["Cache-Control"] = "no-store"
        return EffectivePermissionsResponse(
            user_id=user_id, permission_ids=sorted(permission_ids, key=str)
        )

    @router.post("/users/{user_id}/check", response_model=CheckAccessResponse)
    def check_access(
        user_id: UUID,
        body: CheckAccessRequest,
        response: Response,
        use_case: Annotated[CheckAccess, Depends(check_dependency)],
    ) -> CheckAccessResponse:
        allowed = use_case.execute(user_id, body.permission_id)
        response.headers["Cache-Control"] = "no-store"
        return CheckAccessResponse(
            user_id=user_id, permission_id=body.permission_id, allowed=allowed
        )

    return router
