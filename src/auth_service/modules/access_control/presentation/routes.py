from collections.abc import Callable
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Response

from auth_service.modules.access_control.application.use_cases.check_access import (
    CheckAccess,
)
from auth_service.modules.access_control.application.use_cases.get_effective_permissions import (
    GetEffectivePermissions,
)
from auth_service.modules.access_control.presentation.schemas import (
    CheckAccessRequest,
    CheckAccessResponse,
    EffectivePermissionsResponse,
)


def create_self_router(
    current_user_id_dependency: Callable[..., UUID],
    effective_dependency: Callable[..., GetEffectivePermissions],
    check_dependency: Callable[..., CheckAccess],
) -> APIRouter:
    router = APIRouter(prefix="/access-control/me", tags=["My access"])

    @router.get("/permissions", response_model=EffectivePermissionsResponse)
    def effective_permissions(
        response: Response,
        user_id: Annotated[UUID, Depends(current_user_id_dependency)],
        use_case: Annotated[GetEffectivePermissions, Depends(effective_dependency)],
    ) -> EffectivePermissionsResponse:
        permission_ids = use_case.execute(user_id)
        response.headers["Cache-Control"] = "no-store"
        return EffectivePermissionsResponse(
            user_id=user_id, permission_ids=sorted(permission_ids, key=str)
        )

    @router.post("/check", response_model=CheckAccessResponse)
    def check_access(
        body: CheckAccessRequest,
        response: Response,
        user_id: Annotated[UUID, Depends(current_user_id_dependency)],
        use_case: Annotated[CheckAccess, Depends(check_dependency)],
    ) -> CheckAccessResponse:
        allowed = use_case.execute(user_id, body.permission_id)
        response.headers["Cache-Control"] = "no-store"
        return CheckAccessResponse(
            user_id=user_id, permission_id=body.permission_id, allowed=allowed
        )

    return router
