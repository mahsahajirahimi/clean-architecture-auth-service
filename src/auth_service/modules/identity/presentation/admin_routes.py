from collections.abc import Callable
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Response

from auth_service.modules.identity.application.use_cases.add_user_to_group import (
    AddUserToGroup,
)
from auth_service.modules.identity.application.use_cases.create_group import CreateGroup
from auth_service.modules.identity.application.use_cases.create_user import CreateUser
from auth_service.modules.identity.domain.entities.user import User
from auth_service.modules.identity.presentation.schemas import (
    AddMemberRequest,
    CreateGroupRequest,
    CreateUserRequest,
    GroupResponse,
    MembershipResponse,
    UserResponse,
)


def create_admin_router(
    administrator_dependency: Callable[..., User],
    create_user_dependency: Callable[..., CreateUser],
    create_group_dependency: Callable[..., CreateGroup],
    add_member_dependency: Callable[..., AddUserToGroup],
) -> APIRouter:
    router = APIRouter(
        tags=["Identity administration"],
        dependencies=[Depends(administrator_dependency)],
    )

    @router.post("/users", response_model=UserResponse, status_code=201)
    def create_user(
        body: CreateUserRequest,
        response: Response,
        use_case: Annotated[CreateUser, Depends(create_user_dependency)],
    ) -> UserResponse:
        user = use_case.execute(body.username, body.password.get_secret_value())
        response.headers["Cache-Control"] = "no-store"
        return UserResponse(
            id=user.id, username=user.username, is_active=user.is_active
        )

    @router.post("/groups", response_model=GroupResponse, status_code=201)
    def create_group(
        body: CreateGroupRequest,
        response: Response,
        use_case: Annotated[CreateGroup, Depends(create_group_dependency)],
    ) -> GroupResponse:
        group = use_case.execute(body.name)
        response.headers["Cache-Control"] = "no-store"
        return GroupResponse(id=group.id, name=group.name)

    @router.post(
        "/groups/{group_id}/members", response_model=MembershipResponse, status_code=201
    )
    def add_member(
        group_id: UUID,
        body: AddMemberRequest,
        response: Response,
        use_case: Annotated[AddUserToGroup, Depends(add_member_dependency)],
    ) -> MembershipResponse:
        membership = use_case.execute(body.user_id, group_id)
        response.headers["Cache-Control"] = "no-store"
        return MembershipResponse(
            user_id=membership.user_id, group_id=membership.group_id
        )

    return router
