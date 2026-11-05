from collections.abc import Callable
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response

from auth_service.modules.identity.application.use_cases.get_group import GetGroup
from auth_service.modules.identity.application.use_cases.get_user import GetUser
from auth_service.modules.identity.application.use_cases.list_group_members import (
    ListGroupMembers,
)
from auth_service.modules.identity.application.use_cases.list_groups import ListGroups
from auth_service.modules.identity.application.use_cases.list_user_groups import (
    ListUserGroups,
)
from auth_service.modules.identity.application.use_cases.list_users import ListUsers
from auth_service.modules.identity.application.use_cases.remove_user_from_group import (
    RemoveUserFromGroup,
)
from auth_service.modules.identity.application.use_cases.set_user_status import (
    SetUserStatus,
)
from auth_service.modules.identity.domain.entities.user import User
from auth_service.modules.identity.presentation.schemas import (
    GroupResponse,
    SetUserStatusRequest,
    UserResponse,
)


def create_management_router(
    administrator_dependency: Callable[..., User],
    get_user_dependency: Callable[..., GetUser],
    list_users_dependency: Callable[..., ListUsers],
    get_group_dependency: Callable[..., GetGroup],
    list_groups_dependency: Callable[..., ListGroups],
    set_status_dependency: Callable[..., SetUserStatus],
    remove_member_dependency: Callable[..., RemoveUserFromGroup],
    user_groups_dependency: Callable[..., ListUserGroups],
    group_members_dependency: Callable[..., ListGroupMembers],
) -> APIRouter:
    router = APIRouter(
        tags=["Identity administration"],
        dependencies=[Depends(administrator_dependency)],
    )

    @router.get("/users", response_model=list[UserResponse])
    def list_users(
        response: Response,
        use_case: Annotated[ListUsers, Depends(list_users_dependency)],
        limit: Annotated[int, Query(ge=1, le=100)] = 50,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> list[UserResponse]:
        users = use_case.execute(limit, offset)
        response.headers["Cache-Control"] = "no-store"
        return [
            UserResponse(id=user.id, username=user.username, is_active=user.is_active)
            for user in users
        ]

    @router.get("/users/{user_id}", response_model=UserResponse)
    def get_user(
        user_id: UUID,
        response: Response,
        use_case: Annotated[GetUser, Depends(get_user_dependency)],
    ) -> UserResponse:
        user = use_case.execute(user_id)
        response.headers["Cache-Control"] = "no-store"
        return UserResponse(
            id=user.id, username=user.username, is_active=user.is_active
        )

    @router.get("/groups", response_model=list[GroupResponse])
    def list_groups(
        response: Response,
        use_case: Annotated[ListGroups, Depends(list_groups_dependency)],
        limit: Annotated[int, Query(ge=1, le=100)] = 50,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> list[GroupResponse]:
        groups = use_case.execute(limit, offset)
        response.headers["Cache-Control"] = "no-store"
        return [GroupResponse(id=group.id, name=group.name) for group in groups]

    @router.get("/groups/{group_id}", response_model=GroupResponse)
    def get_group(
        group_id: UUID,
        response: Response,
        use_case: Annotated[GetGroup, Depends(get_group_dependency)],
    ) -> GroupResponse:
        group = use_case.execute(group_id)
        response.headers["Cache-Control"] = "no-store"
        return GroupResponse(id=group.id, name=group.name)

    @router.patch("/users/{user_id}/status", response_model=UserResponse)
    def set_status(
        user_id: UUID,
        body: SetUserStatusRequest,
        response: Response,
        use_case: Annotated[SetUserStatus, Depends(set_status_dependency)],
    ) -> UserResponse:
        user = use_case.execute(user_id, body.is_active)
        response.headers["Cache-Control"] = "no-store"
        return UserResponse(
            id=user.id, username=user.username, is_active=user.is_active
        )

    @router.delete("/groups/{group_id}/members/{user_id}", status_code=204)
    def remove_member(
        group_id: UUID,
        user_id: UUID,
        use_case: Annotated[RemoveUserFromGroup, Depends(remove_member_dependency)],
    ) -> Response:
        use_case.execute(user_id, group_id)
        return Response(status_code=204, headers={"Cache-Control": "no-store"})

    @router.get("/users/{user_id}/groups", response_model=list[GroupResponse])
    def user_groups(
        user_id: UUID,
        response: Response,
        use_case: Annotated[ListUserGroups, Depends(user_groups_dependency)],
        limit: Annotated[int, Query(ge=1, le=100)] = 50,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> list[GroupResponse]:
        groups = use_case.execute(user_id, limit, offset)
        response.headers["Cache-Control"] = "no-store"
        return [GroupResponse(id=g.id, name=g.name) for g in groups]

    @router.get("/groups/{group_id}/members", response_model=list[UserResponse])
    def group_members(
        group_id: UUID,
        response: Response,
        use_case: Annotated[ListGroupMembers, Depends(group_members_dependency)],
        limit: Annotated[int, Query(ge=1, le=100)] = 50,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> list[UserResponse]:
        users = use_case.execute(group_id, limit, offset)
        response.headers["Cache-Control"] = "no-store"
        return [
            UserResponse(id=u.id, username=u.username, is_active=u.is_active)
            for u in users
        ]

    return router
