from collections.abc import Callable
from typing import Annotated

from fastapi import APIRouter, Depends, Response

from auth_service.modules.identity.application.use_cases.login import Login
from auth_service.modules.identity.domain.entities.user import User
from auth_service.modules.identity.presentation.schemas import (
    LoginRequest,
    TokenResponse,
    UserResponse,
)


def create_router(
    login_dependency: Callable[..., Login],
    current_user_dependency: Callable[..., User],
) -> APIRouter:
    router = APIRouter(prefix="/auth", tags=["Authentication"])

    @router.post("/login", response_model=TokenResponse)
    def login(
        body: LoginRequest,
        response: Response,
        use_case: Annotated[Login, Depends(login_dependency)],
    ) -> TokenResponse:
        result = use_case.execute(body.username, body.password.get_secret_value())
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        return TokenResponse(
            access_token=result.access_token, expires_in=result.expires_in
        )

    @router.get("/me", response_model=UserResponse)
    def me(
        response: Response,
        user: Annotated[User, Depends(current_user_dependency)],
    ) -> UserResponse:
        response.headers["Cache-Control"] = "no-store"
        return UserResponse(
            id=user.id, username=user.username, is_active=user.is_active
        )

    return router
