from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from auth_service.modules.access_control.application.exceptions import (
    AccessControlError,
    DuplicatePermissionError,
    DuplicateScopeError,
    GrantAlreadyExistsError,
    GrantNotFoundError,
    InvalidInputError,
    PermissionNotFoundError,
    ScopeNotFoundError,
    SubjectNotFoundError,
    UserNotFoundError,
)


def register_access_control_errors(app: FastAPI) -> None:
    statuses = {
        InvalidInputError: 400,
        DuplicateScopeError: 409,
        DuplicatePermissionError: 409,
        GrantAlreadyExistsError: 409,
        ScopeNotFoundError: 404,
        PermissionNotFoundError: 404,
        SubjectNotFoundError: 404,
        GrantNotFoundError: 404,
        UserNotFoundError: 404,
    }

    @app.exception_handler(AccessControlError)
    async def access_control_error(request: Request, error: AccessControlError):
        status = statuses.get(type(error), 500)
        detail = str(error) if status != 500 else "Access control operation failed"
        return JSONResponse(
            status_code=status,
            content={"detail": detail},
            headers={"Cache-Control": "no-store"},
        )
