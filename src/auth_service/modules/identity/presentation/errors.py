from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from auth_service.modules.identity.application.exceptions import (
    AdministratorRequiredError,
    AuthenticationError,
    DataConflictError,
    DuplicateGroupError,
    DuplicateUsernameError,
    GroupNotFoundError,
    InvalidInputError,
    MembershipAlreadyExistsError,
    UserNotFoundError,
)


def register_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(AuthenticationError)
    async def authentication_error(request: Request, error: AuthenticationError):
        return JSONResponse(
            status_code=401,
            content={"detail": "Authentication failed"},
            headers={"WWW-Authenticate": "Bearer", "Cache-Control": "no-store"},
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, error: RequestValidationError):
        # FastAPI's default validation detail includes rejected input values.
        # Never echo a submitted password or token in a validation response.
        details = [
            {"loc": item["loc"], "msg": item["msg"], "type": item["type"]}
            for item in error.errors()
        ]
        return JSONResponse(status_code=422, content={"detail": details})

    statuses = {
        AdministratorRequiredError: 403,
        InvalidInputError: 400,
        DuplicateUsernameError: 409,
        DuplicateGroupError: 409,
        MembershipAlreadyExistsError: 409,
        DataConflictError: 409,
        UserNotFoundError: 404,
        GroupNotFoundError: 404,
    }

    async def identity_error(request: Request, error: Exception):
        return JSONResponse(
            status_code=statuses[type(error)],
            content={"detail": str(error)},
            headers={"Cache-Control": "no-store"},
        )

    for exception_class in statuses:
        app.add_exception_handler(exception_class, identity_error)
