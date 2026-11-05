from auth_service.modules.identity.application.exceptions import InvalidInputError


def validate_pagination(limit: int, offset: int) -> None:
    if type(limit) is not int or not 1 <= limit <= 100:
        raise InvalidInputError("Limit must be an integer between 1 and 100")
    if type(offset) is not int or offset < 0:
        raise InvalidInputError("Offset must be a nonnegative integer")
