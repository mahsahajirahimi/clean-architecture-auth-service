from auth_service.modules.identity.application.ports import UserRepository
from auth_service.modules.identity.application.use_cases._pagination import (
    validate_pagination,
)
from auth_service.modules.identity.domain.entities.user import User


class ListUsers:
    def __init__(self, users: UserRepository):
        self.users = users

    def execute(self, limit: int = 50, offset: int = 0) -> list[User]:
        validate_pagination(limit, offset)
        return self.users.list(limit, offset)
