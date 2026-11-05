from uuid import UUID

from auth_service.modules.identity.application.exceptions import UserNotFoundError
from auth_service.modules.identity.application.ports import UserRepository
from auth_service.modules.identity.domain.entities.user import User


class GetUser:
    def __init__(self, users: UserRepository):
        self.users = users

    def execute(self, user_id: UUID) -> User:
        user = self.users.get_by_id(user_id)
        if user is None:
            raise UserNotFoundError("User not found")
        return user
