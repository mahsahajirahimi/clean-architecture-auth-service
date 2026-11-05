from uuid import UUID

from auth_service.modules.identity.application.exceptions import (
    InvalidInputError,
    ProtectedAdministratorError,
    UserNotFoundError,
)
from auth_service.modules.identity.application.ports import (
    AdministratorRepository,
    UserRepository,
)
from auth_service.modules.identity.domain.entities.user import User


class SetUserStatus:
    def __init__(self, users: UserRepository, administrators: AdministratorRepository):
        self.users = users
        self.administrators = administrators

    def execute(self, user_id: UUID, is_active: bool) -> User:
        if type(is_active) is not bool:
            raise InvalidInputError("is_active must be a boolean")
        user = self.users.get_by_id(user_id)
        if user is None:
            raise UserNotFoundError("User not found")
        if not is_active and self.administrators.get_user_id() == user_id:
            raise ProtectedAdministratorError(
                "The initial administrator cannot be deactivated"
            )
        if user.is_active == is_active:
            return user
        updated = user.activate() if is_active else user.deactivate()
        self.users.save(updated)
        return updated
