from auth_service.modules.identity.application.exceptions import (
    AdministratorRequiredError,
)
from auth_service.modules.identity.application.ports import AdministratorRepository
from auth_service.modules.identity.domain.entities.user import User


class RequireAdministrator:
    def __init__(self, administrators: AdministratorRepository):
        self.administrators = administrators

    def execute(self, user: User) -> User:
        if not user.is_active or self.administrators.get_user_id() != user.id:
            raise AdministratorRequiredError("Administrator access required")
        return user
