from auth_service.modules.identity.application.exceptions import (
    BootstrapAlreadyCompletedError,
)
from auth_service.modules.identity.application.ports import (
    AdministratorRepository,
    PasswordHasher,
    UserRepository,
)
from auth_service.modules.identity.application.use_cases.create_user import CreateUser
from auth_service.modules.identity.domain.entities.user import User


class BootstrapAdministrator:
    """Create the initial administrator inside a caller-owned transaction."""

    def __init__(
        self,
        users: UserRepository,
        administrators: AdministratorRepository,
        passwords: PasswordHasher,
    ):
        self.users = users
        self.administrators = administrators
        self.passwords = passwords

    def execute(self, username: str, password: str) -> User:
        if self.administrators.get_user_id() is not None:
            raise BootstrapAlreadyCompletedError(
                "Administrator bootstrap has already completed"
            )
        user = CreateUser(self.users, self.passwords).execute(username, password)
        self.administrators.initialize(user.id)
        return user
