
from uuid import uuid4

from auth_service.modules.identity.application.exceptions import (
    DuplicateUsernameError,
    InvalidInputError,
)
from auth_service.modules.identity.application.ports import (
    PasswordHasher,
    UserRepository,
)
from auth_service.modules.identity.domain.entities.user import User


class CreateUser:
    def __init__(
        self,
        users: UserRepository,
        password_hasher: PasswordHasher,
    ):
        self.users = users
        self.password_hasher = password_hasher

    def execute(self, username: str, password: str) -> User:
        if not isinstance(username, str) or not username.strip():
            raise InvalidInputError("Username cannot be empty")

        if not isinstance(password, str) or not password.strip():
            raise InvalidInputError("Password cannot be empty")

        username = username.strip()
        if len(username) > 255:
            raise InvalidInputError("Username must not exceed 255 characters")
        if len(password) > 1024:
            raise InvalidInputError("Password must not exceed 1024 characters")

        if self.users.get_by_username(username) is not None:
            raise DuplicateUsernameError("Username already exists")

        user = User(
            id=uuid4(),
            username=username,
            password_hash=self.password_hasher.hash(password),
        )

        self.users.save(user)

        return user
