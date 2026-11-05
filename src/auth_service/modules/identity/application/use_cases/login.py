from auth_service.modules.identity.application.dto import IssuedAccessToken
from auth_service.modules.identity.application.exceptions import InvalidCredentialsError
from auth_service.modules.identity.application.ports import (
    AccessTokenIssuer,
    PasswordHasher,
    UserRepository,
)


class Login:
    def __init__(
        self,
        users: UserRepository,
        passwords: PasswordHasher,
        tokens: AccessTokenIssuer,
        dummy_password_hash: str,
    ):
        self.users = users
        self.passwords = passwords
        self.tokens = tokens
        self.dummy_password_hash = dummy_password_hash

    def execute(self, username: str, password: str) -> IssuedAccessToken:
        if not isinstance(username, str) or not username.strip():
            raise InvalidCredentialsError("Invalid credentials")
        if not isinstance(password, str) or not password:
            raise InvalidCredentialsError("Invalid credentials")

        user = self.users.get_by_username(username.strip())
        # Verify even for unknown users to avoid skipping the expensive hash check.
        password_hash = user.password_hash if user else self.dummy_password_hash
        matches = self.passwords.verify(password, password_hash)
        if user is None or not matches or not user.is_active:
            raise InvalidCredentialsError("Invalid credentials")
        return self.tokens.issue(user.id)
