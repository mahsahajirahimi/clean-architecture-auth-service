from auth_service.modules.identity.application.exceptions import InvalidTokenError
from auth_service.modules.identity.application.ports import (
    AccessTokenVerifier,
    UserRepository,
)
from auth_service.modules.identity.domain.entities.user import User


class GetCurrentUser:
    def __init__(self, users: UserRepository, tokens: AccessTokenVerifier):
        self.users = users
        self.tokens = tokens

    def execute(self, access_token: str) -> User:
        user_id = self.tokens.verify(access_token)
        user = self.users.get_by_id(user_id)
        if user is None or not user.is_active:
            raise InvalidTokenError("Invalid authentication token")
        return user
