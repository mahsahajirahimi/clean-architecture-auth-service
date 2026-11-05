class IdentityError(Exception):
    pass


class InvalidInputError(IdentityError):
    pass


class DuplicateUsernameError(IdentityError):
    pass


class DuplicateGroupError(IdentityError):
    pass


class UserNotFoundError(IdentityError):
    pass


class GroupNotFoundError(IdentityError):
    pass


class MembershipAlreadyExistsError(IdentityError):
    pass


class AuthenticationError(IdentityError):
    pass


class InvalidCredentialsError(AuthenticationError):
    pass


class InvalidTokenError(AuthenticationError):
    pass
