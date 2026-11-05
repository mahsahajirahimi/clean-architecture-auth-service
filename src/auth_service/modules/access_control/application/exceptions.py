class AccessControlError(Exception):
    pass


class InvalidInputError(AccessControlError):
    pass


class DuplicateScopeError(AccessControlError):
    pass


class DuplicatePermissionError(AccessControlError):
    pass


class ScopeNotFoundError(AccessControlError):
    pass


class PermissionNotFoundError(AccessControlError):
    pass


class SubjectNotFoundError(AccessControlError):
    pass


class GrantAlreadyExistsError(AccessControlError):
    pass


class GrantNotFoundError(AccessControlError):
    pass


class UserNotFoundError(AccessControlError):
    pass


class IdentityContextError(AccessControlError):
    pass
