from uuid import UUID

from auth_service.modules.identity.application.exceptions import (
    InvalidInputError,
    UserNotFoundError,
)
from auth_service.modules.identity.application.ports import (
    MembershipRepository,
    UserRepository,
)
from auth_service.modules.identity.application.use_cases._pagination import (
    validate_pagination,
)
from auth_service.modules.identity.domain.entities.group import Group


class ListUserGroups:
    def __init__(self, subjects: UserRepository, memberships: MembershipRepository):
        self.subjects = subjects
        self.memberships = memberships

    def execute(self, user_id: UUID, limit: int = 50, offset: int = 0) -> list[Group]:
        if not isinstance(user_id, UUID):
            raise InvalidInputError("User ID must be a UUID")
        validate_pagination(limit, offset)
        if self.subjects.get_by_id(user_id) is None:
            raise UserNotFoundError("User not found")
        return self.memberships.list_groups(user_id, limit, offset)
