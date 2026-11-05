from uuid import UUID

from auth_service.modules.identity.application.exceptions import (
    GroupNotFoundError,
    InvalidInputError,
)
from auth_service.modules.identity.application.ports import (
    GroupRepository,
    MembershipRepository,
)
from auth_service.modules.identity.application.use_cases._pagination import (
    validate_pagination,
)
from auth_service.modules.identity.domain.entities.user import User


class ListGroupMembers:
    def __init__(self, subjects: GroupRepository, memberships: MembershipRepository):
        self.subjects = subjects
        self.memberships = memberships

    def execute(self, group_id: UUID, limit: int = 50, offset: int = 0) -> list[User]:
        if not isinstance(group_id, UUID):
            raise InvalidInputError("Group ID must be a UUID")
        validate_pagination(limit, offset)
        if self.subjects.get_by_id(group_id) is None:
            raise GroupNotFoundError("Group not found")
        return self.memberships.list_users(group_id, limit, offset)
