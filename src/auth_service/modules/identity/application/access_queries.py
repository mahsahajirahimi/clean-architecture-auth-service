from uuid import UUID

from auth_service.modules.identity.application.dto import IdentityUserContext
from auth_service.modules.identity.application.ports import (
    GroupRepository,
    MembershipRepository,
    UserRepository,
)


class IdentityAccessQueries:
    """Read-only application boundary; it never returns credentials or ORM models."""

    def __init__(
        self,
        users: UserRepository,
        groups: GroupRepository,
        memberships: MembershipRepository,
    ):
        self.users = users
        self.groups = groups
        self.memberships = memberships

    def get_user_context(self, user_id: UUID) -> IdentityUserContext | None:
        user = self.users.get_by_id(user_id)
        if user is None:
            return None
        return IdentityUserContext(
            user.id, user.is_active, self.memberships.list_group_ids(user_id)
        )

    def group_exists(self, group_id: UUID) -> bool:
        return self.groups.get_by_id(group_id) is not None
