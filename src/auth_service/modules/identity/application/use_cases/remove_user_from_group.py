from uuid import UUID

from auth_service.modules.identity.application.exceptions import (
    GroupNotFoundError,
    MembershipNotFoundError,
    UserNotFoundError,
)
from auth_service.modules.identity.application.ports import (
    GroupRepository,
    MembershipRepository,
    UserRepository,
)


class RemoveUserFromGroup:
    def __init__(
        self,
        users: UserRepository,
        groups: GroupRepository,
        memberships: MembershipRepository,
    ):
        self.users = users
        self.groups = groups
        self.memberships = memberships

    def execute(self, user_id: UUID, group_id: UUID) -> None:
        if self.users.get_by_id(user_id) is None:
            raise UserNotFoundError("User not found")
        if self.groups.get_by_id(group_id) is None:
            raise GroupNotFoundError("Group not found")
        if not self.memberships.remove(user_id, group_id):
            raise MembershipNotFoundError("Group membership not found")
