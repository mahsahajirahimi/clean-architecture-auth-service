
from uuid import UUID

from auth_service.modules.identity.application.ports import (
    UserRepository,
    GroupRepository,
    MembershipRepository,
)
from auth_service.modules.identity.application.exceptions import (
    UserNotFoundError,
    GroupNotFoundError,
    MembershipAlreadyExistsError,
)
from auth_service.modules.identity.domain.entities.membership import (
    GroupMembership,
)


class AddUserToGroup:
    def __init__(
        self,
        users: UserRepository,
        groups: GroupRepository,
        memberships: MembershipRepository,
    ):
        self.users = users
        self.groups = groups
        self.memberships = memberships

    def execute(
        self,
        user_id: UUID,
        group_id: UUID,
    ) -> GroupMembership:

        if self.users.get_by_id(user_id) is None:
            raise UserNotFoundError("User not found")

        if self.groups.get_by_id(group_id) is None:
            raise GroupNotFoundError("Group not found")

        if self.memberships.exists(user_id, group_id):
            raise MembershipAlreadyExistsError(
                "User is already a member of this group"
            )

        membership = GroupMembership(
            user_id=user_id,
            group_id=group_id,
        )

        self.memberships.save(membership)

        return membership
