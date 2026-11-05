from uuid import UUID

from auth_service.modules.identity.application.exceptions import GroupNotFoundError
from auth_service.modules.identity.application.ports import GroupRepository
from auth_service.modules.identity.domain.entities.group import Group


class GetGroup:
    def __init__(self, groups: GroupRepository):
        self.groups = groups

    def execute(self, group_id: UUID) -> Group:
        group = self.groups.get_by_id(group_id)
        if group is None:
            raise GroupNotFoundError("Group not found")
        return group
