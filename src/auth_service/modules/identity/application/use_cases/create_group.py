
from uuid import uuid4

from auth_service.modules.identity.application.ports import GroupRepository
from auth_service.modules.identity.application.exceptions import (
    DuplicateGroupError,
    InvalidInputError,
)
from auth_service.modules.identity.domain.entities.group import Group


class CreateGroup:
    def __init__(self, groups: GroupRepository):
        self.groups = groups

    def execute(self, name: str) -> Group:
        if not isinstance(name, str) or not name.strip():
            raise InvalidInputError("Group name cannot be empty")

        name = name.strip()

        if self.groups.get_by_name(name) is not None:
            raise DuplicateGroupError("Group already exists")

        group = Group(
            id=uuid4(),
            name=name,
        )

        self.groups.save(group)

        return group
