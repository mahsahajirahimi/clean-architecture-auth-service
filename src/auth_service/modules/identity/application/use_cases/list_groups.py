from auth_service.modules.identity.application.ports import GroupRepository
from auth_service.modules.identity.application.use_cases._pagination import (
    validate_pagination,
)
from auth_service.modules.identity.domain.entities.group import Group


class ListGroups:
    def __init__(self, groups: GroupRepository):
        self.groups = groups

    def execute(self, limit: int = 50, offset: int = 0) -> list[Group]:
        validate_pagination(limit, offset)
        return self.groups.list(limit, offset)
