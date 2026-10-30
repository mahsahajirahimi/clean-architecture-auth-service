
from dataclasses import dataclass
from uuid import UUID


@dataclass(frozen=True, slots=True)
class GroupMembership:
    user_id: UUID
    group_id: UUID

    def __post_init__(self) -> None:
        if not isinstance(self.user_id, UUID):
            raise ValueError("Member user ID must be a UUID")
        if not isinstance(self.group_id, UUID):
            raise ValueError("Member group ID must be a UUID")
