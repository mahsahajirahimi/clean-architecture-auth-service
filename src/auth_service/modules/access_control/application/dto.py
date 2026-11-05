from dataclasses import dataclass
from uuid import UUID


@dataclass(frozen=True, slots=True)
class UserAccessContext:
    user_id: UUID
    is_active: bool
    group_ids: frozenset[UUID]

    def __post_init__(self) -> None:
        if not isinstance(self.user_id, UUID):
            raise ValueError("User ID must be a UUID")
        if type(self.is_active) is not bool:
            raise ValueError("User active status must be a boolean")
        if not isinstance(self.group_ids, frozenset) or any(
            not isinstance(group_id, UUID) for group_id in self.group_ids
        ):
            raise ValueError("Group IDs must be a frozenset of UUIDs")
