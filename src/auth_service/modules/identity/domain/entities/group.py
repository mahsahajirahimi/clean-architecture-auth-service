from dataclasses import dataclass
from uuid import UUID


@dataclass(frozen=True, slots=True)
class Group:
    id: UUID
    name: str

    def __post_init__(self) -> None:
        if not isinstance(self.id, UUID):
            raise ValueError("Group ID must be a UUID")
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("Group name cannot be empty")
