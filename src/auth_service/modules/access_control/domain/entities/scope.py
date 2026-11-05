from dataclasses import dataclass
from uuid import UUID

from auth_service.modules.access_control.domain._validation import (
    require_name,
    require_uuid,
)


@dataclass(frozen=True, slots=True)
class Scope:
    id: UUID
    name: str

    def __post_init__(self) -> None:
        require_uuid(self.id, "Scope ID")
        require_name(self.name, "Scope name")
