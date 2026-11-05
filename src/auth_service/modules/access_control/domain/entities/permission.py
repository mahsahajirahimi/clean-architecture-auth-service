from dataclasses import dataclass
from uuid import UUID

from auth_service.modules.access_control.domain._validation import (
    require_name,
    require_uuid,
)


@dataclass(frozen=True, slots=True)
class Permission:
    id: UUID
    scope_id: UUID
    name: str

    def __post_init__(self) -> None:
        require_uuid(self.id, "Permission ID")
        require_uuid(self.scope_id, "Scope ID")
        require_name(self.name, "Permission name")
