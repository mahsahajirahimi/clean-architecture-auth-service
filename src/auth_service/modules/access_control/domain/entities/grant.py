from dataclasses import dataclass
from enum import Enum
from uuid import UUID

from auth_service.modules.access_control.domain._validation import require_uuid


class SubjectType(str, Enum):
    USER = "user"
    GROUP = "group"


class GrantTargetType(str, Enum):
    SCOPE = "scope"
    PERMISSION = "permission"


@dataclass(frozen=True, slots=True)
class Grant:
    subject_type: SubjectType
    subject_id: UUID
    target_type: GrantTargetType
    target_id: UUID

    def __post_init__(self) -> None:
        if not isinstance(self.subject_type, SubjectType):
            raise ValueError("Subject type must be a SubjectType")
        if not isinstance(self.target_type, GrantTargetType):
            raise ValueError("Target type must be a GrantTargetType")
        require_uuid(self.subject_id, "Subject ID")
        require_uuid(self.target_id, "Target ID")
