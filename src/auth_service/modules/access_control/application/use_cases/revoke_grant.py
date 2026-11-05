from uuid import UUID

from auth_service.modules.access_control.application.exceptions import (
    GrantNotFoundError,
)
from auth_service.modules.access_control.application.ports import GrantRepository
from auth_service.modules.access_control.application.use_cases._validation import (
    make_grant,
)
from auth_service.modules.access_control.domain.entities.grant import (
    GrantTargetType,
    SubjectType,
)


class RevokeGrant:
    def __init__(self, grants: GrantRepository):
        self.grants = grants

    def execute(
        self,
        subject_type: SubjectType,
        subject_id: UUID,
        target_type: GrantTargetType,
        target_id: UUID,
    ) -> None:
        grant = make_grant(subject_type, subject_id, target_type, target_id)
        # Stale grants must remain removable after a subject or target disappears.
        if not self.grants.remove(grant):
            raise GrantNotFoundError("Grant not found")
