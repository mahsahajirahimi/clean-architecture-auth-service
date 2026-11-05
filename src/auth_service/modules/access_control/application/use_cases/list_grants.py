from uuid import UUID

from auth_service.modules.access_control.application.exceptions import InvalidInputError
from auth_service.modules.access_control.application.ports import GrantRepository
from auth_service.modules.access_control.application.use_cases._validation import (
    require_uuid,
    validate_pagination,
)
from auth_service.modules.access_control.domain.entities.grant import Grant, SubjectType


class ListGrants:
    def __init__(self, grants: GrantRepository):
        self.grants = grants

    def execute(
        self,
        subject_type: SubjectType,
        subject_id: UUID,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Grant]:
        if not isinstance(subject_type, SubjectType):
            raise InvalidInputError("Subject type must be a SubjectType")
        require_uuid(subject_id, "Subject ID")
        validate_pagination(limit, offset)
        # Keep stale assignments visible so they can be revoked.
        return self.grants.list_for_subject(subject_type, subject_id, limit, offset)
