from uuid import UUID

from auth_service.modules.access_control.application.exceptions import InvalidInputError
from auth_service.modules.access_control.domain.entities.grant import (
    Grant,
    GrantTargetType,
    SubjectType,
)


def require_uuid(value: UUID, field_name: str) -> None:
    if not isinstance(value, UUID):
        raise InvalidInputError(f"{field_name} must be a UUID")


def normalize_name(name: str, field_name: str) -> str:
    if not isinstance(name, str) or not name.strip():
        raise InvalidInputError(f"{field_name} cannot be empty")
    name = name.strip()
    if len(name) > 255:
        raise InvalidInputError(f"{field_name} must not exceed 255 characters")
    return name


def make_grant(
    subject_type: SubjectType,
    subject_id: UUID,
    target_type: GrantTargetType,
    target_id: UUID,
) -> Grant:
    try:
        return Grant(subject_type, subject_id, target_type, target_id)
    except ValueError as error:
        raise InvalidInputError(str(error)) from None
