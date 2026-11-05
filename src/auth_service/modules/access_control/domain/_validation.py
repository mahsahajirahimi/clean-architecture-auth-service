from uuid import UUID


def require_uuid(value: UUID, field_name: str) -> None:
    if not isinstance(value, UUID):
        raise ValueError(f"{field_name} must be a UUID")


def require_name(value: str, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} cannot be empty")
    if value != value.strip():
        raise ValueError(f"{field_name} must not have surrounding whitespace")
    if len(value) > 255:
        raise ValueError(f"{field_name} must not exceed 255 characters")
