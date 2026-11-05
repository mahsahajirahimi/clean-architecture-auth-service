from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from auth_service.modules.access_control.domain.entities.grant import (
    GrantTargetType,
    SubjectType,
)


class CreateScopeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    name: str = Field(min_length=1, max_length=255)


class CreatePermissionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    name: str = Field(min_length=1, max_length=255)


class GrantRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    subject_type: SubjectType = Field(strict=False)
    subject_id: UUID = Field(strict=False)
    target_type: GrantTargetType = Field(
        strict=False,
        examples=["permission"],
        description="Permission grants cover one operation; scope grants cover all current and future permissions in that scope.",
    )
    target_id: UUID = Field(strict=False)


class CheckAccessRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    permission_id: UUID = Field(strict=False)


class ScopeResponse(BaseModel):
    id: UUID
    name: str


class PermissionResponse(BaseModel):
    id: UUID
    scope_id: UUID
    name: str


class GrantResponse(BaseModel):
    subject_type: SubjectType
    subject_id: UUID
    target_type: GrantTargetType
    target_id: UUID


class EffectivePermissionsResponse(BaseModel):
    user_id: UUID
    permission_ids: list[UUID]


class CheckAccessResponse(BaseModel):
    user_id: UUID
    permission_id: UUID
    allowed: bool
