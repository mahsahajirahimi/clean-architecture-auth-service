from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, SecretStr


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    username: str = Field(min_length=1, max_length=255)
    password: SecretStr = Field(min_length=1, max_length=1024)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class UserResponse(BaseModel):
    id: UUID
    username: str
    is_active: bool


class CreateUserRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    username: str = Field(min_length=1, max_length=255)
    password: SecretStr = Field(min_length=1, max_length=1024)


class CreateGroupRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    name: str = Field(min_length=1, max_length=255)


class AddMemberRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    # UUID strings are the JSON representation; other fields remain strict.
    user_id: UUID = Field(strict=False)


class GroupResponse(BaseModel):
    id: UUID
    name: str


class MembershipResponse(BaseModel):
    user_id: UUID
    group_id: UUID
