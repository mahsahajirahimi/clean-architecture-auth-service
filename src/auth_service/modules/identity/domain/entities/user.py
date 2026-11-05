from dataclasses import dataclass, replace
from uuid import UUID


@dataclass(frozen=True, slots=True)
class User:
    id: UUID
    username: str
    password_hash: str
    is_active: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.id, UUID):
            raise ValueError("User ID must be a UUID")
        if not isinstance(self.username, str) or not self.username.strip():
            raise ValueError("Username cannot be empty")
        if not isinstance(self.password_hash, str) or not self.password_hash.strip():
            raise ValueError("Password hash cannot be empty")
        if not isinstance(self.is_active, bool):
            raise ValueError("is_active must be a boolean")

    def deactivate(self) -> "User":
        return replace(self, is_active=False)

    def activate(self) -> "User":
        return replace(self, is_active=True)
