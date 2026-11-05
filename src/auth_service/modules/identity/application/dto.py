from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class IssuedAccessToken:
    access_token: str = field(repr=False)
    expires_in: int
