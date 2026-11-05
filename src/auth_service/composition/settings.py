import os
from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class Settings:
    jwt_secret: str = field(repr=False)
    database_url: str = "sqlite:///auth_service.db"
    jwt_issuer: str = "auth-service"
    jwt_audience: str = "auth-service-api"
    token_lifetime_seconds: int = 900

    @classmethod
    def from_environment(cls) -> "Settings":
        secret = os.environ.get("AUTH_JWT_SECRET")
        if not secret:
            raise ValueError("AUTH_JWT_SECRET is required")
        try:
            lifetime = int(os.environ.get("AUTH_TOKEN_LIFETIME_SECONDS", "900"))
        except ValueError:
            raise ValueError("AUTH_TOKEN_LIFETIME_SECONDS must be an integer") from None
        return cls(
            jwt_secret=secret,
            database_url=os.environ.get(
                "AUTH_DATABASE_URL", "sqlite:///auth_service.db"
            ),
            jwt_issuer=os.environ.get("AUTH_JWT_ISSUER", "auth-service"),
            jwt_audience=os.environ.get("AUTH_JWT_AUDIENCE", "auth-service-api"),
            token_lifetime_seconds=lifetime,
        )
