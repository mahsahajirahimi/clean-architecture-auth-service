from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import jwt

from auth_service.modules.identity.application.dto import IssuedAccessToken
from auth_service.modules.identity.application.exceptions import InvalidTokenError


class JwtTokens:
    def __init__(
        self,
        secret: str,
        issuer: str,
        audience: str,
        lifetime_seconds: int = 900,
    ):
        if not isinstance(secret, str) or len(secret.encode("utf-8")) < 32:
            raise ValueError("JWT secret must contain at least 32 bytes")
        if not isinstance(issuer, str) or not issuer.strip():
            raise ValueError("JWT issuer must not be empty")
        if not isinstance(audience, str) or not audience.strip():
            raise ValueError("JWT audience must not be empty")
        if type(lifetime_seconds) is not int or not 60 <= lifetime_seconds <= 3600:
            raise ValueError("JWT lifetime must be between 60 and 3600 seconds")
        self._secret = secret
        self.issuer = issuer
        self.audience = audience
        self.lifetime_seconds = lifetime_seconds

    def issue(self, user_id: UUID) -> IssuedAccessToken:
        now = datetime.now(timezone.utc)
        token = jwt.encode(
            {
                "sub": str(user_id),
                "iss": self.issuer,
                "aud": self.audience,
                "iat": now,
                "nbf": now,
                "exp": now + timedelta(seconds=self.lifetime_seconds),
                "jti": str(uuid4()),
                "token_use": "access",
            },
            self._secret,
            algorithm="HS256",
        )
        return IssuedAccessToken(token, self.lifetime_seconds)

    def verify(self, access_token: str) -> UUID:
        try:
            payload = jwt.decode(
                access_token,
                self._secret,
                algorithms=["HS256"],
                issuer=self.issuer,
                audience=self.audience,
                options={
                    "require": [
                        "sub",
                        "iss",
                        "aud",
                        "iat",
                        "nbf",
                        "exp",
                        "jti",
                        "token_use",
                    ],
                    "strict_aud": True,
                },
            )
            if payload["token_use"] != "access":
                raise ValueError("Unexpected token purpose")
            return UUID(payload["sub"])
        except (
            jwt.InvalidTokenError,
            ValueError,
            TypeError,
            AttributeError,
            OverflowError,
        ):
            raise InvalidTokenError("Invalid authentication token") from None
