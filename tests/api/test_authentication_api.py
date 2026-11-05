import os
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from uuid import uuid4

import jwt
from fastapi.testclient import TestClient
from sqlalchemy import delete

from auth_service.composition.app import create_app
from auth_service.composition.settings import Settings
from auth_service.infrastructure.persistence.database import (
    make_engine,
    make_session_factory,
)
from auth_service.modules.identity.application.use_cases.create_user import CreateUser
from auth_service.modules.identity.infrastructure.persistence.models import UserModel
from auth_service.modules.identity.infrastructure.persistence.repositories import (
    SqlAlchemyUserRepository,
)
from auth_service.modules.identity.infrastructure.security.argon2_password_hasher import (
    Argon2PasswordHasher,
)


class AuthenticationApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.secret = "test-secret-key-at-least-thirty-two-bytes-long"
        self.settings = Settings(
            jwt_secret=self.secret,
            database_url=f"sqlite:///{Path(self.temp.name) / 'api.db'}",
        )
        self.app = create_app(self.settings)
        self.engine = make_engine(self.settings.database_url)
        self.addCleanup(self.engine.dispose)
        self.sessions = make_session_factory(self.engine)
        self.client = self.enterContext(TestClient(self.app))
        with self.sessions.begin() as session:
            self.user = CreateUser(
                SqlAlchemyUserRepository(session), Argon2PasswordHasher()
            ).execute("ali", "correct password")

    def login(self):
        response = self.client.post(
            "/auth/login", json={"username": "ali", "password": "correct password"}
        )
        self.assertEqual(response.status_code, 200, response.text)
        return response

    def authorization(self):
        return {"Authorization": f"Bearer {self.login().json()['access_token']}"}

    def test_login_and_me_without_exposing_hash(self):
        response = self.login()
        token = response.json()
        self.assertEqual(set(token), {"access_token", "token_type", "expires_in"})
        self.assertEqual(token["token_type"], "bearer")
        self.assertEqual(token["expires_in"], 900)
        self.assertEqual(response.headers["cache-control"], "no-store")
        response = self.client.get(
            "/auth/me", headers={"Authorization": f"Bearer {token['access_token']}"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {"id": str(self.user.id), "username": "ali", "is_active": True},
        )
        self.assertNotIn(self.user.password_hash, response.text)
        self.assertEqual(response.headers["cache-control"], "no-store")

    def test_unknown_user_wrong_password_and_inactive_user_have_same_error(self):
        responses = []
        for username, password in [("unknown", "correct password"), ("ali", "wrong")]:
            responses.append(
                self.client.post(
                    "/auth/login", json={"username": username, "password": password}
                )
            )
        with self.sessions.begin() as session:
            SqlAlchemyUserRepository(session).save(self.user.deactivate())
        responses.append(
            self.client.post(
                "/auth/login", json={"username": "ali", "password": "correct password"}
            )
        )
        for response in responses:
            self.assertEqual(response.status_code, 401)
            self.assertEqual(response.json(), {"detail": "Authentication failed"})
            self.assertEqual(response.headers["www-authenticate"], "Bearer")

    def test_deactivation_invalidates_existing_token(self):
        headers = self.authorization()
        with self.sessions.begin() as session:
            SqlAlchemyUserRepository(session).save(self.user.deactivate())
        self.assertEqual(self.client.get("/auth/me", headers=headers).status_code, 401)

    def test_deletion_invalidates_existing_token(self):
        headers = self.authorization()
        with self.sessions.begin() as session:
            session.execute(delete(UserModel).where(UserModel.id == str(self.user.id)))
        self.assertEqual(self.client.get("/auth/me", headers=headers).status_code, 401)

    def test_me_requires_valid_bearer_token(self):
        for headers in (
            {},
            {"Authorization": "Basic abc"},
            {"Authorization": "Bearer"},
            {"Authorization": "Bearer invalid"},
        ):
            with self.subTest(headers=headers):
                response = self.client.get("/auth/me", headers=headers)
                self.assertEqual(response.status_code, 401)
                self.assertEqual(response.headers["www-authenticate"], "Bearer")

    def test_api_rejects_expired_and_untrusted_tokens(self):
        now = datetime.now(timezone.utc)
        claims = {
            "sub": str(self.user.id),
            "iss": "auth-service",
            "aud": "auth-service-api",
            "iat": now,
            "nbf": now,
            "exp": now + timedelta(minutes=15),
            "jti": str(uuid4()),
            "token_use": "access",
        }
        for changes, key in [
            ({"exp": now - timedelta(seconds=1)}, self.secret),
            ({"aud": "wrong"}, self.secret),
            ({}, "wrong-signing-key-at-least-thirty-two-bytes"),
        ]:
            with self.subTest(changes=changes):
                token = jwt.encode({**claims, **changes}, key, algorithm="HS256")
                response = self.client.get(
                    "/auth/me", headers={"Authorization": f"Bearer {token}"}
                )
                self.assertEqual(response.status_code, 401)

    def test_login_schema_rejects_invalid_inputs_without_echoing_password(self):
        password = "private-password-value"
        for body in [
            {"username": 42, "password": password},
            {"username": "ali"},
            {"username": "ali", "password": ""},
            {"username": "", "password": password},
            {"username": "ali", "password": password, "extra": True},
            {"username": "ali", "password": {"value": password}},
            {"username": "ali", "password": password * 100},
        ]:
            with self.subTest(body_keys=list(body)):
                response = self.client.post("/auth/login", json=body)
                self.assertEqual(response.status_code, 422, response.text)
                self.assertNotIn(password, response.text)
                for detail in response.json()["detail"]:
                    self.assertNotIn("input", detail)

    def test_malformed_json_returns_validation_error(self):
        response = self.client.post(
            "/auth/login",
            content='{"password": "private-password-value",',
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(response.status_code, 422)
        self.assertNotIn("private-password-value", response.text)

    def test_openapi_declares_bearer_auth_and_safe_user_schema(self):
        schema = self.client.get("/openapi.json").json()
        self.assertIn("security", schema["paths"]["/auth/me"]["get"])
        self.assertEqual(
            set(schema["components"]["schemas"]["UserResponse"]["properties"]),
            {"id", "username", "is_active"},
        )


class SettingsTests(unittest.TestCase):
    def test_environment_requires_secret(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ValueError, "AUTH_JWT_SECRET is required"):
                create_app()

    def test_short_secret_is_rejected_before_database_is_opened(self):
        with self.assertRaisesRegex(ValueError, "at least 32 bytes"):
            create_app(Settings(jwt_secret="short", database_url="invalid://url"))

    def test_environment_settings_and_hidden_secret(self):
        secret = "test-secret-key-at-least-thirty-two-bytes-long"
        with patch.dict(
            os.environ,
            {"AUTH_JWT_SECRET": secret, "AUTH_TOKEN_LIFETIME_SECONDS": "600"},
            clear=True,
        ):
            settings = Settings.from_environment()
        self.assertEqual(settings.token_lifetime_seconds, 600)
        self.assertNotIn(secret, repr(settings))

    def test_invalid_environment_lifetime(self):
        with patch.dict(
            os.environ,
            {"AUTH_JWT_SECRET": "secret", "AUTH_TOKEN_LIFETIME_SECONDS": "not-int"},
            clear=True,
        ):
            with self.assertRaisesRegex(ValueError, "must be an integer"):
                Settings.from_environment()
