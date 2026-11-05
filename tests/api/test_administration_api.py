import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from uuid import UUID, uuid4

from fastapi.testclient import TestClient
from sqlalchemy import event, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from auth_service.composition.app import create_app
from auth_service.composition.settings import Settings
from auth_service.infrastructure.persistence.database import (
    make_engine,
    make_session_factory,
)
from auth_service.modules.identity.application.use_cases.bootstrap_administrator import (
    BootstrapAdministrator,
)
from auth_service.modules.identity.application.use_cases.create_user import CreateUser
from auth_service.modules.identity.infrastructure.persistence.models import (
    AdministratorModel,
)
from auth_service.modules.identity.infrastructure.persistence.repositories import (
    SqlAlchemyAdministratorRepository,
    SqlAlchemyMembershipRepository,
    SqlAlchemyUserRepository,
)
from auth_service.modules.identity.infrastructure.security.argon2_password_hasher import (
    Argon2PasswordHasher,
)
from auth_service.modules.identity.infrastructure.security.jwt_tokens import JwtTokens


class AdministrationApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.settings = Settings(
            jwt_secret="test-signing-secret-at-least-thirty-two-bytes",
            database_url=f"sqlite:///{Path(self.temp.name) / 'api.db'}",
        )
        self.app = create_app(self.settings)
        self.engine = make_engine(self.settings.database_url)
        self.addCleanup(self.engine.dispose)
        self.sessions = make_session_factory(self.engine)
        self.client = self.enterContext(TestClient(self.app))
        passwords = Argon2PasswordHasher()
        with self.sessions.begin() as session:
            users = SqlAlchemyUserRepository(session)
            self.admin = BootstrapAdministrator(
                users, SqlAlchemyAdministratorRepository(session), passwords
            ).execute("admin", "admin password")
            self.user = CreateUser(users, passwords).execute(
                "ordinary", "user password"
            )
        self.tokens = JwtTokens(
            self.settings.jwt_secret,
            self.settings.jwt_issuer,
            self.settings.jwt_audience,
        )
        self.headers = self.auth(self.admin.id)

    def auth(self, user_id):
        return {"Authorization": f"Bearer {self.tokens.issue(user_id).access_token}"}

    def new_group(self, name="staff"):
        response = self.client.post(
            "/groups", json={"name": name}, headers=self.headers
        )
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()["id"]

    def test_all_administrative_routes_require_authentication(self):
        for path, body in [
            ("/users", {"username": "new", "password": "pw"}),
            ("/groups", {"name": "staff"}),
            (f"/groups/{uuid4()}/members", {"user_id": str(self.user.id)}),
        ]:
            with self.subTest(path=path):
                response = self.client.post(path, json=body)
                self.assertEqual(response.status_code, 401)
                self.assertEqual(response.headers["www-authenticate"], "Bearer")

    def test_all_administrative_routes_reject_ordinary_users(self):
        for path, body in [
            ("/users", {"username": "new", "password": "pw"}),
            ("/groups", {"name": "staff"}),
            (f"/groups/{uuid4()}/members", {"user_id": str(self.user.id)}),
        ]:
            with self.subTest(path=path):
                response = self.client.post(
                    path, json=body, headers=self.auth(self.user.id)
                )
                self.assertEqual(response.status_code, 403)
        with self.sessions() as session:
            self.assertIsNone(SqlAlchemyUserRepository(session).get_by_username("new"))

    def test_administrator_login_and_user_creation_without_hash_leak(self):
        login = self.client.post(
            "/auth/login", json={"username": "admin", "password": "admin password"}
        )
        self.assertEqual(login.status_code, 200)
        response = self.client.post(
            "/users",
            json={"username": " new-user ", "password": "secret password"},
            headers={"Authorization": f"Bearer {login.json()['access_token']}"},
        )
        self.assertEqual(response.status_code, 201, response.text)
        self.assertEqual(set(response.json()), {"id", "username", "is_active"})
        self.assertEqual(response.json()["username"], "new-user")
        self.assertNotIn("secret password", response.text)
        with self.sessions() as session:
            user = SqlAlchemyUserRepository(session).get_by_username("new-user")
            self.assertEqual(str(user.id), response.json()["id"])
            self.assertTrue(
                Argon2PasswordHasher().verify("secret password", user.password_hash)
            )
            self.assertNotIn(user.password_hash, response.text)
        self.assertEqual(
            self.client.post(
                "/users",
                json={"username": "new-user", "password": "pw"},
                headers=self.headers,
            ).status_code,
            409,
        )

    def test_create_group_add_membership_and_reject_duplicates(self):
        group_id = self.new_group(" staff ")
        response = self.client.post(
            "/groups", json={"name": "staff"}, headers=self.headers
        )
        self.assertEqual(response.status_code, 409)
        body = {"user_id": str(self.user.id)}
        response = self.client.post(
            f"/groups/{group_id}/members", json=body, headers=self.headers
        )
        self.assertEqual(response.status_code, 201, response.text)
        self.assertEqual(
            response.json(), {"group_id": group_id, "user_id": str(self.user.id)}
        )
        with self.sessions() as session:
            self.assertTrue(
                SqlAlchemyMembershipRepository(session).exists(
                    self.user.id, UUID(group_id)
                )
            )
        self.assertEqual(
            self.client.post(
                f"/groups/{group_id}/members", json=body, headers=self.headers
            ).status_code,
            409,
        )

    def test_missing_user_and_group_return_404(self):
        group_id = self.new_group()
        for group, user in [
            (group_id, str(uuid4())),
            (str(uuid4()), str(self.user.id)),
        ]:
            with self.subTest(group=group, user=user):
                response = self.client.post(
                    f"/groups/{group}/members",
                    json={"user_id": user},
                    headers=self.headers,
                )
                self.assertEqual(response.status_code, 404)

    def test_validation_and_business_input_errors(self):
        for path, body, expected in [
            (
                "/users",
                {"username": "new", "password": "private", "is_admin": True},
                422,
            ),
            ("/users", {"username": 42, "password": "private"}, 422),
            ("/users", {"username": " ", "password": "private"}, 400),
            ("/users", {"username": "new", "password": " "}, 400),
            ("/groups", {"name": " "}, 400),
            ("/groups", {"name": "x" * 256}, 422),
            ("/groups/not-a-uuid/members", {"user_id": str(self.user.id)}, 422),
            (f"/groups/{uuid4()}/members", {"user_id": "invalid"}, 422),
        ]:
            with self.subTest(path=path, expected=expected):
                response = self.client.post(path, json=body, headers=self.headers)
                self.assertEqual(response.status_code, expected, response.text)
                self.assertNotIn("private", response.text)

    def test_inactive_administrator_cannot_use_previously_issued_token(self):
        with self.sessions.begin() as session:
            SqlAlchemyUserRepository(session).save(self.admin.deactivate())
        response = self.client.post(
            "/groups", json={"name": "blocked"}, headers=self.headers
        )
        self.assertEqual(response.status_code, 401)

    def test_administrator_assignment_is_read_again_for_existing_token(self):
        self.new_group("before-change")
        with self.sessions.begin() as session:
            session.execute(
                update(AdministratorModel)
                .where(AdministratorModel.id == 1)
                .values(user_id=str(self.user.id))
            )
        self.assertEqual(
            self.client.post(
                "/groups", json={"name": "blocked"}, headers=self.headers
            ).status_code,
            403,
        )
        self.assertEqual(
            self.client.post(
                "/groups", json={"name": "allowed"}, headers=self.auth(self.user.id)
            ).status_code,
            201,
        )

    def test_group_named_admin_does_not_grant_administrator_access(self):
        group_id = self.new_group("admin")
        self.assertEqual(
            self.client.post(
                f"/groups/{group_id}/members",
                json={"user_id": str(self.user.id)},
                headers=self.headers,
            ).status_code,
            201,
        )
        response = self.client.post(
            "/groups", json={"name": "blocked"}, headers=self.auth(self.user.id)
        )
        self.assertEqual(response.status_code, 403)

    def test_database_uniqueness_race_returns_safe_conflict_and_rolls_back(self):
        with patch.object(
            SqlAlchemyUserRepository, "get_by_username", return_value=None
        ):
            response = self.client.post(
                "/users",
                json={"username": "ordinary", "password": "replacement password"},
                headers=self.headers,
            )
        self.assertEqual(response.status_code, 409, response.text)
        self.assertEqual(
            response.json(), {"detail": "Operation conflicts with existing data"}
        )
        self.assertNotIn("INSERT", response.text)
        self.assertNotIn("replacement password", response.text)
        self.assertEqual(
            self.client.post(
                "/users",
                json={"username": "after-conflict", "password": "pw"},
                headers=self.headers,
            ).status_code,
            201,
        )
        with self.sessions() as session:
            user = SqlAlchemyUserRepository(session).get_by_id(self.user.id)
            self.assertEqual(user.password_hash, self.user.password_hash)

    def test_commit_failure_returns_conflict_instead_of_success_and_rolls_back(self):
        def reject_commit(session):
            raise IntegrityError("private SQL", {}, Exception("private database error"))

        event.listen(Session, "before_commit", reject_commit)
        try:
            response = self.client.post(
                "/users",
                json={"username": "rolled-back", "password": "pw"},
                headers=self.headers,
            )
        finally:
            event.remove(Session, "before_commit", reject_commit)
        self.assertEqual(response.status_code, 409, response.text)
        self.assertNotIn("private", response.text)
        with self.sessions() as session:
            self.assertIsNone(
                SqlAlchemyUserRepository(session).get_by_username("rolled-back")
            )

    def test_openapi_marks_administrative_endpoints_as_protected(self):
        schema = self.client.get("/openapi.json").json()
        for path in ("/users", "/groups", "/groups/{group_id}/members"):
            self.assertIn("security", schema["paths"][path]["post"])
