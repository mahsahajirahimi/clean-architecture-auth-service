import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import UUID, uuid4

from fastapi.testclient import TestClient
from sqlalchemy import event
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
from auth_service.modules.identity.infrastructure.persistence.repositories import (
    SqlAlchemyAdministratorRepository,
    SqlAlchemyMembershipRepository,
    SqlAlchemyUserRepository,
)
from auth_service.modules.identity.infrastructure.security.argon2_password_hasher import (
    Argon2PasswordHasher,
)
from auth_service.modules.identity.infrastructure.security.jwt_tokens import JwtTokens


class IdentityManagementApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.settings = Settings(
            jwt_secret="test-signing-key-with-at-least-thirty-two-bytes",
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
        tokens = JwtTokens(
            self.settings.jwt_secret,
            self.settings.jwt_issuer,
            self.settings.jwt_audience,
        )
        self.admin_headers = {
            "Authorization": f"Bearer {tokens.issue(self.admin.id).access_token}"
        }
        self.user_headers = {
            "Authorization": f"Bearer {tokens.issue(self.user.id).access_token}"
        }

    def group(self, name="staff"):
        response = self.client.post(
            "/groups", json={"name": name}, headers=self.admin_headers
        )
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()["id"]

    def add_member(self, group_id):
        response = self.client.post(
            f"/groups/{group_id}/members",
            json={"user_id": str(self.user.id)},
            headers=self.admin_headers,
        )
        self.assertEqual(response.status_code, 201, response.text)

    def test_every_new_route_requires_active_administrator(self):
        routes = [
            ("GET", "/users"),
            ("GET", f"/users/{self.user.id}"),
            ("GET", "/groups"),
            ("GET", f"/groups/{uuid4()}"),
            ("PATCH", f"/users/{self.user.id}/status"),
            ("DELETE", f"/groups/{uuid4()}/members/{self.user.id}"),
        ]
        for headers, expected in [({}, 401), (self.user_headers, 403)]:
            for method, path in routes:
                with self.subTest(method=method, path=path, expected=expected):
                    response = self.client.request(
                        method,
                        path,
                        headers=headers,
                        json={"is_active": False} if method == "PATCH" else None,
                    )
                    self.assertEqual(response.status_code, expected, response.text)
        with self.sessions() as session:
            self.assertTrue(
                SqlAlchemyUserRepository(session).get_by_id(self.user.id).is_active
            )

    def test_get_and_list_users_have_safe_schemas_and_pagination(self):
        response = self.client.get(
            "/users?limit=1&offset=1", headers=self.admin_headers
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            [{"id": str(self.user.id), "username": "ordinary", "is_active": True}],
        )
        self.assertNotIn(self.user.password_hash, response.text)
        self.assertEqual(response.headers["cache-control"], "no-store")
        response = self.client.get(f"/users/{self.user.id}", headers=self.admin_headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(set(response.json()), {"id", "username", "is_active"})
        self.assertEqual(response.json()["id"], str(self.user.id))
        self.assertEqual(
            self.client.get("/users?offset=100", headers=self.admin_headers).json(), []
        )

    def test_get_and_list_groups_are_sorted_and_paginated(self):
        self.assertEqual(
            self.client.get("/groups", headers=self.admin_headers).json(), []
        )
        self.group("z")
        group_id = self.group("a")
        response = self.client.get("/groups?limit=1", headers=self.admin_headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [{"id": group_id, "name": "a"}])
        response = self.client.get(f"/groups/{group_id}", headers=self.admin_headers)
        self.assertEqual(response.json(), {"id": group_id, "name": "a"})
        self.assertEqual(
            self.client.get(
                "/groups?limit=1&offset=1", headers=self.admin_headers
            ).json()[0]["name"],
            "z",
        )

    def test_disable_blocks_login_and_current_user_and_reactivation_restores_access(
        self,
    ):
        path = f"/users/{self.user.id}/status"
        response = self.client.patch(
            path, json={"is_active": False}, headers=self.admin_headers
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertFalse(response.json()["is_active"])
        self.assertNotIn("password_hash", response.json())
        self.assertEqual(
            self.client.get("/auth/me", headers=self.user_headers).status_code, 401
        )
        self.assertEqual(
            self.client.post(
                "/auth/login",
                json={"username": "ordinary", "password": "user password"},
            ).status_code,
            401,
        )
        detail = self.client.get(f"/users/{self.user.id}", headers=self.admin_headers)
        self.assertFalse(detail.json()["is_active"])
        response = self.client.patch(
            path, json={"is_active": True}, headers=self.admin_headers
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["is_active"])
        self.assertEqual(
            self.client.get("/auth/me", headers=self.user_headers).status_code, 200
        )
        self.assertEqual(
            self.client.post(
                "/auth/login",
                json={"username": "ordinary", "password": "user password"},
            ).status_code,
            200,
        )

    def test_initial_administrator_deactivation_is_rejected_without_losing_access(self):
        response = self.client.patch(
            f"/users/{self.admin.id}/status",
            json={"is_active": False},
            headers=self.admin_headers,
        )
        self.assertEqual(response.status_code, 409, response.text)
        self.assertEqual(
            self.client.get("/users", headers=self.admin_headers).status_code, 200
        )
        with self.sessions() as session:
            self.assertTrue(
                SqlAlchemyUserRepository(session).get_by_id(self.admin.id).is_active
            )

    def test_removing_membership_only_removes_selected_group_and_can_be_added_again(
        self,
    ):
        first, second = self.group("first"), self.group("second")
        self.add_member(first)
        self.add_member(second)
        path = f"/groups/{first}/members/{self.user.id}"
        response = self.client.delete(path, headers=self.admin_headers)
        self.assertEqual(response.status_code, 204, response.text)
        self.assertEqual(response.content, b"")
        self.assertEqual(
            self.client.delete(path, headers=self.admin_headers).status_code, 404
        )
        with self.sessions() as session:
            memberships = SqlAlchemyMembershipRepository(session)
            self.assertFalse(memberships.exists(self.user.id, UUID(first)))
            self.assertTrue(memberships.exists(self.user.id, UUID(second)))
        self.add_member(first)
        self.assertEqual(
            self.client.get(
                f"/users/{self.user.id}", headers=self.admin_headers
            ).status_code,
            200,
        )
        self.assertEqual(
            self.client.get(f"/groups/{first}", headers=self.admin_headers).status_code,
            200,
        )

    def test_unknown_resources_return_404(self):
        group_id = self.group()
        for method, path in [
            ("GET", f"/users/{uuid4()}"),
            ("GET", f"/groups/{uuid4()}"),
            ("PATCH", f"/users/{uuid4()}/status"),
            ("DELETE", f"/groups/{uuid4()}/members/{self.user.id}"),
            ("DELETE", f"/groups/{group_id}/members/{uuid4()}"),
            ("DELETE", f"/groups/{group_id}/members/{self.user.id}"),
        ]:
            with self.subTest(method=method, path=path):
                response = self.client.request(
                    method,
                    path,
                    headers=self.admin_headers,
                    json={"is_active": False} if method == "PATCH" else None,
                )
                self.assertEqual(response.status_code, 404, response.text)

    def test_invalid_pagination_and_identifiers_return_422(self):
        for path in [
            "/users?limit=0",
            "/users?limit=101",
            "/users?offset=-1",
            "/users?limit=abc",
            "/groups?limit=0",
            "/groups?offset=-1",
            "/users/not-uuid",
            "/groups/not-uuid",
        ]:
            with self.subTest(path=path):
                self.assertEqual(
                    self.client.get(path, headers=self.admin_headers).status_code, 422
                )
        self.assertEqual(
            self.client.delete(
                f"/groups/not-uuid/members/{self.user.id}", headers=self.admin_headers
            ).status_code,
            422,
        )

    def test_status_schema_accepts_only_explicit_boolean_and_no_extra_fields(self):
        path = f"/users/{self.user.id}/status"
        for body in [
            {"is_active": 0},
            {"is_active": "false"},
            {"is_active": None},
            {},
            {"is_active": False, "is_admin": True},
        ]:
            with self.subTest(body=body):
                self.assertEqual(
                    self.client.patch(
                        path, json=body, headers=self.admin_headers
                    ).status_code,
                    422,
                )
        with self.sessions() as session:
            self.assertTrue(
                SqlAlchemyUserRepository(session).get_by_id(self.user.id).is_active
            )

    def test_status_and_membership_changes_roll_back_if_commit_fails(self):
        group_id = self.group()
        self.add_member(group_id)

        def fail_commit(session):
            raise IntegrityError("private SQL", {}, Exception("private detail"))

        for method, path in [
            ("PATCH", f"/users/{self.user.id}/status"),
            ("DELETE", f"/groups/{group_id}/members/{self.user.id}"),
        ]:
            with self.subTest(method=method):
                event.listen(Session, "before_commit", fail_commit)
                try:
                    response = self.client.request(
                        method,
                        path,
                        headers=self.admin_headers,
                        json={"is_active": False} if method == "PATCH" else None,
                    )
                finally:
                    event.remove(Session, "before_commit", fail_commit)
                self.assertEqual(response.status_code, 409, response.text)
                self.assertNotIn("private", response.text)
        with self.sessions() as session:
            self.assertTrue(
                SqlAlchemyUserRepository(session).get_by_id(self.user.id).is_active
            )
            self.assertTrue(
                SqlAlchemyMembershipRepository(session).exists(
                    self.user.id, UUID(group_id)
                )
            )
