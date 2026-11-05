import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
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
from auth_service.modules.access_control.application.dto import UserAccessContext
from auth_service.modules.access_control.infrastructure.identity_reader import (
    IdentityReaderAdapter,
)
from auth_service.modules.access_control.infrastructure.persistence.repositories import (
    SqlAlchemyGrantRepository,
    SqlAlchemyScopeRepository,
)
from auth_service.modules.identity.application.use_cases.bootstrap_administrator import (
    BootstrapAdministrator,
)
from auth_service.modules.identity.infrastructure.persistence.repositories import (
    SqlAlchemyAdministratorRepository,
    SqlAlchemyUserRepository,
)
from auth_service.modules.identity.infrastructure.security.argon2_password_hasher import (
    Argon2PasswordHasher,
)

P = "/access-control"


class AccessControlApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.settings = Settings(
            jwt_secret="test-signing-key-with-at-least-thirty-two-bytes",
            database_url=f"sqlite:///{Path(self.temp.name) / 'api.db'}",
        )
        self.engine = make_engine(self.settings.database_url)
        self.addCleanup(self.engine.dispose)
        self.sessions = make_session_factory(self.engine)
        self.client = self.enterContext(TestClient(create_app(self.settings)))
        with self.sessions.begin() as session:
            self.admin = BootstrapAdministrator(
                SqlAlchemyUserRepository(session),
                SqlAlchemyAdministratorRepository(session),
                Argon2PasswordHasher(),
            ).execute("admin", "test password")
        self.admin_headers = self.login("admin")
        self.alice = self.new_user("alice")
        self.bob = self.new_user("bob")
        self.alice_headers = self.login("alice")
        self.bob_headers = self.login("bob")
        self.scope = self.new_scope("orders")
        self.read = self.new_permission(self.scope["id"], "read")
        self.write = self.new_permission(self.scope["id"], "write")

    def login(self, username):
        response = self.client.post(
            "/auth/login", json={"username": username, "password": "test password"}
        )
        self.assertEqual(response.status_code, 200, response.text)
        return {"Authorization": f"Bearer {response.json()['access_token']}"}

    def new_user(self, username):
        response = self.client.post(
            "/users",
            json={"username": username, "password": "test password"},
            headers=self.admin_headers,
        )
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()

    def new_scope(self, name):
        response = self.client.post(
            f"{P}/scopes", json={"name": name}, headers=self.admin_headers
        )
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()

    def new_permission(self, scope_id, name):
        response = self.client.post(
            f"{P}/scopes/{scope_id}/permissions",
            json={"name": name},
            headers=self.admin_headers,
        )
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()

    def new_group(self):
        response = self.client.post(
            "/groups", json={"name": "staff"}, headers=self.admin_headers
        )
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()["id"]

    def assign(self, subject_type, subject_id, target_type, target_id):
        body = {
            "subject_type": subject_type,
            "subject_id": str(subject_id),
            "target_type": target_type,
            "target_id": str(target_id),
        }
        response = self.client.post(
            f"{P}/grants", json=body, headers=self.admin_headers
        )
        self.assertEqual(response.status_code, 201, response.text)
        self.assertEqual(response.json(), body)
        return body

    def revoke_path(self, grant):
        return f"{P}/grants/{grant['subject_type']}/{grant['subject_id']}/{grant['target_type']}/{grant['target_id']}"

    def check(self, permission_id, headers=None):
        response = self.client.post(
            f"{P}/me/check",
            json={"permission_id": str(permission_id)},
            headers=headers or self.alice_headers,
        )
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()["allowed"]

    def test_all_management_routes_require_administrator(self):
        routes = [
            ("POST", f"{P}/scopes", {"name": "blocked"}),
            ("GET", f"{P}/scopes", None),
            ("POST", f"{P}/scopes/{self.scope['id']}/permissions", {"name": "blocked"}),
            ("GET", f"{P}/scopes/{self.scope['id']}/permissions", None),
            (
                "POST",
                f"{P}/grants",
                {
                    "subject_type": "user",
                    "subject_id": self.alice["id"],
                    "target_type": "permission",
                    "target_id": self.read["id"],
                },
            ),
            (
                "DELETE",
                f"{P}/grants/user/{self.alice['id']}/permission/{self.read['id']}",
                None,
            ),
            ("GET", f"{P}/users/{self.bob['id']}/permissions", None),
            (
                "POST",
                f"{P}/users/{self.bob['id']}/check",
                {"permission_id": self.read["id"]},
            ),
        ]
        for headers, expected in [({}, 401), (self.alice_headers, 403)]:
            for method, path, body in routes:
                with self.subTest(method=method, path=path, expected=expected):
                    response = self.client.request(
                        method, path, json=body, headers=headers
                    )
                    self.assertEqual(response.status_code, expected, response.text)

    def test_self_endpoints_require_authentication_and_deny_ungranted_access(self):
        for headers in ({}, {"Authorization": "Bearer invalid"}):
            self.assertEqual(
                self.client.get(f"{P}/me/permissions", headers=headers).status_code, 401
            )
            self.assertEqual(
                self.client.post(
                    f"{P}/me/check",
                    json={"permission_id": self.read["id"]},
                    headers=headers,
                ).status_code,
                401,
            )
        self.assertFalse(self.check(self.read["id"]))
        self.assertFalse(self.check(uuid4()))
        response = self.client.get(f"{P}/me/permissions", headers=self.alice_headers)
        self.assertEqual(
            response.json(), {"user_id": self.alice["id"], "permission_ids": []}
        )
        self.assertEqual(response.headers["cache-control"], "no-store")
        # Identity administration is separate from business-resource permissions.
        self.assertFalse(self.check(self.read["id"], self.admin_headers))

    def test_catalog_creation_uniqueness_and_database_pagination(self):
        other = self.new_scope(" invoices ")
        other_read = self.new_permission(other["id"], " read ")
        response = self.client.get(
            f"{P}/scopes?limit=1&offset=0", headers=self.admin_headers
        )
        self.assertEqual(response.json(), [{"id": other["id"], "name": "invoices"}])
        response = self.client.get(
            f"{P}/scopes?limit=1&offset=1", headers=self.admin_headers
        )
        self.assertEqual(response.json(), [self.scope])
        response = self.client.get(
            f"{P}/scopes/{self.scope['id']}/permissions?limit=1&offset=1",
            headers=self.admin_headers,
        )
        self.assertEqual(response.json(), [self.write])
        response = self.client.get(
            f"{P}/scopes/{other['id']}/permissions", headers=self.admin_headers
        )
        self.assertEqual(response.json(), [other_read])
        self.assertEqual(
            self.client.get(
                f"{P}/scopes?offset=100", headers=self.admin_headers
            ).json(),
            [],
        )
        self.assertEqual(
            self.client.post(
                f"{P}/scopes", json={"name": "orders"}, headers=self.admin_headers
            ).status_code,
            409,
        )
        self.assertEqual(
            self.client.post(
                f"{P}/scopes/{self.scope['id']}/permissions",
                json={"name": "read"},
                headers=self.admin_headers,
            ).status_code,
            409,
        )

    def test_all_four_grant_types_can_be_assigned_and_revoked(self):
        group_id = self.new_group()
        for kind, subject_id in [("user", self.alice["id"]), ("group", group_id)]:
            for target, target_id in [
                ("scope", self.scope["id"]),
                ("permission", self.read["id"]),
            ]:
                with self.subTest(kind=kind, target=target):
                    grant = self.assign(kind, subject_id, target, target_id)
                    self.assertEqual(
                        self.client.post(
                            f"{P}/grants", json=grant, headers=self.admin_headers
                        ).status_code,
                        409,
                    )
                    response = self.client.delete(
                        self.revoke_path(grant), headers=self.admin_headers
                    )
                    self.assertEqual(response.status_code, 204, response.text)
                    self.assertEqual(response.content, b"")
                    self.assertEqual(
                        self.client.delete(
                            self.revoke_path(grant), headers=self.admin_headers
                        ).status_code,
                        404,
                    )

    def test_revocation_uses_live_data_and_preserves_group_sources(self):
        direct = self.assign("user", self.alice["id"], "permission", self.read["id"])
        group_id = self.new_group()
        self.assertEqual(
            self.client.post(
                f"/groups/{group_id}/members",
                json={"user_id": self.alice["id"]},
                headers=self.admin_headers,
            ).status_code,
            201,
        )
        inherited = self.assign("group", group_id, "permission", self.read["id"])
        self.assertTrue(self.check(self.read["id"]))
        self.assertFalse(self.check(self.read["id"], self.bob_headers))
        self.assertEqual(
            self.client.delete(
                self.revoke_path(direct), headers=self.admin_headers
            ).status_code,
            204,
        )
        self.assertTrue(self.check(self.read["id"]))
        self.assertEqual(
            self.client.delete(
                self.revoke_path(inherited), headers=self.admin_headers
            ).status_code,
            204,
        )
        self.assertFalse(self.check(self.read["id"]))

    def test_scope_grants_and_membership_changes_affect_existing_tokens(self):
        group_id = self.new_group()
        self.assign("group", group_id, "scope", self.scope["id"])
        self.assertFalse(self.check(self.read["id"]))
        self.assertEqual(
            self.client.post(
                f"/groups/{group_id}/members",
                json={"user_id": self.alice["id"]},
                headers=self.admin_headers,
            ).status_code,
            201,
        )
        self.assertTrue(self.check(self.read["id"]))
        self.assertTrue(self.check(self.write["id"]))
        later = self.new_permission(self.scope["id"], "delete")
        self.assertTrue(self.check(later["id"]))
        response = self.client.get(f"{P}/me/permissions", headers=self.alice_headers)
        self.assertEqual(
            response.json()["permission_ids"],
            sorted([self.read["id"], self.write["id"], later["id"]]),
        )
        self.assertEqual(
            self.client.delete(
                f"/groups/{group_id}/members/{self.alice['id']}",
                headers=self.admin_headers,
            ).status_code,
            204,
        )
        self.assertFalse(self.check(self.read["id"]))
        self.assertEqual(
            self.client.get(f"{P}/me/permissions", headers=self.alice_headers).json()[
                "permission_ids"
            ],
            [],
        )

    def test_self_routes_cannot_impersonate_another_user(self):
        self.assign("user", self.bob["id"], "permission", self.read["id"])
        self.assertFalse(self.check(self.read["id"]))
        response = self.client.post(
            f"{P}/me/check",
            json={"permission_id": self.read["id"], "user_id": self.bob["id"]},
            headers=self.alice_headers,
        )
        self.assertEqual(response.status_code, 422)
        response = self.client.get(
            f"{P}/me/permissions?user_id={self.bob['id']}", headers=self.alice_headers
        )
        self.assertEqual(
            response.json(), {"user_id": self.alice["id"], "permission_ids": []}
        )
        self.assertEqual(
            self.client.get(
                f"{P}/users/{self.bob['id']}/permissions", headers=self.alice_headers
            ).status_code,
            403,
        )
        response = self.client.post(
            f"{P}/users/{self.bob['id']}/check",
            json={"permission_id": self.read["id"]},
            headers=self.admin_headers,
        )
        self.assertEqual(
            response.json(),
            {
                "user_id": self.bob["id"],
                "permission_id": self.read["id"],
                "allowed": True,
            },
        )

    def test_inactive_users_are_blocked_and_admin_can_observe_denial(self):
        self.assign("user", self.alice["id"], "permission", self.read["id"])
        self.assertTrue(self.check(self.read["id"]))
        path = f"/users/{self.alice['id']}/status"
        self.assertEqual(
            self.client.patch(
                path, json={"is_active": False}, headers=self.admin_headers
            ).status_code,
            200,
        )
        self.assertEqual(
            self.client.get(
                f"{P}/me/permissions", headers=self.alice_headers
            ).status_code,
            401,
        )
        self.assertEqual(
            self.client.post(
                f"{P}/me/check",
                json={"permission_id": self.read["id"]},
                headers=self.alice_headers,
            ).status_code,
            401,
        )
        response = self.client.post(
            f"{P}/users/{self.alice['id']}/check",
            json={"permission_id": self.read["id"]},
            headers=self.admin_headers,
        )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["allowed"])
        self.assertEqual(
            self.client.get(
                f"{P}/users/{self.alice['id']}/permissions", headers=self.admin_headers
            ).json()["permission_ids"],
            [],
        )
        self.assertEqual(
            self.client.patch(
                path, json={"is_active": True}, headers=self.admin_headers
            ).status_code,
            200,
        )
        self.assertTrue(self.check(self.read["id"]))

    def test_scope_grant_does_not_turn_an_ordinary_user_into_an_administrator(self):
        self.assign("user", self.alice["id"], "scope", self.scope["id"])
        self.assertTrue(self.check(self.write["id"]))
        self.assertEqual(
            self.client.post(
                f"{P}/scopes", json={"name": "blocked"}, headers=self.alice_headers
            ).status_code,
            403,
        )

    def test_unknown_resources_return_explicit_not_found_errors(self):
        missing = str(uuid4())
        self.assertEqual(
            self.client.get(
                f"{P}/scopes/{missing}/permissions", headers=self.admin_headers
            ).status_code,
            404,
        )
        self.assertEqual(
            self.client.post(
                f"{P}/scopes/{missing}/permissions",
                json={"name": "read"},
                headers=self.admin_headers,
            ).status_code,
            404,
        )
        for kind, subject, target, target_id in [
            ("user", missing, "permission", self.read["id"]),
            ("group", missing, "scope", self.scope["id"]),
            ("user", self.alice["id"], "permission", missing),
            ("user", self.alice["id"], "scope", missing),
        ]:
            response = self.client.post(
                f"{P}/grants",
                json={
                    "subject_type": kind,
                    "subject_id": subject,
                    "target_type": target,
                    "target_id": target_id,
                },
                headers=self.admin_headers,
            )
            self.assertEqual(response.status_code, 404, response.text)
        self.assertEqual(
            self.client.get(
                f"{P}/users/{missing}/permissions", headers=self.admin_headers
            ).status_code,
            404,
        )
        self.assertEqual(
            self.client.post(
                f"{P}/users/{missing}/check",
                json={"permission_id": self.read["id"]},
                headers=self.admin_headers,
            ).status_code,
            404,
        )

    def test_request_validation_and_business_input_errors_are_sanitized(self):
        for body, expected in [
            ({"name": " "}, 400),
            ({"name": 42}, 422),
            ({"name": "x" * 256}, 422),
            ({"name": "orders", "extra": "private-value"}, 422),
        ]:
            response = self.client.post(
                f"{P}/scopes", json=body, headers=self.admin_headers
            )
            self.assertEqual(response.status_code, expected, response.text)
            self.assertNotIn("private-value", response.text)
        body = {
            "subject_type": "user",
            "subject_id": self.alice["id"],
            "target_type": "permission",
            "target_id": self.read["id"],
        }
        for changes in (
            {"subject_type": "admin"},
            {"target_type": "*"},
            {"subject_id": "invalid"},
            {"target_id": None},
            {"is_admin": True},
        ):
            response = self.client.post(
                f"{P}/grants", json={**body, **changes}, headers=self.admin_headers
            )
            self.assertEqual(response.status_code, 422, response.text)
        for path in [
            f"{P}/scopes?limit=0",
            f"{P}/scopes?limit=101",
            f"{P}/scopes?offset=-1",
            f"{P}/scopes/{self.scope['id']}/permissions?offset=-1",
            f"{P}/scopes/invalid/permissions",
        ]:
            self.assertEqual(
                self.client.get(path, headers=self.admin_headers).status_code, 422
            )
        self.assertEqual(
            self.client.post(
                f"{P}/me/check",
                json={"permission_id": "invalid"},
                headers=self.alice_headers,
            ).status_code,
            422,
        )

    def test_database_conflicts_are_rolled_back_without_exposing_sql(self):
        with patch.object(SqlAlchemyScopeRepository, "get_by_name", return_value=None):
            response = self.client.post(
                f"{P}/scopes", json={"name": "orders"}, headers=self.admin_headers
            )
        self.assertEqual(response.status_code, 409)
        self.assertNotIn("INSERT", response.text)
        self.assertNotIn("access_scopes", response.text)
        grant = self.assign("user", self.alice["id"], "permission", self.read["id"])
        with patch.object(SqlAlchemyGrantRepository, "exists", return_value=False):
            response = self.client.post(
                f"{P}/grants", json=grant, headers=self.admin_headers
            )
        self.assertEqual(response.status_code, 409)
        self.assertNotIn("INSERT", response.text)
        self.new_scope("after-conflict")

    def test_commit_failure_does_not_return_success_or_persist_scope(self):
        def fail_commit(session):
            raise IntegrityError("private SQL", {}, Exception("private database error"))

        event.listen(Session, "before_commit", fail_commit)
        try:
            response = self.client.post(
                f"{P}/scopes", json={"name": "rolled-back"}, headers=self.admin_headers
            )
        finally:
            event.remove(Session, "before_commit", fail_commit)
        self.assertEqual(response.status_code, 409, response.text)
        self.assertNotIn("private", response.text)
        with self.sessions() as session:
            self.assertIsNone(
                SqlAlchemyScopeRepository(session).get_by_name("rolled-back")
            )

    def test_failed_grant_revocation_rolls_back_before_response(self):
        grant = self.assign("user", self.alice["id"], "permission", self.read["id"])

        def fail_commit(session):
            raise IntegrityError("private SQL", {}, Exception("private database error"))

        event.listen(Session, "before_commit", fail_commit)
        try:
            response = self.client.delete(
                self.revoke_path(grant), headers=self.admin_headers
            )
        finally:
            event.remove(Session, "before_commit", fail_commit)
        self.assertEqual(response.status_code, 409, response.text)
        self.assertTrue(self.check(self.read["id"]))

    def test_identity_context_failure_is_reported_safely_as_server_error(self):
        wrong = UserAccessContext(UUID(self.bob["id"]), True, frozenset())
        with patch.object(
            IdentityReaderAdapter, "get_user_context", return_value=wrong
        ):
            response = self.client.get(
                f"{P}/me/permissions", headers=self.alice_headers
            )
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json(), {"detail": "Access control operation failed"})
        self.assertNotIn(self.bob["id"], response.text)

    def test_openapi_declares_authentication_on_every_access_control_operation(self):
        schema = self.client.get("/openapi.json").json()
        count = 0
        for path, operations in schema["paths"].items():
            if path.startswith(P):
                for method, operation in operations.items():
                    if method in ("get", "post", "delete"):
                        self.assertIn("security", operation, path)
                        count += 1
        self.assertEqual(count, 10)
