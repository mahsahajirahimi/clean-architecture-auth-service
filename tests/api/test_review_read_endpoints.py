import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import uuid4

from fastapi.testclient import TestClient

from auth_service.composition.app import create_app
from auth_service.composition.settings import Settings
from auth_service.infrastructure.persistence.database import (
    make_engine,
    make_session_factory,
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


class ReviewReadEndpointTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        settings = Settings(
            jwt_secret="test-key-with-at-least-thirty-two-bytes",
            database_url=f"sqlite:///{Path(self.temp.name)/'review.db'}",
        )
        self.engine = make_engine(settings.database_url)
        self.addCleanup(self.engine.dispose)
        self.client = self.enterContext(TestClient(create_app(settings)))
        with make_session_factory(self.engine).begin() as session:
            BootstrapAdministrator(
                SqlAlchemyUserRepository(session),
                SqlAlchemyAdministratorRepository(session),
                Argon2PasswordHasher(),
            ).execute("admin", "test password")
        self.admin = self.login("admin")
        self.user = self.create(
            "/users", {"username": "alice", "password": "test password"}
        )
        self.other = self.create(
            "/users", {"username": "bob", "password": "test password"}
        )
        self.ordinary = self.login("alice")

    def login(self, username):
        response = self.client.post(
            "/auth/login", json={"username": username, "password": "test password"}
        )
        self.assertEqual(response.status_code, 200, response.text)
        return {"Authorization": f"Bearer {response.json()['access_token']}"}

    def create(self, path, body):
        response = self.client.post(path, json=body, headers=self.admin)
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()

    def test_membership_lists_are_filtered_paginated_and_do_not_expose_hashes(self):
        a = self.create("/groups", {"name": "a"})
        z = self.create("/groups", {"name": "z"})
        for group in (a, z):
            self.create(f"/groups/{group['id']}/members", {"user_id": self.user["id"]})
        self.create(f"/groups/{a['id']}/members", {"user_id": self.other["id"]})
        response = self.client.get(
            f"/users/{self.user['id']}/groups?limit=1&offset=1", headers=self.admin
        )
        self.assertEqual(response.json(), [z])
        response = self.client.get(
            f"/groups/{a['id']}/members?limit=1&offset=1", headers=self.admin
        )
        self.assertEqual(response.json(), [self.other])
        response = self.client.get(f"/groups/{z['id']}/members", headers=self.admin)
        self.assertEqual(response.json(), [self.user])
        self.assertNotIn("password_hash", response.text)
        self.assertEqual(response.headers["cache-control"], "no-store")

    def test_grant_lists_show_exact_subject_across_both_target_types(self):
        scope = self.create("/access-control/scopes", {"name": "orders"})
        permission = self.create(
            f"/access-control/scopes/{scope['id']}/permissions", {"name": "read"}
        )
        group = self.create("/groups", {"name": "staff"})
        grants = []
        for target, target_id in [
            ("scope", scope["id"]),
            ("permission", permission["id"]),
        ]:
            grants.append(
                self.create(
                    "/access-control/grants",
                    {
                        "subject_type": "user",
                        "subject_id": self.user["id"],
                        "target_type": target,
                        "target_id": target_id,
                    },
                )
            )
        self.create(
            "/access-control/grants",
            {
                "subject_type": "group",
                "subject_id": group["id"],
                "target_type": "scope",
                "target_id": scope["id"],
            },
        )
        path = f"/access-control/grants?subject_type=user&subject_id={self.user['id']}"
        response = self.client.get(path, headers=self.admin)
        self.assertEqual(response.json(), [grants[1], grants[0]])
        self.assertEqual(
            self.client.get(path + "&limit=1&offset=1", headers=self.admin).json(),
            [grants[0]],
        )
        self.assertEqual(
            self.client.get(
                f"/access-control/grants?subject_type=user&subject_id={self.other['id']}",
                headers=self.admin,
            ).json(),
            [],
        )
        self.assertEqual(
            self.client.get(path + "&offset=100", headers=self.admin).json(), []
        )

    def test_new_read_routes_are_administrator_only(self):
        paths = [
            f"/users/{self.user['id']}/groups",
            f"/groups/{uuid4()}/members",
            f"/access-control/grants?subject_type=user&subject_id={self.user['id']}",
        ]
        for path in paths:
            for headers, expected in [({}, 401), (self.ordinary, 403)]:
                with self.subTest(path=path, expected=expected):
                    self.assertEqual(
                        self.client.get(path, headers=headers).status_code, expected
                    )

    def test_missing_subjects_and_invalid_pagination_are_explicit(self):
        for path in (f"/users/{uuid4()}/groups", f"/groups/{uuid4()}/members"):
            self.assertEqual(self.client.get(path, headers=self.admin).status_code, 404)
        for path in (
            f"/users/{self.user['id']}/groups?limit=0",
            f"/groups/{uuid4()}/members?offset=-1",
            f"/access-control/grants?subject_type=admin&subject_id={self.user['id']}",
            "/access-control/grants?subject_type=user&subject_id=invalid",
        ):
            self.assertEqual(self.client.get(path, headers=self.admin).status_code, 422)
