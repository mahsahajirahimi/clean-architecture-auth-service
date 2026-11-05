import ast
import unittest
from pathlib import Path
from uuid import uuid4

import jwt

from auth_service.modules.identity.application.exceptions import InvalidTokenError
from auth_service.modules.identity.domain.entities.group import Group
from auth_service.modules.identity.domain.entities.user import User
from auth_service.modules.identity.infrastructure.security.jwt_tokens import JwtTokens


class FinalReviewTests(unittest.TestCase):
    def test_domain_string_fields_reject_non_strings_consistently(self):
        for value in (42, True, [], None):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    User(uuid4(), value, "hash")
                with self.assertRaises(ValueError):
                    User(uuid4(), "user", value)
                with self.assertRaises(ValueError):
                    Group(uuid4(), value)

    def test_unbounded_numeric_dates_are_rejected_as_invalid_tokens(self):
        secret = "test-secret-with-at-least-thirty-two-bytes"
        service = JwtTokens(secret, "issuer", "audience")
        good = jwt.decode(
            service.issue(uuid4()).access_token,
            secret,
            algorithms=["HS256"],
            issuer="issuer",
            audience="audience",
        )
        for field in ("exp", "iat", "nbf"):
            for value in (float("inf"), float("-inf")):
                with self.subTest(field=field, value=value):
                    token = jwt.encode(
                        {**good, field: value}, secret, algorithm="HS256"
                    )
                    with self.assertRaises(InvalidTokenError):
                        service.verify(token)

    def test_inner_layers_remain_independent_of_frameworks_and_outer_layers(self):
        root = Path(__file__).resolve().parents[2] / "src/auth_service/modules"
        forbidden = (
            "fastapi",
            "sqlalchemy",
            "pydantic",
            "argon2",
            "jwt",
            ".infrastructure",
            ".presentation",
            ".composition",
        )
        for path in root.rglob("*.py"):
            if "/domain/" not in str(path) and "/application/" not in str(path):
                continue
            for module in self.imports(path):
                self.assertFalse(
                    any(name in module for name in forbidden), f"{path}: {module}"
                )

    def test_access_control_does_not_import_identity_storage_or_domain(self):
        root = (
            Path(__file__).resolve().parents[2]
            / "src/auth_service/modules/access_control"
        )
        for path in root.rglob("*.py"):
            for module in self.imports(path):
                if module.startswith("auth_service.modules.identity."):
                    self.assertTrue(
                        module.startswith("auth_service.modules.identity.application."),
                        f"{path}: {module}",
                    )

    def test_repositories_do_not_commit_or_rollback(self):
        root = Path(__file__).resolve().parents[2] / "src/auth_service/modules"
        for path in root.glob("*/infrastructure/persistence/repositories.py"):
            for node in ast.walk(ast.parse(path.read_text())):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    self.assertNotIn(node.func.attr, ("commit", "rollback"), str(path))

    @staticmethod
    def imports(path):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.ImportFrom):
                yield node.module or ""
            elif isinstance(node, ast.Import):
                yield from (alias.name for alias in node.names)
