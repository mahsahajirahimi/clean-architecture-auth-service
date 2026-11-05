import os
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from auth_service.composition.create_user import main
from auth_service.infrastructure.persistence.database import (
    make_engine,
    make_session_factory,
)
from auth_service.modules.identity.infrastructure.persistence.repositories import (
    SqlAlchemyUserRepository,
)
from auth_service.modules.identity.infrastructure.security.argon2_password_hasher import (
    Argon2PasswordHasher,
)


class CreateUserCommandTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.database_path = Path(self.temp.name) / "cli.db"
        self.database_url = f"sqlite:///{self.database_path}"
        self.enterContext(
            patch.dict(os.environ, {"AUTH_DATABASE_URL": self.database_url})
        )

    def run_command(self, username="ali", passwords=("test password", "test password")):
        output = StringIO()
        with patch("builtins.input", return_value=username), patch(
            "auth_service.composition.create_user.getpass", side_effect=passwords
        ), redirect_stdout(output):
            main()
        return output.getvalue()

    def test_creates_user_with_hashed_password_without_printing_secrets(self):
        output = self.run_command()
        engine = make_engine(self.database_url)
        self.addCleanup(engine.dispose)
        with make_session_factory(engine)() as session:
            user = SqlAlchemyUserRepository(session).get_by_username("ali")
            self.assertIsNotNone(user)
            self.assertTrue(
                Argon2PasswordHasher().verify("test password", user.password_hash)
            )
        self.assertIn(str(user.id), output)
        self.assertNotIn("test password", output)
        self.assertNotIn(user.password_hash, output)

    def test_mismatched_passwords_do_not_create_database(self):
        with self.assertRaisesRegex(SystemExit, "Passwords do not match"):
            self.run_command(passwords=("first", "second"))
        self.assertFalse(self.database_path.exists())

    def test_duplicate_username_exits_without_overwriting_password(self):
        self.run_command()
        with self.assertRaisesRegex(SystemExit, "Username already exists"):
            self.run_command(passwords=("different password", "different password"))
        engine = make_engine(self.database_url)
        self.addCleanup(engine.dispose)
        with make_session_factory(engine)() as session:
            user = SqlAlchemyUserRepository(session).get_by_username("ali")
            self.assertTrue(
                Argon2PasswordHasher().verify("test password", user.password_hash)
            )

    def test_rejects_credentials_that_cannot_be_used_at_login(self):
        with self.assertRaisesRegex(SystemExit, "input limit"):
            self.run_command(passwords=("x" * 1025, "x" * 1025))
        self.assertFalse(self.database_path.exists())
