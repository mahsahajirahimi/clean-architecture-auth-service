import os
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Barrier
from unittest.mock import Mock, patch
from uuid import uuid4

from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError

from auth_service.composition.bootstrap_admin import main
from auth_service.infrastructure.persistence.database import (
    Base,
    make_engine,
    make_session_factory,
)
from auth_service.modules.identity.application.exceptions import DuplicateUsernameError
from auth_service.modules.identity.application.use_cases.bootstrap_administrator import (
    BootstrapAdministrator,
)
from auth_service.modules.identity.domain.entities.user import User
from auth_service.modules.identity.infrastructure.persistence.models import (
    AdministratorModel,
    GroupMembershipModel,
    GroupModel,
    UserModel,
)
from auth_service.modules.identity.infrastructure.persistence.repositories import (
    SqlAlchemyAdministratorRepository,
    SqlAlchemyUserRepository,
)
from auth_service.modules.identity.infrastructure.security.argon2_password_hasher import (
    Argon2PasswordHasher,
)


class AdministratorBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.url = f"sqlite:///{Path(self.temp.name) / 'admin.db'}"
        self.engine = make_engine(self.url)
        self.addCleanup(self.engine.dispose)
        Base.metadata.create_all(self.engine)
        self.sessions = make_session_factory(self.engine)
        self.enterContext(patch.dict(os.environ, {"AUTH_DATABASE_URL": self.url}))

    def bootstrap(self, username="admin"):
        with self.sessions.begin() as session:
            return BootstrapAdministrator(
                SqlAlchemyUserRepository(session),
                SqlAlchemyAdministratorRepository(session),
                Argon2PasswordHasher(),
            ).execute(username, "test password")

    def test_command_creates_hashed_administrator_and_cannot_be_repeated(self):
        output = StringIO()
        with patch("builtins.input", return_value="admin"), patch(
            "auth_service.composition.bootstrap_admin.getpass",
            side_effect=["test password", "test password"],
        ), redirect_stdout(output):
            main()
        with self.sessions() as session:
            user = SqlAlchemyUserRepository(session).get_by_username("admin")
            self.assertEqual(
                SqlAlchemyAdministratorRepository(session).get_user_id(), user.id
            )
            self.assertTrue(
                Argon2PasswordHasher().verify("test password", user.password_hash)
            )
        self.assertNotIn("test password", output.getvalue())
        self.assertNotIn(user.password_hash, output.getvalue())
        with patch("builtins.input") as prompt, self.assertRaisesRegex(
            SystemExit, "already completed"
        ):
            main()
        prompt.assert_not_called()
        with self.sessions() as session:
            self.assertEqual(
                session.scalar(select(func.count()).select_from(UserModel)), 1
            )

    def test_password_confirmation_failure_leaves_no_user_or_administrator(self):
        with patch("builtins.input", return_value="admin"), patch(
            "auth_service.composition.bootstrap_admin.getpass",
            side_effect=["first", "second"],
        ), self.assertRaisesRegex(SystemExit, "Passwords do not match"):
            main()
        with self.sessions() as session:
            self.assertIsNone(SqlAlchemyAdministratorRepository(session).get_user_id())
            self.assertIsNone(
                SqlAlchemyUserRepository(session).get_by_username("admin")
            )

    def test_existing_username_is_never_promoted_or_overwritten(self):
        original = User(uuid4(), "existing", "original-hash")
        with self.sessions.begin() as session:
            SqlAlchemyUserRepository(session).save(original)
        with self.assertRaises(DuplicateUsernameError):
            self.bootstrap("existing")
        with self.sessions() as session:
            self.assertEqual(
                SqlAlchemyUserRepository(session).get_by_id(original.id), original
            )
            self.assertIsNone(SqlAlchemyAdministratorRepository(session).get_user_id())
        self.bootstrap("new-admin")

    def test_concurrent_bootstraps_commit_exactly_one_administrator_and_user(self):
        barrier = Barrier(2, timeout=5)

        class RacingAdministratorRepository(SqlAlchemyAdministratorRepository):
            def get_user_id(self):
                value = super().get_user_id()
                barrier.wait()
                return value

        def attempt(username):
            try:
                with self.sessions.begin() as session:
                    passwords = Mock()
                    passwords.hash.return_value = "hashed-password"
                    user = BootstrapAdministrator(
                        SqlAlchemyUserRepository(session),
                        RacingAdministratorRepository(session),
                        passwords,
                    ).execute(username, "password")
                return user.id
            except IntegrityError:
                return None

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(attempt, ["first", "second"]))
        winners = [result for result in results if result is not None]
        self.assertEqual(len(winners), 1)
        with self.sessions() as session:
            self.assertEqual(
                SqlAlchemyAdministratorRepository(session).get_user_id(), winners[0]
            )
            self.assertEqual(
                session.scalar(select(func.count()).select_from(UserModel)), 1
            )

    def test_initialization_failure_rolls_back_created_user(self):
        with self.assertRaises(IntegrityError):
            with self.sessions.begin() as session:
                users = SqlAlchemyUserRepository(session)
                administrators = SqlAlchemyAdministratorRepository(session)
                user = User(uuid4(), "rolled-back", "hash")
                users.save(user)
                administrators.initialize(uuid4())
        with self.sessions() as session:
            self.assertIsNone(
                SqlAlchemyUserRepository(session).get_by_username("rolled-back")
            )
            self.assertIsNone(SqlAlchemyAdministratorRepository(session).get_user_id())

    def test_administrator_cannot_be_deleted_to_reopen_bootstrap(self):
        admin = self.bootstrap()
        with self.assertRaises(IntegrityError):
            with self.sessions.begin() as session:
                session.execute(delete(UserModel).where(UserModel.id == str(admin.id)))
        with self.sessions() as session:
            self.assertEqual(
                SqlAlchemyAdministratorRepository(session).get_user_id(), admin.id
            )

    def test_database_rejects_non_singleton_administrator_id(self):
        user = User(uuid4(), "user", "hash")
        with self.sessions.begin() as session:
            SqlAlchemyUserRepository(session).save(user)
        with self.assertRaises(IntegrityError):
            with self.sessions.begin() as session:
                session.add(AdministratorModel(id=2, user_id=str(user.id)))
                session.flush()

    def test_bootstrap_adds_table_to_existing_identity_database_without_data_loss(self):
        legacy_url = f"sqlite:///{Path(self.temp.name) / 'existing.db'}"
        legacy_engine = make_engine(legacy_url)
        self.addCleanup(legacy_engine.dispose)
        Base.metadata.create_all(
            legacy_engine,
            tables=[
                UserModel.__table__,
                GroupModel.__table__,
                GroupMembershipModel.__table__,
            ],
        )
        sessions = make_session_factory(legacy_engine)
        existing = User(uuid4(), "existing-user", "stored-hash")
        with sessions.begin() as session:
            SqlAlchemyUserRepository(session).save(existing)
        with patch.dict(os.environ, {"AUTH_DATABASE_URL": legacy_url}), patch(
            "builtins.input", return_value="admin"
        ), patch(
            "auth_service.composition.bootstrap_admin.getpass",
            side_effect=["password", "password"],
        ), redirect_stdout(
            StringIO()
        ):
            main()
        with sessions() as session:
            self.assertEqual(
                SqlAlchemyUserRepository(session).get_by_id(existing.id), existing
            )
            admin = SqlAlchemyUserRepository(session).get_by_username("admin")
            self.assertEqual(
                SqlAlchemyAdministratorRepository(session).get_user_id(), admin.id
            )
