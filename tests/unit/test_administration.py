import unittest
from unittest.mock import Mock
from uuid import uuid4

from auth_service.modules.identity.application.exceptions import (
    AdministratorRequiredError,
    BootstrapAlreadyCompletedError,
    InvalidInputError,
)
from auth_service.modules.identity.application.ports import (
    AdministratorRepository,
    GroupRepository,
    PasswordHasher,
    UserRepository,
)
from auth_service.modules.identity.application.use_cases.bootstrap_administrator import (
    BootstrapAdministrator,
)
from auth_service.modules.identity.application.use_cases.create_group import CreateGroup
from auth_service.modules.identity.application.use_cases.create_user import CreateUser
from auth_service.modules.identity.application.use_cases.require_administrator import (
    RequireAdministrator,
)
from auth_service.modules.identity.domain.entities.user import User


class AdministrationTests(unittest.TestCase):
    def test_bootstrap_creates_user_then_initializes_administrator(self):
        users = Mock(spec=UserRepository)
        users.get_by_username.return_value = None
        administrators = Mock(spec=AdministratorRepository)
        administrators.get_user_id.return_value = None
        passwords = Mock(spec=PasswordHasher)
        passwords.hash.return_value = "hashed-password"
        user = BootstrapAdministrator(users, administrators, passwords).execute(
            " admin ", "password"
        )
        self.assertEqual(user.username, "admin")
        self.assertEqual(user.password_hash, "hashed-password")
        users.save.assert_called_once_with(user)
        administrators.initialize.assert_called_once_with(user.id)

    def test_repeated_bootstrap_does_not_create_or_hash_anything(self):
        users = Mock(spec=UserRepository)
        passwords = Mock(spec=PasswordHasher)
        administrators = Mock(spec=AdministratorRepository)
        administrators.get_user_id.return_value = uuid4()
        with self.assertRaises(BootstrapAlreadyCompletedError):
            BootstrapAdministrator(users, administrators, passwords).execute(
                "another", "password"
            )
        users.save.assert_not_called()
        passwords.hash.assert_not_called()
        administrators.initialize.assert_not_called()

    def test_require_administrator_accepts_only_the_active_administrator(self):
        user = User(uuid4(), "admin", "hash")
        administrators = Mock(spec=AdministratorRepository)
        administrators.get_user_id.return_value = user.id
        self.assertEqual(RequireAdministrator(administrators).execute(user), user)
        for candidate in (user.deactivate(), User(uuid4(), "other", "hash")):
            with self.subTest(candidate=candidate.username):
                with self.assertRaises(AdministratorRequiredError):
                    RequireAdministrator(administrators).execute(candidate)

    def test_no_bootstrapped_administrator_means_no_administrator_access(self):
        administrators = Mock(spec=AdministratorRepository)
        administrators.get_user_id.return_value = None
        with self.assertRaises(AdministratorRequiredError):
            RequireAdministrator(administrators).execute(User(uuid4(), "admin", "hash"))

    def test_create_user_enforces_login_length_limits_in_application(self):
        users = Mock(spec=UserRepository)
        passwords = Mock(spec=PasswordHasher)
        for username, password in [("u" * 256, "password"), ("user", "p" * 1025)]:
            with self.subTest(username_length=len(username)):
                with self.assertRaises(InvalidInputError):
                    CreateUser(users, passwords).execute(username, password)
        users.save.assert_not_called()
        passwords.hash.assert_not_called()

    def test_group_name_length_limit_in_application(self):
        groups = Mock(spec=GroupRepository)
        with self.assertRaises(InvalidInputError):
            CreateGroup(groups).execute("x" * 256)
        groups.save.assert_not_called()
