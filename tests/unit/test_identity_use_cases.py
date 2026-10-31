
import unittest
from unittest.mock import Mock
from uuid import uuid4

from auth_service.modules.identity.domain.entities.user import User
from auth_service.modules.identity.domain.entities.group import Group

from auth_service.modules.identity.application.ports import (
    UserRepository,
    GroupRepository,
    MembershipRepository,
    PasswordHasher,
)
from auth_service.modules.identity.application.exceptions import (
    DuplicateUsernameError,
    DuplicateGroupError,
    InvalidInputError,
    UserNotFoundError,
    GroupNotFoundError,
    MembershipAlreadyExistsError,
)
from auth_service.modules.identity.application.use_cases.create_user import CreateUser
from auth_service.modules.identity.application.use_cases.create_group import CreateGroup
from auth_service.modules.identity.application.use_cases.add_user_to_group import AddUserToGroup


class IdentityUseCaseTests(unittest.TestCase):

    def setUp(self):
        self.users = Mock(spec=UserRepository)
        self.groups = Mock(spec=GroupRepository)
        self.memberships = Mock(spec=MembershipRepository)
        self.hasher = Mock(spec=PasswordHasher)

        self.user = User(
            id=uuid4(),
            username="ali",
            password_hash="stored-hash",
        )
        self.group = Group(id=uuid4(), name="employees")

        self.users.get_by_username.return_value = None
        self.users.get_by_id.return_value = self.user
        self.groups.get_by_name.return_value = None
        self.groups.get_by_id.return_value = self.group
        self.memberships.exists.return_value = False
        self.hasher.hash.return_value = "hashed-password"

    def test_create_user(self):
        result = CreateUser(self.users, self.hasher).execute(
            " ali ", "password123"
        )

        self.assertEqual(result.username, "ali")
        self.assertEqual(result.password_hash, "hashed-password")
        self.hasher.hash.assert_called_once_with("password123")
        self.users.save.assert_called_once_with(result)

    def test_duplicate_username(self):
        self.users.get_by_username.return_value = self.user

        with self.assertRaises(DuplicateUsernameError):
            CreateUser(self.users, self.hasher).execute(
                "ali", "password123"
            )

        self.users.save.assert_not_called()

    def test_empty_password(self):
        with self.assertRaises(InvalidInputError):
            CreateUser(self.users, self.hasher).execute(
                "ali", " "
            )

        self.users.save.assert_not_called()

    def test_create_group(self):
        result = CreateGroup(self.groups).execute(" employees ")

        self.assertEqual(result.name, "employees")
        self.groups.save.assert_called_once_with(result)

    def test_duplicate_group(self):
        self.groups.get_by_name.return_value = self.group

        with self.assertRaises(DuplicateGroupError):
            CreateGroup(self.groups).execute("employees")

        self.groups.save.assert_not_called()

    def test_add_user_to_group(self):
        result = AddUserToGroup(
            self.users, self.groups, self.memberships
        ).execute(self.user.id, self.group.id)

        self.assertEqual(result.user_id, self.user.id)
        self.assertEqual(result.group_id, self.group.id)
        self.memberships.save.assert_called_once_with(result)

    def test_user_not_found(self):
        self.users.get_by_id.return_value = None

        with self.assertRaises(UserNotFoundError):
            AddUserToGroup(
                self.users, self.groups, self.memberships
            ).execute(uuid4(), self.group.id)

        self.memberships.save.assert_not_called()

    def test_group_not_found(self):
        self.groups.get_by_id.return_value = None

        with self.assertRaises(GroupNotFoundError):
            AddUserToGroup(
                self.users, self.groups, self.memberships
            ).execute(self.user.id, uuid4())

        self.memberships.save.assert_not_called()

    def test_duplicate_membership(self):
        self.memberships.exists.return_value = True

        with self.assertRaises(MembershipAlreadyExistsError):
            AddUserToGroup(
                self.users, self.groups, self.memberships
            ).execute(self.user.id, self.group.id)

        self.memberships.save.assert_not_called()


if __name__ == "__main__":
    unittest.main()
