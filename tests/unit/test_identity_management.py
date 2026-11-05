import unittest
from unittest.mock import Mock
from uuid import uuid4

from auth_service.modules.identity.application.exceptions import (
    GroupNotFoundError,
    InvalidInputError,
    MembershipNotFoundError,
    ProtectedAdministratorError,
    UserNotFoundError,
)
from auth_service.modules.identity.application.ports import (
    AdministratorRepository,
    GroupRepository,
    MembershipRepository,
    UserRepository,
)
from auth_service.modules.identity.application.use_cases.get_group import GetGroup
from auth_service.modules.identity.application.use_cases.get_user import GetUser
from auth_service.modules.identity.application.use_cases.list_groups import ListGroups
from auth_service.modules.identity.application.use_cases.list_users import ListUsers
from auth_service.modules.identity.application.use_cases.remove_user_from_group import (
    RemoveUserFromGroup,
)
from auth_service.modules.identity.application.use_cases.set_user_status import (
    SetUserStatus,
)
from auth_service.modules.identity.domain.entities.group import Group
from auth_service.modules.identity.domain.entities.user import User


class IdentityManagementTests(unittest.TestCase):
    def setUp(self):
        self.users = Mock(spec=UserRepository)
        self.groups = Mock(spec=GroupRepository)
        self.memberships = Mock(spec=MembershipRepository)
        self.administrators = Mock(spec=AdministratorRepository)
        self.user = User(uuid4(), "ali", "stored-hash")
        self.group = Group(uuid4(), "staff")
        self.users.get_by_id.return_value = self.user
        self.groups.get_by_id.return_value = self.group
        self.administrators.get_user_id.return_value = uuid4()

    def test_get_user_and_group(self):
        self.assertEqual(GetUser(self.users).execute(self.user.id), self.user)
        self.assertEqual(GetGroup(self.groups).execute(self.group.id), self.group)
        self.users.get_by_id.assert_called_once_with(self.user.id)
        self.groups.get_by_id.assert_called_once_with(self.group.id)

    def test_get_missing_user_and_group(self):
        self.users.get_by_id.return_value = None
        self.groups.get_by_id.return_value = None
        with self.assertRaises(UserNotFoundError):
            GetUser(self.users).execute(uuid4())
        with self.assertRaises(GroupNotFoundError):
            GetGroup(self.groups).execute(uuid4())

    def test_lists_pass_validated_pagination_to_repositories(self):
        self.users.list.return_value = [self.user]
        self.groups.list.return_value = [self.group]
        self.assertEqual(ListUsers(self.users).execute(), [self.user])
        self.users.list.assert_called_once_with(50, 0)
        self.assertEqual(ListGroups(self.groups).execute(10, 5), [self.group])
        self.groups.list.assert_called_once_with(10, 5)

    def test_lists_reject_invalid_pagination_before_querying(self):
        for use_case, repository in [
            (ListUsers(self.users), self.users),
            (ListGroups(self.groups), self.groups),
        ]:
            for limit, offset in [
                (0, 0),
                (101, 0),
                (True, 0),
                ("5", 0),
                (5, -1),
                (5, True),
                (5, 1.5),
            ]:
                with self.subTest(limit=limit, offset=offset):
                    with self.assertRaises(InvalidInputError):
                        use_case.execute(limit, offset)
            repository.list.assert_not_called()

    def test_status_changes_are_immutable_and_preserve_credentials(self):
        use_case = SetUserStatus(self.users, self.administrators)
        disabled = use_case.execute(self.user.id, False)
        self.assertTrue(self.user.is_active)
        self.assertFalse(disabled.is_active)
        self.assertEqual(disabled.password_hash, self.user.password_hash)
        self.users.save.assert_called_once_with(disabled)
        self.users.get_by_id.return_value = disabled
        self.assertEqual(use_case.execute(self.user.id, True), self.user)

    def test_status_same_value_does_not_save(self):
        self.assertEqual(
            SetUserStatus(self.users, self.administrators).execute(self.user.id, True),
            self.user,
        )
        self.users.save.assert_not_called()

    def test_status_rejects_missing_users_and_non_boolean_values(self):
        use_case = SetUserStatus(self.users, self.administrators)
        for value in (1, "false", None):
            with self.subTest(value=value):
                with self.assertRaises(InvalidInputError):
                    use_case.execute(self.user.id, value)
        self.users.get_by_id.return_value = None
        with self.assertRaises(UserNotFoundError):
            use_case.execute(self.user.id, False)
        self.users.save.assert_not_called()

    def test_initial_administrator_cannot_be_deactivated(self):
        self.administrators.get_user_id.return_value = self.user.id
        with self.assertRaises(ProtectedAdministratorError):
            SetUserStatus(self.users, self.administrators).execute(self.user.id, False)
        self.users.save.assert_not_called()

    def test_remove_membership(self):
        self.memberships.remove.return_value = True
        RemoveUserFromGroup(self.users, self.groups, self.memberships).execute(
            self.user.id, self.group.id
        )
        self.memberships.remove.assert_called_once_with(self.user.id, self.group.id)

    def test_remove_missing_membership(self):
        self.memberships.remove.return_value = False
        with self.assertRaises(MembershipNotFoundError):
            RemoveUserFromGroup(self.users, self.groups, self.memberships).execute(
                self.user.id, self.group.id
            )

    def test_remove_checks_user_and_group_before_deleting(self):
        use_case = RemoveUserFromGroup(self.users, self.groups, self.memberships)
        self.users.get_by_id.return_value = None
        with self.assertRaises(UserNotFoundError):
            use_case.execute(self.user.id, self.group.id)
        self.users.get_by_id.return_value = self.user
        self.groups.get_by_id.return_value = None
        with self.assertRaises(GroupNotFoundError):
            use_case.execute(self.user.id, self.group.id)
        self.memberships.remove.assert_not_called()
