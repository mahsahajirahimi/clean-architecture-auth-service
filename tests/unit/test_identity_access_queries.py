import unittest
from dataclasses import asdict
from unittest.mock import Mock
from uuid import uuid4

from auth_service.modules.identity.application.access_queries import (
    IdentityAccessQueries,
)
from auth_service.modules.identity.application.ports import (
    GroupRepository,
    MembershipRepository,
    UserRepository,
)
from auth_service.modules.identity.domain.entities.group import Group
from auth_service.modules.identity.domain.entities.user import User


class IdentityAccessQueriesTests(unittest.TestCase):
    def setUp(self):
        self.users = Mock(spec=UserRepository)
        self.groups = Mock(spec=GroupRepository)
        self.memberships = Mock(spec=MembershipRepository)
        self.queries = IdentityAccessQueries(self.users, self.groups, self.memberships)

    def test_context_exposes_only_activity_and_membership_data(self):
        user = User(uuid4(), "ali", "private-password-hash", False)
        group = Group(uuid4(), "staff")
        self.users.get_by_id.return_value = user
        self.groups.get_by_id.return_value = group
        self.memberships.list_group_ids.return_value = frozenset({group.id})
        context = self.queries.get_user_context(user.id)
        self.assertEqual(
            asdict(context),
            {
                "user_id": user.id,
                "is_active": False,
                "group_ids": frozenset({group.id}),
            },
        )
        self.assertNotIn(user.password_hash, repr(context))
        self.memberships.list_group_ids.assert_called_once_with(user.id)
        self.assertTrue(self.queries.group_exists(group.id))
        self.groups.get_by_id.assert_called_once_with(group.id)

    def test_missing_user_does_not_query_memberships_and_missing_group_is_false(self):
        self.users.get_by_id.return_value = None
        self.groups.get_by_id.return_value = None
        self.assertIsNone(self.queries.get_user_context(uuid4()))
        self.memberships.list_group_ids.assert_not_called()
        self.assertFalse(self.queries.group_exists(uuid4()))
