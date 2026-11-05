import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import uuid4

from auth_service.infrastructure.persistence.database import (
    Base,
    make_engine,
    make_session_factory,
)
from auth_service.modules.identity.domain.entities.group import Group
from auth_service.modules.identity.domain.entities.membership import GroupMembership
from auth_service.modules.identity.domain.entities.user import User
from auth_service.modules.identity.infrastructure.persistence.repositories import (
    SqlAlchemyGroupRepository,
    SqlAlchemyMembershipRepository,
    SqlAlchemyUserRepository,
)


class IdentityManagementPersistenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.engine = make_engine(f"sqlite:///{Path(self.temp.name) / 'test.db'}")
        self.addCleanup(self.engine.dispose)
        Base.metadata.create_all(self.engine)
        self.sessions = make_session_factory(self.engine)
        self.users = [
            User(uuid4(), name, "hash", is_active=name != "b")
            for name in ("c", "a", "b")
        ]
        self.groups = [Group(uuid4(), name) for name in ("z", "x", "y")]
        with self.sessions.begin() as session:
            for user in self.users:
                SqlAlchemyUserRepository(session).save(user)
            for group in self.groups:
                SqlAlchemyGroupRepository(session).save(group)
            for group in self.groups:
                SqlAlchemyMembershipRepository(session).save(
                    GroupMembership(self.users[0].id, group.id)
                )

    def test_list_users_is_sorted_paginated_and_includes_inactive_users(self):
        with self.sessions() as session:
            users = SqlAlchemyUserRepository(session)
            self.assertEqual([u.username for u in users.list(100, 0)], ["a", "b", "c"])
            page = users.list(1, 1)
            self.assertEqual(page[0].username, "b")
            self.assertFalse(page[0].is_active)
            self.assertEqual(users.list(10, 100), [])

    def test_list_groups_is_sorted_and_paginated(self):
        with self.sessions() as session:
            groups = SqlAlchemyGroupRepository(session)
            self.assertEqual([g.name for g in groups.list(100, 0)], ["x", "y", "z"])
            self.assertEqual([g.name for g in groups.list(1, 1)], ["y"])
            self.assertEqual(groups.list(10, 100), [])

    def test_removal_persists_without_deleting_parents_or_other_memberships(self):
        user_id, group_id = self.users[0].id, self.groups[0].id
        with self.sessions.begin() as session:
            self.assertTrue(
                SqlAlchemyMembershipRepository(session).remove(user_id, group_id)
            )
        with self.sessions() as session:
            memberships = SqlAlchemyMembershipRepository(session)
            self.assertFalse(memberships.exists(user_id, group_id))
            self.assertTrue(memberships.exists(user_id, self.groups[1].id))
            self.assertIsNotNone(SqlAlchemyUserRepository(session).get_by_id(user_id))
            self.assertIsNotNone(SqlAlchemyGroupRepository(session).get_by_id(group_id))
            self.assertFalse(memberships.remove(user_id, group_id))

    def test_membership_removal_is_rolled_back_without_commit(self):
        user_id, group_id = self.users[0].id, self.groups[0].id
        with self.sessions() as session:
            self.assertTrue(
                SqlAlchemyMembershipRepository(session).remove(user_id, group_id)
            )
            session.rollback()
        with self.sessions() as session:
            self.assertTrue(
                SqlAlchemyMembershipRepository(session).exists(user_id, group_id)
            )
