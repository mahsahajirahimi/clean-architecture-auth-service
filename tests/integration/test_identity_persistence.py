import unittest
from tempfile import TemporaryDirectory
from pathlib import Path
from uuid import uuid4

from sqlalchemy import delete, text
from sqlalchemy.exc import IntegrityError

from auth_service.infrastructure.persistence.database import (
    Base, make_engine, make_session_factory,
)
from auth_service.modules.identity.application.use_cases.create_user import CreateUser
from auth_service.modules.identity.application.use_cases.create_group import CreateGroup
from auth_service.modules.identity.application.use_cases.add_user_to_group import AddUserToGroup
from auth_service.modules.identity.domain.entities.user import User
from auth_service.modules.identity.domain.entities.group import Group
from auth_service.modules.identity.domain.entities.membership import GroupMembership
from auth_service.modules.identity.infrastructure.persistence.models import UserModel, GroupModel
from auth_service.modules.identity.infrastructure.persistence.repositories import (
    SqlAlchemyUserRepository, SqlAlchemyGroupRepository, SqlAlchemyMembershipRepository,
)
from auth_service.modules.identity.infrastructure.security.argon2_password_hasher import Argon2PasswordHasher


class IdentityPersistenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.engine = make_engine(f"sqlite:///{Path(self.temp.name) / 'test.db'}")
        self.addCleanup(self.engine.dispose)
        Base.metadata.create_all(self.engine)
        self.sessions = make_session_factory(self.engine)
        self.user = User(uuid4(), "ali", "stored-hash")
        self.group = Group(uuid4(), "staff")

    def seed(self):
        with self.sessions.begin() as session:
            SqlAlchemyUserRepository(session).save(self.user)
            SqlAlchemyGroupRepository(session).save(self.group)

    def test_create_user_through_use_case_and_reload(self):
        hasher = Argon2PasswordHasher()
        with self.sessions.begin() as session:
            user = CreateUser(SqlAlchemyUserRepository(session), hasher).execute(" ali ", "secret")
        with self.sessions() as session:
            users = SqlAlchemyUserRepository(session)
            stored = users.get_by_id(user.id)
            self.assertEqual(stored, user)
            self.assertEqual(users.get_by_username("ali"), user)
            self.assertNotEqual(stored.password_hash, "secret")
            self.assertTrue(stored.password_hash.startswith("$argon2id$"))
            self.assertTrue(hasher.verify("secret", stored.password_hash))

    def test_password_verification_rejects_wrong_and_malformed_hashes(self):
        hasher = Argon2PasswordHasher()
        encoded = hasher.hash("secret")
        self.assertFalse(hasher.verify("wrong", encoded))
        for malformed in ("", "not-a-hash", "$argon2id$broken"):
            with self.subTest(hash=malformed):
                self.assertFalse(hasher.verify("secret", malformed))
        self.assertNotEqual(encoded, hasher.hash("secret"))

    def test_create_group_and_membership_through_use_cases(self):
        with self.sessions.begin() as session:
            users = SqlAlchemyUserRepository(session)
            groups = SqlAlchemyGroupRepository(session)
            users.save(self.user)
            group = CreateGroup(groups).execute(" staff ")
            AddUserToGroup(users, groups, SqlAlchemyMembershipRepository(session)).execute(self.user.id, group.id)
        with self.sessions() as session:
            groups = SqlAlchemyGroupRepository(session)
            self.assertEqual(groups.get_by_id(group.id), group)
            self.assertEqual(groups.get_by_name("staff"), group)
            self.assertTrue(SqlAlchemyMembershipRepository(session).exists(self.user.id, group.id))

    def test_update_user_status(self):
        self.seed()
        with self.sessions.begin() as session:
            SqlAlchemyUserRepository(session).save(self.user.deactivate())
        with self.sessions() as session:
            self.assertEqual(SqlAlchemyUserRepository(session).get_by_id(self.user.id), self.user.deactivate())

    def test_duplicate_username_constraint(self):
        self.seed()
        with self.assertRaises(IntegrityError):
            with self.sessions.begin() as session:
                SqlAlchemyUserRepository(session).save(User(uuid4(), self.user.username, "other-hash"))

    def test_duplicate_group_name_constraint(self):
        self.seed()
        with self.assertRaises(IntegrityError):
            with self.sessions.begin() as session:
                SqlAlchemyGroupRepository(session).save(Group(uuid4(), self.group.name))

    def test_membership_requires_existing_user_and_group(self):
        self.seed()
        for user_id, group_id in [(uuid4(), self.group.id), (self.user.id, uuid4())]:
            with self.subTest(user_id=user_id, group_id=group_id):
                with self.assertRaises(IntegrityError):
                    with self.sessions.begin() as session:
                        SqlAlchemyMembershipRepository(session).save(GroupMembership(user_id, group_id))

    def test_duplicate_membership_constraint(self):
        self.seed()
        membership = GroupMembership(self.user.id, self.group.id)
        with self.sessions.begin() as session:
            SqlAlchemyMembershipRepository(session).save(membership)
        with self.assertRaises(IntegrityError):
            with self.sessions.begin() as session:
                SqlAlchemyMembershipRepository(session).save(membership)

    def test_deleting_either_parent_cascades_memberships(self):
        for model, entity in [(UserModel, self.user), (GroupModel, self.group)]:
            with self.subTest(model=model.__name__):
                self.seed()
                with self.sessions.begin() as session:
                    SqlAlchemyMembershipRepository(session).save(GroupMembership(self.user.id, self.group.id))
                with self.sessions.begin() as session:
                    session.execute(delete(model).where(model.id == str(entity.id)))
                with self.sessions() as session:
                    self.assertFalse(SqlAlchemyMembershipRepository(session).exists(self.user.id, self.group.id))

    def test_repositories_do_not_commit(self):
        with self.sessions() as session:
            SqlAlchemyUserRepository(session).save(self.user)
            SqlAlchemyGroupRepository(session).save(self.group)
            SqlAlchemyMembershipRepository(session).save(GroupMembership(self.user.id, self.group.id))
            session.rollback()
        with self.sessions() as session:
            self.assertIsNone(SqlAlchemyUserRepository(session).get_by_id(self.user.id))
            self.assertIsNone(SqlAlchemyGroupRepository(session).get_by_id(self.group.id))
            self.assertFalse(SqlAlchemyMembershipRepository(session).exists(self.user.id, self.group.id))

    def test_transaction_rolls_back_all_writes_on_failure(self):
        with self.assertRaises(IntegrityError):
            with self.sessions.begin() as session:
                SqlAlchemyUserRepository(session).save(self.user)
                SqlAlchemyGroupRepository(session).save(self.group)
                SqlAlchemyMembershipRepository(session).save(GroupMembership(uuid4(), self.group.id))
        with self.sessions() as session:
            self.assertIsNone(SqlAlchemyUserRepository(session).get_by_username(self.user.username))
            self.assertIsNone(SqlAlchemyGroupRepository(session).get_by_name(self.group.name))

    def test_missing_records(self):
        with self.sessions() as session:
            users = SqlAlchemyUserRepository(session)
            groups = SqlAlchemyGroupRepository(session)
            self.assertIsNone(users.get_by_id(uuid4()))
            self.assertIsNone(users.get_by_username("missing"))
            self.assertIsNone(groups.get_by_id(uuid4()))
            self.assertIsNone(groups.get_by_name("missing"))
            self.assertFalse(SqlAlchemyMembershipRepository(session).exists(uuid4(), uuid4()))

    def test_foreign_keys_enabled_on_each_connection(self):
        with self.engine.connect() as first, self.engine.connect() as second:
            self.assertEqual(first.scalar(text("PRAGMA foreign_keys")), 1)
            self.assertEqual(second.scalar(text("PRAGMA foreign_keys")), 1)


if __name__ == "__main__":
    unittest.main()
