
import unittest
from uuid import uuid4

from auth_service.modules.identity.domain.entities.group import Group
from auth_service.modules.identity.domain.entities.membership import GroupMembership
from auth_service.modules.identity.domain.entities.user import User


class IdentityEntityTests(unittest.TestCase):

    def test_user_can_be_created(self):
        user = User(
            id=uuid4(),
            username="ali",
            password_hash="hashed-value"
        )
        self.assertEqual(user.username, "ali")
        self.assertTrue(user.is_active)

    def test_username_cannot_be_blank(self):
        with self.assertRaises(ValueError):
            User(
                id=uuid4(),
                username="   ",
                password_hash="hashed-value"
            )

    def test_password_hash_cannot_be_blank(self):
        with self.assertRaises(ValueError):
            User(
                id=uuid4(),
                username="ali",
                password_hash=" "
            )

    def test_user_can_be_deactivated_immutably(self):
        user = User(
            id=uuid4(),
            username="ali",
            password_hash="hashed-value"
        )
        updated = user.deactivate()

        self.assertFalse(updated.is_active)
        self.assertTrue(user.is_active)
        self.assertEqual(updated.id, user.id)
        self.assertTrue(updated.activate().is_active)

    def test_group_name_cannot_be_blank(self):
        with self.assertRaises(ValueError):
            Group(id=uuid4(), name=" ")

    def test_membership_references_user_and_group(self):
        user_id, group_id = uuid4(), uuid4()
        membership = GroupMembership(
            user_id=user_id,
            group_id=group_id
        )

        self.assertEqual(membership.user_id, user_id)
        self.assertEqual(membership.group_id, group_id)

    def test_identifiers_must_be_uuids(self):
        with self.assertRaises(ValueError):
            Group(id="not-a-uuid", name="staff")

        with self.assertRaises(ValueError):
            GroupMembership(
                user_id=uuid4(),
                group_id="not-a-uuid"
            )


if __name__ == "__main__":
    unittest.main()
