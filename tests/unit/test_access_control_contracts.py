import unittest
from dataclasses import FrozenInstanceError
from uuid import uuid4

from auth_service.modules.access_control.application.dto import UserAccessContext


class UserAccessContextTests(unittest.TestCase):
    def test_snapshot_is_immutable(self):
        user_id, group_id = uuid4(), uuid4()
        context = UserAccessContext(user_id, True, frozenset({group_id}))
        self.assertEqual(context.group_ids, frozenset({group_id}))
        with self.assertRaises(FrozenInstanceError):
            context.is_active = False

    def test_snapshot_requires_explicit_boolean_and_immutable_uuid_groups(self):
        user_id = uuid4()
        for args in [
            ("bad-id", True, frozenset()),
            (user_id, 1, frozenset()),
            (user_id, "false", frozenset()),
            (user_id, True, {uuid4()}),
            (user_id, True, frozenset({"bad-id"})),
            (user_id, True, None),
        ]:
            with self.subTest(args=args):
                with self.assertRaises(ValueError):
                    UserAccessContext(*args)
