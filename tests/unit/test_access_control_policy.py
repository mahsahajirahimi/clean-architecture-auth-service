import unittest
from uuid import uuid4

from auth_service.modules.access_control.domain.entities.grant import (
    Grant,
    GrantTargetType,
    SubjectType,
)
from auth_service.modules.access_control.domain.entities.permission import Permission
from auth_service.modules.access_control.domain.entities.scope import Scope
from auth_service.modules.access_control.domain.policy import AccessPolicy


class AccessPolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy = AccessPolicy()
        self.user_id = uuid4()
        self.first_group, self.second_group = uuid4(), uuid4()
        self.orders = Scope(uuid4(), "orders")
        self.invoices = Scope(uuid4(), "invoices")
        self.read = Permission(uuid4(), self.orders.id, "read")
        self.write = Permission(uuid4(), self.orders.id, "write")
        self.invoice_read = Permission(uuid4(), self.invoices.id, "read")
        self.context = {
            "user_id": self.user_id,
            "user_is_active": True,
            "group_ids": [self.first_group, self.second_group],
            "scopes": [self.orders, self.invoices],
            "permissions": [self.read, self.write, self.invoice_read],
        }

    def user_grant(self, permission):
        return Grant(
            SubjectType.USER, self.user_id, GrantTargetType.PERMISSION, permission.id
        )

    def group_grant(self, group_id, permission):
        return Grant(
            SubjectType.GROUP, group_id, GrantTargetType.PERMISSION, permission.id
        )

    def evaluate(self, grants, **changes):
        return self.policy.effective_permissions(
            **{**self.context, **changes}, grants=grants
        )

    def test_no_grants_deny_access_by_default(self):
        self.assertEqual(self.evaluate([]), frozenset())
        self.assertFalse(self.policy.allows(self.read.id, **self.context, grants=[]))

    def test_direct_permission_grant_allows_only_that_permission(self):
        grants = [self.user_grant(self.read)]
        self.assertEqual(self.evaluate(grants), frozenset({self.read.id}))
        self.assertTrue(self.policy.allows(self.read.id, **self.context, grants=grants))
        self.assertFalse(
            self.policy.allows(self.write.id, **self.context, grants=grants)
        )

    def test_direct_and_multiple_group_permissions_are_combined(self):
        grants = [
            self.user_grant(self.write),
            self.group_grant(self.first_group, self.read),
            self.group_grant(self.second_group, self.invoice_read),
        ]
        self.assertEqual(
            self.evaluate(grants),
            frozenset({self.read.id, self.write.id, self.invoice_read.id}),
        )

    def test_grants_for_other_users_and_nonmember_groups_are_ignored(self):
        grants = [
            Grant(SubjectType.USER, uuid4(), GrantTargetType.SCOPE, self.orders.id),
            self.group_grant(uuid4(), self.invoice_read),
        ]
        self.assertEqual(self.evaluate(grants), frozenset())

    def test_user_and_group_uuid_namespaces_are_not_interchangeable(self):
        wrong_user = Grant(
            SubjectType.USER, self.first_group, GrantTargetType.PERMISSION, self.read.id
        )
        wrong_group = self.group_grant(self.user_id, self.read)
        self.assertEqual(self.evaluate([wrong_user, wrong_group]), frozenset())

    def test_scope_grant_covers_all_permissions_only_in_its_scope(self):
        grant = Grant(
            SubjectType.USER, self.user_id, GrantTargetType.SCOPE, self.orders.id
        )
        self.assertEqual(
            self.evaluate([grant]), frozenset({self.read.id, self.write.id})
        )
        self.assertFalse(
            self.policy.allows(self.invoice_read.id, **self.context, grants=[grant])
        )

    def test_group_scope_grant_requires_current_membership(self):
        grant = Grant(
            SubjectType.GROUP, self.first_group, GrantTargetType.SCOPE, self.orders.id
        )
        self.assertEqual(
            self.evaluate([grant]), frozenset({self.read.id, self.write.id})
        )
        self.assertEqual(
            self.evaluate([grant], group_ids=[self.second_group]), frozenset()
        )

    def test_scope_grant_covers_later_added_permissions_and_revocation_removes_access(
        self,
    ):
        grant = Grant(
            SubjectType.USER, self.user_id, GrantTargetType.SCOPE, self.orders.id
        )
        delete = Permission(uuid4(), self.orders.id, "delete")
        self.assertNotIn(delete.id, self.evaluate([grant]))
        catalog = [*self.context["permissions"], delete]
        self.assertIn(delete.id, self.evaluate([grant], permissions=catalog))
        self.assertEqual(self.evaluate([], permissions=catalog), frozenset())

    def test_removing_membership_preserves_direct_and_other_group_grants(self):
        grants = [
            self.user_grant(self.write),
            self.group_grant(self.first_group, self.read),
            self.group_grant(self.second_group, self.read),
        ]
        self.assertEqual(
            self.evaluate(grants, group_ids=[self.second_group]),
            frozenset({self.read.id, self.write.id}),
        )
        self.assertEqual(
            self.evaluate(grants, group_ids=[]), frozenset({self.write.id})
        )

    def test_revoking_a_direct_grant_does_not_override_a_scope_or_group_grant(self):
        direct = self.user_grant(self.read)
        scope = Grant(
            SubjectType.USER, self.user_id, GrantTargetType.SCOPE, self.orders.id
        )
        group = self.group_grant(self.first_group, self.read)
        self.assertIn(self.read.id, self.evaluate([scope, group]))
        self.assertIn(self.read.id, self.evaluate([group]))
        self.assertIn(self.read.id, self.evaluate([direct]))
        self.assertEqual(self.evaluate([]), frozenset())

    def test_inactive_users_are_denied_even_with_scope_and_group_grants(self):
        grants = [
            Grant(
                SubjectType.USER, self.user_id, GrantTargetType.SCOPE, self.orders.id
            ),
            self.group_grant(self.first_group, self.invoice_read),
        ]
        self.assertEqual(self.evaluate(grants, user_is_active=False), frozenset())
        self.assertFalse(
            self.policy.allows(
                self.read.id, **{**self.context, "user_is_active": False}, grants=grants
            )
        )

    def test_stale_grants_and_deleted_catalog_entries_do_not_allow_access(self):
        grants = [
            self.user_grant(self.read),
            Grant(SubjectType.USER, self.user_id, GrantTargetType.PERMISSION, uuid4()),
            Grant(SubjectType.USER, self.user_id, GrantTargetType.SCOPE, uuid4()),
        ]
        self.assertEqual(
            self.evaluate(grants, permissions=[self.write, self.invoice_read]),
            frozenset(),
        )
        self.assertEqual(self.evaluate(grants, scopes=[self.invoices]), frozenset())
        self.assertFalse(self.policy.allows(uuid4(), **self.context, grants=grants))

    def test_same_permission_name_in_other_scope_does_not_confer_access(self):
        grants = [self.user_grant(self.read)]
        self.assertFalse(
            self.policy.allows(self.invoice_read.id, **self.context, grants=grants)
        )

    def test_target_type_is_not_inferred_from_uuid_or_name(self):
        wrong_target = Grant(
            SubjectType.USER, self.user_id, GrantTargetType.SCOPE, self.read.id
        )
        self.assertEqual(self.evaluate([wrong_target]), frozenset())

    def test_duplicate_grants_are_idempotent_and_results_are_immutable(self):
        grant = self.user_grant(self.read)
        result = self.evaluate([grant, grant])
        self.assertIsInstance(result, frozenset)
        self.assertEqual(result, frozenset({self.read.id}))

    def test_catalog_and_memberships_may_be_generators(self):
        self.assertEqual(
            self.evaluate(
                iter([self.user_grant(self.read)]),
                group_ids=iter(self.context["group_ids"]),
                scopes=iter(self.context["scopes"]),
                permissions=iter(self.context["permissions"]),
            ),
            frozenset({self.read.id}),
        )

    def test_invalid_subject_identifiers_or_active_status_are_rejected(self):
        for changes in (
            {"user_id": "invalid"},
            {"user_is_active": 1},
            {"user_is_active": "false"},
            {"group_ids": ["invalid"]},
        ):
            with self.subTest(changes=changes):
                with self.assertRaises(ValueError):
                    self.evaluate([], **changes)
        with self.assertRaises(ValueError):
            self.policy.allows("invalid", **self.context, grants=[])

    def test_empty_scope_does_not_allow_an_unconfigured_operation(self):
        empty_scope = Scope(uuid4(), "empty")
        grant = Grant(
            SubjectType.USER, self.user_id, GrantTargetType.SCOPE, empty_scope.id
        )
        self.assertEqual(
            self.evaluate([grant], scopes=[empty_scope], permissions=[]), frozenset()
        )
