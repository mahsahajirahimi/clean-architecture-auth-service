import unittest
from dataclasses import FrozenInstanceError
from uuid import uuid4

from auth_service.modules.access_control.domain.entities.grant import (
    Grant,
    GrantTargetType,
    SubjectType,
)
from auth_service.modules.access_control.domain.entities.permission import Permission
from auth_service.modules.access_control.domain.entities.scope import Scope


class AccessControlEntityTests(unittest.TestCase):
    def test_scope_and_permission_reference_by_uuid(self):
        scope = Scope(uuid4(), "orders")
        permission = Permission(uuid4(), scope.id, "read")
        self.assertEqual(permission.scope_id, scope.id)
        self.assertEqual(permission.name, "read")

    def test_permission_name_is_scoped_and_case_sensitive(self):
        orders, invoices = Scope(uuid4(), "orders"), Scope(uuid4(), "invoices")
        read_orders = Permission(uuid4(), orders.id, "read")
        read_invoices = Permission(uuid4(), invoices.id, "read")
        self.assertNotEqual(read_orders, read_invoices)
        self.assertNotEqual(
            Permission(uuid4(), orders.id, "Read").name, read_orders.name
        )

    def test_grants_support_users_groups_scopes_and_permissions(self):
        for subject_type in SubjectType:
            for target_type in GrantTargetType:
                with self.subTest(subject_type=subject_type, target_type=target_type):
                    subject_id, target_id = uuid4(), uuid4()
                    grant = Grant(subject_type, subject_id, target_type, target_id)
                    self.assertEqual(grant.subject_id, subject_id)
                    self.assertEqual(grant.target_id, target_id)
                    self.assertEqual(grant.subject_type, subject_type)
                    self.assertEqual(grant.target_type, target_type)

    def test_all_identifiers_must_be_uuids(self):
        for invalid in ("not-uuid", None, 1):
            factories = [
                lambda: Scope(invalid, "orders"),
                lambda: Permission(invalid, uuid4(), "read"),
                lambda: Permission(uuid4(), invalid, "read"),
                lambda: Grant(
                    SubjectType.USER, invalid, GrantTargetType.SCOPE, uuid4()
                ),
                lambda: Grant(
                    SubjectType.USER, uuid4(), GrantTargetType.PERMISSION, invalid
                ),
            ]
            for factory in factories:
                with self.subTest(invalid=invalid, factory=factory):
                    with self.assertRaises(ValueError):
                        factory()

    def test_names_are_nonblank_trimmed_strings_with_a_length_limit(self):
        for name in ("", " ", " orders", "read ", "x" * 256, None, 42):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    Scope(uuid4(), name)
                with self.assertRaises(ValueError):
                    Permission(uuid4(), uuid4(), name)
        self.assertEqual(Scope(uuid4(), "x" * 255).name, "x" * 255)
        self.assertEqual(Permission(uuid4(), uuid4(), "خواندن").name, "خواندن")

    def test_grant_enums_are_required_instead_of_unvalidated_strings(self):
        for subject_type in ("user", "administrator", None, 1):
            with self.subTest(subject_type=subject_type):
                with self.assertRaises(ValueError):
                    Grant(subject_type, uuid4(), GrantTargetType.SCOPE, uuid4())
        for target_type in ("scope", "*", None, 1):
            with self.subTest(target_type=target_type):
                with self.assertRaises(ValueError):
                    Grant(SubjectType.USER, uuid4(), target_type, uuid4())

    def test_entities_are_immutable_and_grants_have_composite_identity(self):
        scope = Scope(uuid4(), "orders")
        permission = Permission(uuid4(), scope.id, "read")
        grant = Grant(
            SubjectType.USER, uuid4(), GrantTargetType.PERMISSION, permission.id
        )
        for entity, field, value in [
            (scope, "name", "other"),
            (permission, "scope_id", uuid4()),
            (grant, "subject_id", uuid4()),
        ]:
            with self.subTest(entity=type(entity).__name__):
                with self.assertRaises(FrozenInstanceError):
                    setattr(entity, field, value)
        duplicate = Grant(
            grant.subject_type, grant.subject_id, grant.target_type, grant.target_id
        )
        self.assertEqual(len({grant, duplicate}), 1)
