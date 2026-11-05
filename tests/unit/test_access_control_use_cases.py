import unittest
from unittest.mock import Mock, call
from uuid import uuid4

from auth_service.modules.access_control.application.dto import UserAccessContext
from auth_service.modules.access_control.application.exceptions import (
    DuplicatePermissionError,
    DuplicateScopeError,
    GrantAlreadyExistsError,
    GrantNotFoundError,
    IdentityContextError,
    InvalidInputError,
    PermissionNotFoundError,
    ScopeNotFoundError,
    SubjectNotFoundError,
    UserNotFoundError,
)
from auth_service.modules.access_control.application.ports import (
    GrantRepository,
    IdentityReader,
    PermissionRepository,
    ScopeRepository,
)
from auth_service.modules.access_control.application.use_cases.assign_grant import (
    AssignGrant,
)
from auth_service.modules.access_control.application.use_cases.check_access import (
    CheckAccess,
)
from auth_service.modules.access_control.application.use_cases.create_permission import (
    CreatePermission,
)
from auth_service.modules.access_control.application.use_cases.create_scope import (
    CreateScope,
)
from auth_service.modules.access_control.application.use_cases.get_effective_permissions import (
    GetEffectivePermissions,
)
from auth_service.modules.access_control.application.use_cases.revoke_grant import (
    RevokeGrant,
)
from auth_service.modules.access_control.domain.entities.grant import (
    Grant,
    GrantTargetType,
    SubjectType,
)
from auth_service.modules.access_control.domain.entities.permission import Permission
from auth_service.modules.access_control.domain.entities.scope import Scope


class AccessControlUseCaseTests(unittest.TestCase):
    def setUp(self):
        self.scopes = Mock(spec=ScopeRepository)
        self.permissions = Mock(spec=PermissionRepository)
        self.grants = Mock(spec=GrantRepository)
        self.identity = Mock(spec=IdentityReader)
        self.user_id, self.group_id = uuid4(), uuid4()
        self.scope = Scope(uuid4(), "orders")
        self.read = Permission(uuid4(), self.scope.id, "read")
        self.write = Permission(uuid4(), self.scope.id, "write")
        self.context = UserAccessContext(self.user_id, True, frozenset({self.group_id}))
        self.scopes.get_by_name.return_value = None
        self.scopes.get_by_id.return_value = self.scope
        self.scopes.list_all.return_value = [self.scope]
        self.permissions.get_by_id.return_value = self.read
        self.permissions.get_by_scope_and_name.return_value = None
        self.permissions.list_all.return_value = [self.read, self.write]
        self.grants.exists.return_value = False
        self.grants.remove.return_value = True
        self.grants.list_for_user.return_value = []
        self.identity.get_user_context.return_value = self.context
        self.identity.group_exists.return_value = True
        self.assign = AssignGrant(
            self.scopes, self.permissions, self.grants, self.identity
        )
        self.effective = GetEffectivePermissions(
            self.scopes, self.permissions, self.grants, self.identity
        )

    def grant(self):
        return Grant(
            SubjectType.USER, self.user_id, GrantTargetType.PERMISSION, self.read.id
        )

    def test_create_scope_normalizes_name_and_saves_entity(self):
        scope = CreateScope(self.scopes).execute(" Orders ")
        self.assertEqual(scope.name, "Orders")
        self.assertNotEqual(scope.id, self.scope.id)
        self.scopes.get_by_name.assert_called_once_with("Orders")
        self.scopes.save.assert_called_once_with(scope)

    def test_create_scope_rejects_duplicate(self):
        self.scopes.get_by_name.return_value = self.scope
        with self.assertRaises(DuplicateScopeError):
            CreateScope(self.scopes).execute("orders")
        self.scopes.save.assert_not_called()

    def test_create_scope_rejects_invalid_names_without_querying(self):
        for name in ("", " ", None, 42, "x" * 256):
            with self.subTest(name=name):
                with self.assertRaises(InvalidInputError):
                    CreateScope(self.scopes).execute(name)
        self.scopes.get_by_name.assert_not_called()
        self.scopes.save.assert_not_called()

    def test_create_permission_normalizes_name_and_checks_scope_specific_uniqueness(
        self,
    ):
        permission = CreatePermission(self.scopes, self.permissions).execute(
            self.scope.id, " read "
        )
        self.assertEqual(permission.scope_id, self.scope.id)
        self.assertEqual(permission.name, "read")
        self.permissions.get_by_scope_and_name.assert_called_once_with(
            self.scope.id, "read"
        )
        self.permissions.save.assert_called_once_with(permission)

    def test_same_permission_name_is_allowed_in_distinct_scopes(self):
        other = Scope(uuid4(), "invoices")
        self.scopes.get_by_id.side_effect = [self.scope, other]
        use_case = CreatePermission(self.scopes, self.permissions)
        first = use_case.execute(self.scope.id, "read")
        second = use_case.execute(other.id, "read")
        self.assertNotEqual(first.id, second.id)
        self.assertNotEqual(first.scope_id, second.scope_id)
        self.permissions.get_by_scope_and_name.assert_has_calls(
            [call(self.scope.id, "read"), call(other.id, "read")]
        )

    def test_create_permission_rejects_missing_scope(self):
        self.scopes.get_by_id.return_value = None
        with self.assertRaises(ScopeNotFoundError):
            CreatePermission(self.scopes, self.permissions).execute(
                self.scope.id, "read"
            )
        self.permissions.save.assert_not_called()
        self.permissions.get_by_scope_and_name.assert_not_called()

    def test_create_permission_rejects_duplicate_within_scope(self):
        self.permissions.get_by_scope_and_name.return_value = self.read
        with self.assertRaises(DuplicatePermissionError):
            CreatePermission(self.scopes, self.permissions).execute(
                self.scope.id, "read"
            )
        self.permissions.save.assert_not_called()

    def test_create_permission_rejects_invalid_input_before_querying(self):
        for scope_id, name in [
            ("bad-id", "read"),
            (self.scope.id, ""),
            (self.scope.id, None),
            (self.scope.id, "x" * 256),
        ]:
            with self.subTest(name=name):
                with self.assertRaises(InvalidInputError):
                    CreatePermission(self.scopes, self.permissions).execute(
                        scope_id, name
                    )
        self.scopes.get_by_id.assert_not_called()
        self.permissions.save.assert_not_called()

    def test_assign_supports_all_subject_and_target_types(self):
        for subject_type, subject_id in [
            (SubjectType.USER, self.user_id),
            (SubjectType.GROUP, self.group_id),
        ]:
            for target_type, target_id in [
                (GrantTargetType.SCOPE, self.scope.id),
                (GrantTargetType.PERMISSION, self.read.id),
            ]:
                with self.subTest(subject_type=subject_type, target_type=target_type):
                    grant = self.assign.execute(
                        subject_type, subject_id, target_type, target_id
                    )
                    self.assertEqual(
                        grant, Grant(subject_type, subject_id, target_type, target_id)
                    )
                    self.grants.save.assert_called_with(grant)
                    self.grants.exists.assert_called_with(grant)
        self.assertEqual(self.grants.save.call_count, 4)

    def test_assign_to_inactive_existing_user_is_allowed(self):
        self.identity.get_user_context.return_value = UserAccessContext(
            self.user_id, False, frozenset()
        )
        grant = self.assign.execute(
            SubjectType.USER, self.user_id, GrantTargetType.PERMISSION, self.read.id
        )
        self.grants.save.assert_called_once_with(grant)
        self.assertEqual(self.effective.execute(self.user_id), frozenset())

    def test_assign_rejects_missing_user_or_group(self):
        self.identity.get_user_context.return_value = None
        self.identity.group_exists.return_value = False
        for kind, subject_id in [
            (SubjectType.USER, self.user_id),
            (SubjectType.GROUP, self.group_id),
        ]:
            with self.subTest(kind=kind):
                with self.assertRaises(SubjectNotFoundError):
                    self.assign.execute(
                        kind, subject_id, GrantTargetType.PERMISSION, self.read.id
                    )
        self.grants.save.assert_not_called()

    def test_assign_rejects_missing_scope_permission_or_permission_parent(self):
        self.scopes.get_by_id.return_value = None
        with self.assertRaises(ScopeNotFoundError):
            self.assign.execute(
                SubjectType.USER, self.user_id, GrantTargetType.SCOPE, self.scope.id
            )
        with self.assertRaises(ScopeNotFoundError):
            self.assign.execute(
                SubjectType.USER, self.user_id, GrantTargetType.PERMISSION, self.read.id
            )
        self.permissions.get_by_id.return_value = None
        with self.assertRaises(PermissionNotFoundError):
            self.assign.execute(
                SubjectType.USER, self.user_id, GrantTargetType.PERMISSION, self.read.id
            )
        self.grants.save.assert_not_called()

    def test_assign_rejects_duplicate_grant(self):
        self.grants.exists.return_value = True
        with self.assertRaises(GrantAlreadyExistsError):
            self.assign.execute(
                SubjectType.USER, self.user_id, GrantTargetType.PERMISSION, self.read.id
            )
        self.grants.save.assert_not_called()

    def test_assign_rejects_invalid_enums_and_ids_before_lookups(self):
        for args in [
            ("user", self.user_id, GrantTargetType.PERMISSION, self.read.id),
            (SubjectType.USER, "bad-id", GrantTargetType.PERMISSION, self.read.id),
            (SubjectType.USER, self.user_id, "permission", self.read.id),
            (SubjectType.USER, self.user_id, GrantTargetType.PERMISSION, "bad-id"),
        ]:
            with self.subTest(args=args):
                with self.assertRaises(InvalidInputError):
                    self.assign.execute(*args)
        self.identity.get_user_context.assert_not_called()
        self.identity.group_exists.assert_not_called()
        self.grants.save.assert_not_called()

    def test_assign_rejects_mismatched_identity_context(self):
        self.identity.get_user_context.return_value = UserAccessContext(
            uuid4(), True, frozenset()
        )
        with self.assertRaises(IdentityContextError):
            self.assign.execute(
                SubjectType.USER, self.user_id, GrantTargetType.SCOPE, self.scope.id
            )
        self.grants.save.assert_not_called()

    def test_write_failures_are_not_reported_as_success(self):
        self.grants.save.side_effect = RuntimeError("persistence failure")
        with self.assertRaisesRegex(RuntimeError, "persistence failure"):
            self.assign.execute(
                SubjectType.USER, self.user_id, GrantTargetType.PERMISSION, self.read.id
            )

    def test_revoke_removes_exact_grant_without_identity_or_catalog_lookups(self):
        grant = self.grant()
        RevokeGrant(self.grants).execute(
            grant.subject_type, grant.subject_id, grant.target_type, grant.target_id
        )
        self.grants.remove.assert_called_once_with(grant)
        self.identity.get_user_context.assert_not_called()
        self.scopes.get_by_id.assert_not_called()
        self.permissions.get_by_id.assert_not_called()

    def test_revoke_missing_grant_is_explicit_error(self):
        self.grants.remove.return_value = False
        grant = self.grant()
        with self.assertRaises(GrantNotFoundError):
            RevokeGrant(self.grants).execute(
                grant.subject_type, grant.subject_id, grant.target_type, grant.target_id
            )

    def test_revoke_validates_keys_before_deleting(self):
        with self.assertRaises(InvalidInputError):
            RevokeGrant(self.grants).execute(
                SubjectType.USER, "invalid", GrantTargetType.SCOPE, self.scope.id
            )
        self.grants.remove.assert_not_called()

    def test_effective_permissions_uses_identity_snapshot_and_real_domain_policy(self):
        self.grants.list_for_user.return_value = [
            self.grant(),
            Grant(
                SubjectType.GROUP,
                self.group_id,
                GrantTargetType.PERMISSION,
                self.write.id,
            ),
        ]
        result = self.effective.execute(self.user_id)
        self.assertEqual(result, frozenset({self.read.id, self.write.id}))
        self.identity.get_user_context.assert_called_once_with(self.user_id)
        self.grants.list_for_user.assert_called_once_with(
            self.user_id, self.context.group_ids
        )
        self.scopes.list_all.assert_called_once()
        self.permissions.list_all.assert_called_once()

    def test_membership_changes_are_read_on_each_check(self):
        self.grants.list_for_user.return_value = [
            Grant(
                SubjectType.GROUP,
                self.group_id,
                GrantTargetType.PERMISSION,
                self.read.id,
            )
        ]
        self.identity.get_user_context.side_effect = [
            self.context,
            UserAccessContext(self.user_id, True, frozenset()),
        ]
        check = CheckAccess(self.effective)
        self.assertTrue(check.execute(self.user_id, self.read.id))
        self.assertFalse(check.execute(self.user_id, self.read.id))
        self.grants.list_for_user.assert_has_calls(
            [
                call(self.user_id, frozenset({self.group_id})),
                call(self.user_id, frozenset()),
            ]
        )
        self.assertEqual(self.identity.get_user_context.call_count, 2)

    def test_revocation_is_visible_to_the_next_check(self):
        self.grants.list_for_user.return_value = [self.grant()]
        check = CheckAccess(self.effective)
        self.assertTrue(check.execute(self.user_id, self.read.id))
        self.grants.list_for_user.return_value = []
        self.assertFalse(check.execute(self.user_id, self.read.id))
        self.assertEqual(self.grants.list_for_user.call_count, 2)

    def test_catalog_is_read_again_so_scope_grants_include_new_permissions(self):
        self.grants.list_for_user.return_value = [
            Grant(SubjectType.USER, self.user_id, GrantTargetType.SCOPE, self.scope.id)
        ]
        added = Permission(uuid4(), self.scope.id, "delete")
        self.assertNotIn(added.id, self.effective.execute(self.user_id))
        self.permissions.list_all.return_value = [self.read, self.write, added]
        self.assertIn(added.id, self.effective.execute(self.user_id))
        self.assertEqual(self.permissions.list_all.call_count, 2)

    def test_inactive_user_returns_no_permissions_without_loading_catalog_or_grants(
        self,
    ):
        self.identity.get_user_context.return_value = UserAccessContext(
            self.user_id, False, frozenset()
        )
        self.assertEqual(self.effective.execute(self.user_id), frozenset())
        self.scopes.list_all.assert_not_called()
        self.permissions.list_all.assert_not_called()
        self.grants.list_for_user.assert_not_called()

    def test_missing_user_returns_explicit_error_without_loading_access_data(self):
        self.identity.get_user_context.return_value = None
        with self.assertRaises(UserNotFoundError):
            self.effective.execute(self.user_id)
        self.grants.list_for_user.assert_not_called()
        self.scopes.list_all.assert_not_called()

    def test_effective_permissions_rejects_mismatched_context(self):
        self.identity.get_user_context.return_value = UserAccessContext(
            uuid4(), True, frozenset({self.group_id})
        )
        with self.assertRaises(IdentityContextError):
            self.effective.execute(self.user_id)
        self.grants.list_for_user.assert_not_called()

    def test_failed_identity_lookup_never_falls_back_to_allow_or_cached_data(self):
        self.grants.list_for_user.return_value = [self.grant()]
        check = CheckAccess(self.effective)
        self.assertTrue(check.execute(self.user_id, self.read.id))
        self.identity.get_user_context.side_effect = TimeoutError(
            "identity unavailable"
        )
        with self.assertRaises(TimeoutError):
            check.execute(self.user_id, self.read.id)
        self.assertEqual(self.grants.list_for_user.call_count, 1)

    def test_check_access_denies_unknown_permission_and_validates_identifiers(self):
        self.grants.list_for_user.return_value = [self.grant()]
        self.assertFalse(CheckAccess(self.effective).execute(self.user_id, uuid4()))
        self.identity.get_user_context.reset_mock()
        with self.assertRaises(InvalidInputError):
            CheckAccess(self.effective).execute(self.user_id, "invalid")
        with self.assertRaises(InvalidInputError):
            CheckAccess(self.effective).execute("invalid", self.read.id)
        self.identity.get_user_context.assert_not_called()
