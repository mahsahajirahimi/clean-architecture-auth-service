import unittest
from dataclasses import asdict
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import uuid4

from sqlalchemy import delete, inspect
from sqlalchemy.exc import IntegrityError

from auth_service.composition.access_control import make_identity_reader
from auth_service.composition.schema import create_schema
from auth_service.infrastructure.persistence.database import (
    Base,
    make_engine,
    make_session_factory,
)
from auth_service.modules.access_control.application.exceptions import (
    SubjectNotFoundError,
    UserNotFoundError,
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
from auth_service.modules.access_control.infrastructure.persistence.models import (
    PermissionGrantModel,
    PermissionModel,
    ScopeGrantModel,
    ScopeModel,
)
from auth_service.modules.access_control.infrastructure.persistence.repositories import (
    SqlAlchemyGrantRepository,
    SqlAlchemyPermissionRepository,
    SqlAlchemyScopeRepository,
)
from auth_service.modules.identity.domain.entities.group import Group
from auth_service.modules.identity.domain.entities.membership import GroupMembership
from auth_service.modules.identity.domain.entities.user import User
from auth_service.modules.identity.infrastructure.persistence.models import (
    AdministratorModel,
    GroupMembershipModel,
    GroupModel,
    UserModel,
)
from auth_service.modules.identity.infrastructure.persistence.repositories import (
    SqlAlchemyGroupRepository,
    SqlAlchemyMembershipRepository,
    SqlAlchemyUserRepository,
)


class AccessControlPersistenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.engine = make_engine(f"sqlite:///{Path(self.temp.name) / 'access.db'}")
        self.addCleanup(self.engine.dispose)
        create_schema(self.engine)
        self.sessions = make_session_factory(self.engine)
        self.user = User(uuid4(), "ali", "stored-password-hash")
        self.other = User(uuid4(), "other", "other-password-hash")
        self.group = Group(uuid4(), "staff")
        self.second_group = Group(uuid4(), "editors")
        self.scope = Scope(uuid4(), "orders")
        self.other_scope = Scope(uuid4(), "invoices")
        self.read = Permission(uuid4(), self.scope.id, "read")
        self.write = Permission(uuid4(), self.scope.id, "write")
        self.invoice_read = Permission(uuid4(), self.other_scope.id, "read")
        with self.sessions.begin() as session:
            for user in (self.user, self.other):
                SqlAlchemyUserRepository(session).save(user)
            for group in (self.group, self.second_group):
                SqlAlchemyGroupRepository(session).save(group)
                SqlAlchemyMembershipRepository(session).save(
                    GroupMembership(self.user.id, group.id)
                )
            for scope in (self.scope, self.other_scope):
                SqlAlchemyScopeRepository(session).save(scope)
            for permission in (self.read, self.write, self.invoice_read):
                SqlAlchemyPermissionRepository(session).save(permission)

    def assign(self, subject_type, subject_id, target_type, target_id):
        with self.sessions.begin() as session:
            return AssignGrant(
                SqlAlchemyScopeRepository(session),
                SqlAlchemyPermissionRepository(session),
                SqlAlchemyGrantRepository(session),
                make_identity_reader(session),
            ).execute(subject_type, subject_id, target_type, target_id)

    def effective(self, user_id=None):
        with self.sessions() as session:
            return GetEffectivePermissions(
                SqlAlchemyScopeRepository(session),
                SqlAlchemyPermissionRepository(session),
                SqlAlchemyGrantRepository(session),
                make_identity_reader(session),
            ).execute(user_id or self.user.id)

    def test_create_and_reload_scope_and_scoped_permission(self):
        with self.sessions.begin() as session:
            scopes, permissions = SqlAlchemyScopeRepository(
                session
            ), SqlAlchemyPermissionRepository(session)
            scope = CreateScope(scopes).execute(" reports ")
            permission = CreatePermission(scopes, permissions).execute(
                scope.id, " read "
            )
        with self.sessions() as session:
            scopes, permissions = SqlAlchemyScopeRepository(
                session
            ), SqlAlchemyPermissionRepository(session)
            self.assertEqual(scopes.get_by_id(scope.id), scope)
            self.assertEqual(scopes.get_by_name("reports"), scope)
            self.assertEqual(permissions.get_by_id(permission.id), permission)
            self.assertEqual(
                permissions.get_by_scope_and_name(scope.id, "read"), permission
            )
            self.assertEqual(
                [s.name for s in scopes.list_all()], ["invoices", "orders", "reports"]
            )
            self.assertEqual(
                set(permissions.list_all()),
                {self.read, self.write, self.invoice_read, permission},
            )

    def test_missing_records_and_empty_memberships(self):
        with self.sessions() as session:
            self.assertIsNone(SqlAlchemyScopeRepository(session).get_by_id(uuid4()))
            self.assertIsNone(SqlAlchemyScopeRepository(session).get_by_name("absent"))
            self.assertIsNone(
                SqlAlchemyPermissionRepository(session).get_by_id(uuid4())
            )
            self.assertIsNone(
                SqlAlchemyPermissionRepository(session).get_by_scope_and_name(
                    self.scope.id, "absent"
                )
            )
            self.assertEqual(
                SqlAlchemyMembershipRepository(session).list_group_ids(self.other.id),
                frozenset(),
            )
            self.assertIsNone(make_identity_reader(session).get_user_context(uuid4()))
            self.assertFalse(make_identity_reader(session).group_exists(uuid4()))

    def test_identity_adapter_reads_current_data_without_exposing_credentials(self):
        with self.sessions() as session:
            reader = make_identity_reader(session)
            context = reader.get_user_context(self.user.id)
            self.assertEqual(context.user_id, self.user.id)
            self.assertTrue(context.is_active)
            self.assertEqual(
                context.group_ids, frozenset({self.group.id, self.second_group.id})
            )
            self.assertEqual(
                set(asdict(context)), {"user_id", "is_active", "group_ids"}
            )
            self.assertNotIn(self.user.password_hash, repr(context))
            self.assertTrue(reader.group_exists(self.group.id))

    def test_all_four_grant_types_round_trip_and_filter_by_subject(self):
        saved = set()
        for subject_type, subject_id in [
            (SubjectType.USER, self.user.id),
            (SubjectType.GROUP, self.group.id),
        ]:
            for target_type, target_id in [
                (GrantTargetType.SCOPE, self.scope.id),
                (GrantTargetType.PERMISSION, self.read.id),
            ]:
                saved.add(self.assign(subject_type, subject_id, target_type, target_id))
        self.assign(
            SubjectType.USER,
            self.other.id,
            GrantTargetType.PERMISSION,
            self.invoice_read.id,
        )
        with self.sessions() as session:
            grants = SqlAlchemyGrantRepository(session)
            for grant in saved:
                self.assertTrue(grants.exists(grant))
            self.assertEqual(
                set(grants.list_for_user(self.user.id, frozenset({self.group.id}))),
                saved,
            )
            self.assertEqual(
                set(grants.list_for_user(self.user.id, frozenset())),
                {g for g in saved if g.subject_type == SubjectType.USER},
            )

    def test_effective_access_combines_direct_and_group_grants(self):
        self.assign(
            SubjectType.USER, self.user.id, GrantTargetType.PERMISSION, self.read.id
        )
        self.assign(
            SubjectType.GROUP, self.group.id, GrantTargetType.PERMISSION, self.write.id
        )
        self.assign(
            SubjectType.GROUP,
            self.second_group.id,
            GrantTargetType.SCOPE,
            self.other_scope.id,
        )
        self.assertEqual(
            self.effective(),
            frozenset({self.read.id, self.write.id, self.invoice_read.id}),
        )
        self.assertEqual(self.effective(self.other.id), frozenset())

    def test_revocation_is_visible_but_other_grant_sources_survive(self):
        direct = self.assign(
            SubjectType.USER, self.user.id, GrantTargetType.PERMISSION, self.read.id
        )
        group = self.assign(
            SubjectType.GROUP, self.group.id, GrantTargetType.PERMISSION, self.read.id
        )
        with self.sessions.begin() as session:
            RevokeGrant(SqlAlchemyGrantRepository(session)).execute(
                direct.subject_type,
                direct.subject_id,
                direct.target_type,
                direct.target_id,
            )
        self.assertIn(self.read.id, self.effective())
        with self.sessions.begin() as session:
            RevokeGrant(SqlAlchemyGrantRepository(session)).execute(
                group.subject_type, group.subject_id, group.target_type, group.target_id
            )
        self.assertNotIn(self.read.id, self.effective())

    def test_membership_removal_updates_effective_access_without_changing_other_sources(
        self,
    ):
        self.assign(
            SubjectType.GROUP, self.group.id, GrantTargetType.PERMISSION, self.read.id
        )
        self.assign(
            SubjectType.GROUP,
            self.second_group.id,
            GrantTargetType.PERMISSION,
            self.write.id,
        )
        self.assign(
            SubjectType.USER,
            self.user.id,
            GrantTargetType.PERMISSION,
            self.invoice_read.id,
        )
        with self.sessions.begin() as session:
            self.assertTrue(
                SqlAlchemyMembershipRepository(session).remove(
                    self.user.id, self.group.id
                )
            )
        self.assertEqual(
            self.effective(), frozenset({self.write.id, self.invoice_read.id})
        )

    def test_deactivation_blocks_access_and_reactivation_restores_it(self):
        self.assign(
            SubjectType.USER, self.user.id, GrantTargetType.SCOPE, self.scope.id
        )
        with self.sessions.begin() as session:
            SqlAlchemyUserRepository(session).save(self.user.deactivate())
        self.assertEqual(self.effective(), frozenset())
        with self.sessions.begin() as session:
            SqlAlchemyUserRepository(session).save(self.user)
        self.assertEqual(self.effective(), frozenset({self.read.id, self.write.id}))

    def test_new_permission_is_included_in_an_existing_scope_grant(self):
        self.assign(
            SubjectType.USER, self.user.id, GrantTargetType.SCOPE, self.scope.id
        )
        with self.sessions.begin() as session:
            permission = CreatePermission(
                SqlAlchemyScopeRepository(session),
                SqlAlchemyPermissionRepository(session),
            ).execute(self.scope.id, "delete")
        self.assertIn(permission.id, self.effective())

    def test_missing_users_cannot_be_checked_and_unknown_subjects_cannot_be_assigned(
        self,
    ):
        with self.assertRaises(UserNotFoundError):
            self.effective(uuid4())
        for kind in SubjectType:
            with self.subTest(kind=kind):
                with self.assertRaises(SubjectNotFoundError):
                    self.assign(kind, uuid4(), GrantTargetType.SCOPE, self.scope.id)

    def test_duplicate_scope_name_is_enforced_by_database(self):
        with self.assertRaises(IntegrityError):
            with self.sessions.begin() as session:
                SqlAlchemyScopeRepository(session).save(Scope(uuid4(), "orders"))

    def test_duplicate_permission_name_is_restricted_to_its_scope(self):
        with self.assertRaises(IntegrityError):
            with self.sessions.begin() as session:
                SqlAlchemyPermissionRepository(session).save(
                    Permission(uuid4(), self.scope.id, "read")
                )
        with self.sessions() as session:
            self.assertEqual(
                SqlAlchemyPermissionRepository(session).get_by_scope_and_name(
                    self.other_scope.id, "read"
                ),
                self.invoice_read,
            )

    def test_duplicate_grants_are_enforced_for_every_subject_and_target_type(self):
        for kind, subject_id in [
            (SubjectType.USER, self.user.id),
            (SubjectType.GROUP, self.group.id),
        ]:
            for target, target_id in [
                (GrantTargetType.SCOPE, self.scope.id),
                (GrantTargetType.PERMISSION, self.read.id),
            ]:
                with self.subTest(kind=kind, target=target):
                    grant = self.assign(kind, subject_id, target, target_id)
                    with self.assertRaises(IntegrityError):
                        with self.sessions.begin() as session:
                            SqlAlchemyGrantRepository(session).save(grant)

    def test_missing_parent_scope_and_grant_targets_are_rejected_by_foreign_keys(self):
        with self.assertRaises(IntegrityError):
            with self.sessions.begin() as session:
                SqlAlchemyPermissionRepository(session).save(
                    Permission(uuid4(), uuid4(), "read")
                )
        for target in GrantTargetType:
            with self.subTest(target=target):
                with self.assertRaises(IntegrityError):
                    with self.sessions.begin() as session:
                        SqlAlchemyGrantRepository(session).save(
                            Grant(SubjectType.USER, self.user.id, target, uuid4())
                        )

    def test_database_rejects_unknown_subject_types(self):
        for model, target in [
            (ScopeGrantModel, self.scope.id),
            (PermissionGrantModel, self.read.id),
        ]:
            with self.subTest(model=model.__name__):
                with self.assertRaises(IntegrityError):
                    with self.sessions.begin() as session:
                        session.add(
                            model(
                                subject_type="admin",
                                subject_id=str(self.user.id),
                                target_id=str(target),
                            )
                        )
                        session.flush()

    def test_user_and_group_with_same_uuid_keep_distinct_grants(self):
        with self.sessions.begin() as session:
            SqlAlchemyGroupRepository(session).save(
                Group(self.user.id, "same-id-group")
            )
        direct = self.assign(
            SubjectType.USER, self.user.id, GrantTargetType.PERMISSION, self.read.id
        )
        group = self.assign(
            SubjectType.GROUP, self.user.id, GrantTargetType.PERMISSION, self.read.id
        )
        with self.sessions() as session:
            grants = SqlAlchemyGrantRepository(session)
            self.assertEqual(grants.list_for_user(self.user.id, frozenset()), [direct])
            self.assertEqual(
                set(grants.list_for_user(self.user.id, frozenset({self.user.id}))),
                {direct, group},
            )

    def test_repository_writes_do_not_commit(self):
        scope = Scope(uuid4(), "temporary")
        permission = Permission(uuid4(), scope.id, "read")
        grant = Grant(
            SubjectType.USER, self.user.id, GrantTargetType.PERMISSION, permission.id
        )
        with self.sessions() as session:
            SqlAlchemyScopeRepository(session).save(scope)
            SqlAlchemyPermissionRepository(session).save(permission)
            SqlAlchemyGrantRepository(session).save(grant)
        with self.sessions() as session:
            self.assertIsNone(SqlAlchemyScopeRepository(session).get_by_id(scope.id))
            self.assertIsNone(
                SqlAlchemyPermissionRepository(session).get_by_id(permission.id)
            )
            self.assertFalse(SqlAlchemyGrantRepository(session).exists(grant))

    def test_failed_transaction_rolls_back_scope_permission_and_grant(self):
        scope = Scope(uuid4(), "rolled-back")
        permission = Permission(uuid4(), scope.id, "read")
        with self.assertRaises(IntegrityError):
            with self.sessions.begin() as session:
                SqlAlchemyScopeRepository(session).save(scope)
                SqlAlchemyPermissionRepository(session).save(permission)
                SqlAlchemyGrantRepository(session).save(
                    Grant(
                        SubjectType.USER,
                        self.user.id,
                        GrantTargetType.PERMISSION,
                        permission.id,
                    )
                )
                SqlAlchemyGrantRepository(session).save(
                    Grant(
                        SubjectType.USER,
                        self.user.id,
                        GrantTargetType.PERMISSION,
                        uuid4(),
                    )
                )
        with self.sessions() as session:
            self.assertIsNone(SqlAlchemyScopeRepository(session).get_by_id(scope.id))
            self.assertIsNone(
                SqlAlchemyPermissionRepository(session).get_by_id(permission.id)
            )

    def test_revocation_does_not_commit_and_removes_only_exact_grant(self):
        direct = self.assign(
            SubjectType.USER, self.user.id, GrantTargetType.PERMISSION, self.read.id
        )
        group = self.assign(
            SubjectType.GROUP, self.group.id, GrantTargetType.PERMISSION, self.read.id
        )
        with self.sessions() as session:
            self.assertTrue(SqlAlchemyGrantRepository(session).remove(direct))
        with self.sessions() as session:
            self.assertTrue(SqlAlchemyGrantRepository(session).exists(direct))
        with self.sessions.begin() as session:
            self.assertTrue(SqlAlchemyGrantRepository(session).remove(direct))
            self.assertFalse(SqlAlchemyGrantRepository(session).remove(direct))
        with self.sessions() as session:
            self.assertFalse(SqlAlchemyGrantRepository(session).exists(direct))
            self.assertTrue(SqlAlchemyGrantRepository(session).exists(group))

    def test_deleting_scope_cascades_permissions_and_both_grant_types(self):
        direct = self.assign(
            SubjectType.USER, self.user.id, GrantTargetType.SCOPE, self.scope.id
        )
        specific = self.assign(
            SubjectType.GROUP, self.group.id, GrantTargetType.PERMISSION, self.read.id
        )
        other = self.assign(
            SubjectType.USER,
            self.user.id,
            GrantTargetType.PERMISSION,
            self.invoice_read.id,
        )
        with self.sessions.begin() as session:
            session.execute(
                delete(ScopeModel).where(ScopeModel.id == str(self.scope.id))
            )
        with self.sessions() as session:
            grants = SqlAlchemyGrantRepository(session)
            self.assertIsNone(
                SqlAlchemyPermissionRepository(session).get_by_id(self.read.id)
            )
            self.assertFalse(grants.exists(direct))
            self.assertFalse(grants.exists(specific))
            self.assertTrue(grants.exists(other))
        self.assertEqual(self.effective(), frozenset({self.invoice_read.id}))

    def test_deleting_permission_preserves_scope_grants_and_other_permissions(self):
        scope = self.assign(
            SubjectType.USER, self.user.id, GrantTargetType.SCOPE, self.scope.id
        )
        permission = self.assign(
            SubjectType.USER, self.user.id, GrantTargetType.PERMISSION, self.read.id
        )
        with self.sessions.begin() as session:
            session.execute(
                delete(PermissionModel).where(PermissionModel.id == str(self.read.id))
            )
        with self.sessions() as session:
            self.assertTrue(SqlAlchemyGrantRepository(session).exists(scope))
            self.assertFalse(SqlAlchemyGrantRepository(session).exists(permission))
        self.assertEqual(self.effective(), frozenset({self.write.id}))

    def test_deleted_identity_group_loses_access_and_stale_grant_remains_revocable(
        self,
    ):
        grant = self.assign(
            SubjectType.GROUP, self.group.id, GrantTargetType.PERMISSION, self.read.id
        )
        with self.sessions.begin() as session:
            session.execute(
                delete(GroupModel).where(GroupModel.id == str(self.group.id))
            )
        self.assertNotIn(self.read.id, self.effective())
        with self.sessions.begin() as session:
            self.assertTrue(SqlAlchemyGrantRepository(session).remove(grant))

    def test_schema_creation_adds_access_tables_to_existing_identity_database(self):
        legacy_engine = make_engine(f"sqlite:///{Path(self.temp.name) / 'legacy.db'}")
        self.addCleanup(legacy_engine.dispose)
        Base.metadata.create_all(
            legacy_engine,
            tables=[
                UserModel.__table__,
                GroupModel.__table__,
                GroupMembershipModel.__table__,
                AdministratorModel.__table__,
            ],
        )
        sessions = make_session_factory(legacy_engine)
        with sessions.begin() as session:
            SqlAlchemyUserRepository(session).save(self.user)
        create_schema(legacy_engine)
        create_schema(legacy_engine)
        self.assertEqual(
            set(inspect(legacy_engine).get_table_names()),
            {
                "identity_users",
                "identity_groups",
                "identity_group_memberships",
                "identity_administrator",
                "access_scopes",
                "access_permissions",
                "access_scope_grants",
                "access_permission_grants",
            },
        )
        with sessions() as session:
            self.assertEqual(
                SqlAlchemyUserRepository(session).get_by_id(self.user.id), self.user
            )

    def test_check_access_uses_persisted_grants_and_denies_ungranted_permissions(self):
        self.assign(
            SubjectType.USER, self.user.id, GrantTargetType.PERMISSION, self.read.id
        )
        with self.sessions() as session:
            check = CheckAccess(
                GetEffectivePermissions(
                    SqlAlchemyScopeRepository(session),
                    SqlAlchemyPermissionRepository(session),
                    SqlAlchemyGrantRepository(session),
                    make_identity_reader(session),
                )
            )
            self.assertTrue(check.execute(self.user.id, self.read.id))
            self.assertFalse(check.execute(self.user.id, self.write.id))
            self.assertFalse(check.execute(self.user.id, uuid4()))
            self.assertFalse(check.execute(self.other.id, self.read.id))

    def test_recreated_username_does_not_inherit_deleted_users_grants(self):
        grant = self.assign(
            SubjectType.USER, self.user.id, GrantTargetType.PERMISSION, self.read.id
        )
        with self.sessions.begin() as session:
            session.execute(delete(UserModel).where(UserModel.id == str(self.user.id)))
            recreated = User(uuid4(), self.user.username, "new-password-hash")
            SqlAlchemyUserRepository(session).save(recreated)
        self.assertEqual(self.effective(recreated.id), frozenset())
        with self.assertRaises(UserNotFoundError):
            self.effective(self.user.id)
        with self.sessions.begin() as session:
            self.assertTrue(SqlAlchemyGrantRepository(session).remove(grant))
