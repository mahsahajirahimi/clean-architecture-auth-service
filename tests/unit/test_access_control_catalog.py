import unittest
from unittest.mock import Mock
from uuid import uuid4

from auth_service.modules.access_control.application.exceptions import (
    InvalidInputError,
    ScopeNotFoundError,
)
from auth_service.modules.access_control.application.ports import (
    PermissionRepository,
    ScopeRepository,
)
from auth_service.modules.access_control.application.use_cases.list_permissions import (
    ListPermissions,
)
from auth_service.modules.access_control.application.use_cases.list_scopes import (
    ListScopes,
)


class AccessControlCatalogTests(unittest.TestCase):
    def test_invalid_pagination_is_rejected_before_repository_access(self):
        scopes, permissions = Mock(spec=ScopeRepository), Mock(
            spec=PermissionRepository
        )
        for limit, offset in [
            (0, 0),
            (101, 0),
            (True, 0),
            ("5", 0),
            (5, -1),
            (5, True),
        ]:
            with self.subTest(limit=limit, offset=offset):
                with self.assertRaises(InvalidInputError):
                    ListScopes(scopes).execute(limit, offset)
                with self.assertRaises(InvalidInputError):
                    ListPermissions(scopes, permissions).execute(uuid4(), limit, offset)
        scopes.list.assert_not_called()
        scopes.get_by_id.assert_not_called()
        permissions.list_by_scope.assert_not_called()

    def test_permission_listing_requires_a_valid_existing_scope(self):
        scopes, permissions = Mock(spec=ScopeRepository), Mock(
            spec=PermissionRepository
        )
        scopes.get_by_id.return_value = None
        with self.assertRaises(InvalidInputError):
            ListPermissions(scopes, permissions).execute("invalid")
        with self.assertRaises(ScopeNotFoundError):
            ListPermissions(scopes, permissions).execute(uuid4())
        permissions.list_by_scope.assert_not_called()
