import unittest
from unittest.mock import Mock
from uuid import uuid4

from auth_service.modules.identity.application.dto import IssuedAccessToken
from auth_service.modules.identity.application.exceptions import (
    InvalidCredentialsError,
    InvalidTokenError,
)
from auth_service.modules.identity.application.ports import (
    AccessTokenIssuer,
    AccessTokenVerifier,
    PasswordHasher,
    UserRepository,
)
from auth_service.modules.identity.application.use_cases.get_current_user import (
    GetCurrentUser,
)
from auth_service.modules.identity.application.use_cases.login import Login
from auth_service.modules.identity.domain.entities.user import User


class AuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.users = Mock(spec=UserRepository)
        self.passwords = Mock(spec=PasswordHasher)
        self.tokens = Mock(spec=AccessTokenIssuer)
        self.user = User(uuid4(), "ali", "stored-hash")
        self.users.get_by_username.return_value = self.user
        self.passwords.verify.return_value = True
        self.tokens.issue.return_value = IssuedAccessToken("signed-token", 900)
        self.login = Login(self.users, self.passwords, self.tokens, "dummy-hash")

    def test_login_issues_token_for_verified_active_user(self):
        result = self.login.execute(" ali ", " password ")
        self.assertEqual(result, IssuedAccessToken("signed-token", 900))
        self.users.get_by_username.assert_called_once_with("ali")
        self.passwords.verify.assert_called_once_with(" password ", "stored-hash")
        self.tokens.issue.assert_called_once_with(self.user.id)

    def test_unknown_user_still_verifies_dummy_hash(self):
        self.users.get_by_username.return_value = None
        with self.assertRaises(InvalidCredentialsError):
            self.login.execute("unknown", "password")
        self.passwords.verify.assert_called_once_with("password", "dummy-hash")
        self.tokens.issue.assert_not_called()

    def test_wrong_password_does_not_issue_token(self):
        self.passwords.verify.return_value = False
        with self.assertRaises(InvalidCredentialsError):
            self.login.execute("ali", "wrong")
        self.tokens.issue.assert_not_called()

    def test_inactive_user_does_not_receive_token(self):
        self.users.get_by_username.return_value = self.user.deactivate()
        with self.assertRaises(InvalidCredentialsError):
            self.login.execute("ali", "password")
        self.passwords.verify.assert_called_once()
        self.tokens.issue.assert_not_called()

    def test_invalid_input_is_rejected_without_issuing_token(self):
        for username, password in [
            ("", "pw"),
            (" ", "pw"),
            (None, "pw"),
            ("ali", ""),
            ("ali", None),
        ]:
            with self.subTest(username=username, password=password):
                with self.assertRaises(InvalidCredentialsError):
                    self.login.execute(username, password)
        self.tokens.issue.assert_not_called()

    def test_token_dto_repr_hides_token(self):
        self.assertNotIn("signed-token", repr(self.tokens.issue.return_value))

    def test_current_user_loads_live_record(self):
        verifier = Mock(spec=AccessTokenVerifier)
        verifier.verify.return_value = self.user.id
        self.users.get_by_id.return_value = self.user
        result = GetCurrentUser(self.users, verifier).execute("token")
        self.assertEqual(result, self.user)
        verifier.verify.assert_called_once_with("token")
        self.users.get_by_id.assert_called_once_with(self.user.id)

    def test_current_user_rejects_deleted_and_inactive_users(self):
        verifier = Mock(spec=AccessTokenVerifier)
        verifier.verify.return_value = self.user.id
        for user in (None, self.user.deactivate()):
            with self.subTest(user=user):
                self.users.get_by_id.return_value = user
                with self.assertRaises(InvalidTokenError):
                    GetCurrentUser(self.users, verifier).execute("token")

    def test_current_user_does_not_query_database_for_invalid_token(self):
        verifier = Mock(spec=AccessTokenVerifier)
        verifier.verify.side_effect = InvalidTokenError("Invalid authentication token")
        with self.assertRaises(InvalidTokenError):
            GetCurrentUser(self.users, verifier).execute("invalid")
        self.users.get_by_id.assert_not_called()
