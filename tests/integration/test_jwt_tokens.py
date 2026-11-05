import unittest
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import jwt

from auth_service.modules.identity.application.exceptions import InvalidTokenError
from auth_service.modules.identity.infrastructure.security.jwt_tokens import JwtTokens


class JwtTokenTests(unittest.TestCase):
    def setUp(self):
        self.secret = "test-secret-key-long-enough-for-both-hs256-and-hs384-algorithms"
        self.tokens = JwtTokens(self.secret, "test-issuer", "test-api", 900)
        self.user_id = uuid4()

    def claims(self):
        now = datetime.now(timezone.utc)
        return {
            "sub": str(self.user_id),
            "iss": "test-issuer",
            "aud": "test-api",
            "iat": now,
            "nbf": now,
            "exp": now + timedelta(minutes=15),
            "jti": str(uuid4()),
            "token_use": "access",
        }

    def encode(self, claims, secret=None, algorithm="HS256"):
        return jwt.encode(claims, secret or self.secret, algorithm=algorithm)

    def test_issue_and_verify(self):
        token = self.tokens.issue(self.user_id)
        self.assertEqual(self.tokens.verify(token.access_token), self.user_id)
        self.assertEqual(token.expires_in, 900)
        payload = jwt.decode(
            token.access_token,
            self.secret,
            algorithms=["HS256"],
            issuer="test-issuer",
            audience="test-api",
        )
        self.assertEqual(payload["exp"] - payload["iat"], 900)
        self.assertNotIn("password_hash", payload)
        self.assertNotIn("permissions", payload)
        self.assertNotEqual(
            token.access_token, self.tokens.issue(self.user_id).access_token
        )

    def test_rejects_invalid_signatures_algorithms_and_malformed_tokens(self):
        for token in (
            self.encode(
                self.claims(), secret="another-secret-key-at-least-thirty-two-bytes"
            ),
            self.encode(self.claims(), algorithm="HS384"),
            jwt.encode(self.claims(), "", algorithm="none"),
            "malformed",
            "",
        ):
            with self.subTest(token=token):
                with self.assertRaises(InvalidTokenError):
                    self.tokens.verify(token)

    def test_rejects_expired_and_future_tokens(self):
        now = datetime.now(timezone.utc)
        for field, value in [
            ("exp", now - timedelta(seconds=10)),
            ("nbf", now + timedelta(minutes=5)),
            ("iat", now + timedelta(minutes=5)),
        ]:
            with self.subTest(field=field):
                claims = self.claims()
                claims[field] = value
                with self.assertRaises(InvalidTokenError):
                    self.tokens.verify(self.encode(claims))

    def test_requires_all_security_claims(self):
        for field in self.claims():
            with self.subTest(field=field):
                claims = self.claims()
                del claims[field]
                with self.assertRaises(InvalidTokenError):
                    self.tokens.verify(self.encode(claims))

    def test_rejects_wrong_issuer_audience_purpose_and_subject(self):
        for field, value in [
            ("iss", "other"),
            ("aud", "other"),
            ("aud", ["test-api", "other"]),
            ("sub", "invalid-uuid"),
            ("sub", 42),
            ("token_use", "refresh"),
        ]:
            with self.subTest(field=field, value=value):
                claims = self.claims()
                claims[field] = value
                with self.assertRaises(InvalidTokenError):
                    self.tokens.verify(self.encode(claims))

    def test_rejects_invalid_configuration(self):
        for secret, issuer, audience, lifetime in [
            ("short", "issuer", "api", 900),
            (self.secret, "", "api", 900),
            (self.secret, "issuer", " ", 900),
            (self.secret, "issuer", "api", 0),
            (self.secret, "issuer", "api", 3601),
            (self.secret, "issuer", "api", True),
        ]:
            with self.subTest(issuer=issuer, audience=audience, lifetime=lifetime):
                with self.assertRaises(ValueError):
                    JwtTokens(secret, issuer, audience, lifetime)
