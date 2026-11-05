import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi.testclient import TestClient

from auth_service.composition.app import create_app
from auth_service.composition.settings import Settings


class WebTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        settings = Settings(
            jwt_secret="test-key-with-at-least-thirty-two-bytes",
            database_url=f"sqlite:///{Path(self.temp.name)/'web.db'}",
        )
        self.client = self.enterContext(TestClient(create_app(settings)))

    def test_local_dashboard_is_served_with_restrictive_browser_headers(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.url.path, "/ui/")
        self.assertIn("مدیریت هویت و دسترسی", response.text)
        self.assertIn("script-src 'self'", response.headers["content-security-policy"])
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertEqual(response.headers["x-content-type-options"], "nosniff")
        self.assertIn('lang="fa"', response.text)
        for asset in ("app.js", "style.css"):
            self.assertEqual(self.client.get("/ui/" + asset).status_code, 200)

    def test_dashboard_does_not_make_admin_apis_public_or_expose_source_files(self):
        self.assertEqual(self.client.get("/users").status_code, 401)
        self.assertEqual(self.client.get("/ui/../../pyproject.toml").status_code, 404)
        self.assertEqual(self.client.get("/openapi.json").status_code, 200)

    def test_forms_never_fall_back_to_putting_credentials_in_query_strings(self):
        from html.parser import HTMLParser

        class Forms(HTMLParser):
            def __init__(self):
                super().__init__()
                self.methods = []

            def handle_starttag(self, tag, attrs):
                if tag == "form":
                    self.methods.append(dict(attrs).get("method", "get").lower())

        parser = Forms()
        parser.feed(self.client.get("/ui/").text)
        self.assertTrue(parser.methods)
        self.assertEqual(set(parser.methods), {"post"})
