"""Web application import and health smoke tests."""

import importlib
import os
import subprocess
import sys
import unittest
from unittest import mock

from werkzeug.security import generate_password_hash


class TestWebAppImport(unittest.TestCase):
    def run_web_import(self, overrides):
        env = os.environ.copy()
        for key in (
            "THIRSTYS_ENV",
            "SECRET_KEY",
            "JWT_SECRET_KEY",
            "THIRSTYS_ADMIN_USERNAME",
            "THIRSTYS_ADMIN_PASSWORD_HASH",
            "CORS_ORIGINS",
            "THIRSTYS_ALLOW_DEMO_LOGIN",
        ):
            env.pop(key, None)
        env.update(overrides)
        return subprocess.run(
            [sys.executable, "-c", "import web.app"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=env,
            timeout=20,
        )

    def test_web_app_imports_without_external_thirsty_lang(self):
        app_module = importlib.import_module("web.app")

        self.assertTrue(hasattr(app_module, "app"))
        self.assertTrue(hasattr(app_module, "health_check"))

    def test_health_endpoint_reports_binding_status(self):
        app_module = importlib.import_module("web.app")
        client = app_module.app.test_client()

        response = client.get("/health")
        payload = response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(payload["status"], "healthy")
        self.assertIn("sovereign_binding", payload)
        self.assertIn("available", payload["sovereign_binding"])

    def test_default_login_fails_closed_without_configured_credentials(self):
        app_module = importlib.import_module("web.app")
        client = app_module.app.test_client()

        response = client.post(
            "/api/auth/login", json={"username": "admin", "password": "admin"}
        )
        payload = response.get_json()

        self.assertEqual(response.status_code, 503)
        self.assertEqual(payload["error"], "Authentication is not configured")

    def test_configured_admin_hash_can_authenticate(self):
        app_module = importlib.import_module("web.app")
        password_hash = generate_password_hash("correct-horse")

        with mock.patch.object(app_module.Config, "ADMIN_USERNAME", "operator"), mock.patch.object(
            app_module.Config, "ADMIN_PASSWORD_HASH", password_hash
        ):
            response = app_module.app.test_client().post(
                "/api/auth/login",
                json={"username": "operator", "password": "correct-horse"},
            )
            payload = response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertIn("access_token", payload)
        self.assertEqual(payload["user"]["username"], "operator")
        self.assertEqual(payload["user"]["auth_mode"], "configured")

    def test_production_import_requires_explicit_secrets(self):
        completed = self.run_web_import({"THIRSTYS_ENV": "production"})

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("Production configuration is missing", completed.stdout)
        self.assertIn("SECRET_KEY", completed.stdout)
        self.assertIn("JWT_SECRET_KEY", completed.stdout)
        self.assertIn("THIRSTYS_ADMIN_USERNAME", completed.stdout)
        self.assertIn("THIRSTYS_ADMIN_PASSWORD_HASH", completed.stdout)
        self.assertIn("CORS_ORIGINS", completed.stdout)

    def test_production_import_rejects_wildcard_cors_and_demo_login(self):
        base = {
            "THIRSTYS_ENV": "production",
            "SECRET_KEY": "s" * 64,
            "JWT_SECRET_KEY": "j" * 64,
            "THIRSTYS_ADMIN_USERNAME": "operator",
            "THIRSTYS_ADMIN_PASSWORD_HASH": generate_password_hash("correct-horse"),
            "CORS_ORIGINS": "*",
        }
        wildcard = self.run_web_import(base)

        self.assertNotEqual(wildcard.returncode, 0)
        self.assertIn("Production CORS_ORIGINS must not include '*'", wildcard.stdout)

        demo = dict(base)
        demo["CORS_ORIGINS"] = "https://example.invalid"
        demo["THIRSTYS_ALLOW_DEMO_LOGIN"] = "true"
        demo_enabled = self.run_web_import(demo)

        self.assertNotEqual(demo_enabled.returncode, 0)
        self.assertIn("Production must not enable THIRSTYS_ALLOW_DEMO_LOGIN", demo_enabled.stdout)

    def test_production_import_accepts_required_secret_configuration(self):
        completed = self.run_web_import(
            {
                "THIRSTYS_ENV": "production",
                "SECRET_KEY": "s" * 64,
                "JWT_SECRET_KEY": "j" * 64,
                "THIRSTYS_ADMIN_USERNAME": "operator",
                "THIRSTYS_ADMIN_PASSWORD_HASH": generate_password_hash("correct-horse"),
                "CORS_ORIGINS": "https://example.invalid",
                "THIRSTYS_ALLOW_DEMO_LOGIN": "false",
            }
        )

        self.assertEqual(completed.returncode, 0, completed.stdout)


if __name__ == "__main__":
    unittest.main()
