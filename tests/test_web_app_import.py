"""Web application import and health smoke tests."""

import importlib
import os
from pathlib import Path
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
        default_username = "admin"

        response = client.post(
            "/api/auth/login",
            json={"username": default_username, "password": default_username},
        )
        payload = response.get_json()

        self.assertEqual(response.status_code, 503)
        self.assertEqual(payload["error"], "Authentication is not configured")

    def test_configured_admin_hash_can_authenticate(self):
        app_module = importlib.import_module("web.app")
        admin_login_value = "non-sensitive-test-login-value"
        password_hash = generate_password_hash(admin_login_value)

        with mock.patch.object(app_module.Config, "ADMIN_USERNAME", "operator"), mock.patch.object(
            app_module.Config, "ADMIN_PASSWORD_HASH", password_hash
        ):
            response = app_module.app.test_client().post(
                "/api/auth/login",
                json={"username": "operator", "password": admin_login_value},
            )
            payload = response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertIn("access_token", payload)
        self.assertEqual(payload["user"]["username"], "operator")
        self.assertEqual(payload["user"]["auth_mode"], "configured")

    def test_vpn_connect_does_not_report_success_when_service_fails(self):
        app_module = importlib.import_module("web.app")
        token = None
        with app_module.app.app_context():
            token = app_module.create_access_token(identity="operator")

        with mock.patch.object(
            app_module.service,
            "vpn_connect",
            return_value={"success": False, "error": "VPN not available"},
        ):
            response = app_module.app.test_client().post(
                "/api/vpn/connect",
                headers={"Authorization": f"Bearer {token}"},
                json={"protocol": "wireguard"},
            )
            payload = response.get_json()

        self.assertEqual(response.status_code, 503)
        self.assertFalse(payload["success"])
        self.assertNotIn("connected", payload)

    def test_firewall_list_does_not_report_fake_active_state_on_backend_failure(self):
        app_module = importlib.import_module("web.app")
        with app_module.app.app_context():
            token = app_module.create_access_token(identity="operator")

        with mock.patch.object(
            app_module.service,
            "get_firewalls_status",
            return_value={"success": False, "error": "Firewalls not available"},
        ):
            response = app_module.app.test_client().get(
                "/api/firewalls/list",
                headers={"Authorization": f"Bearer {token}"},
            )
            payload = response.get_json()

        self.assertEqual(response.status_code, 503)
        self.assertFalse(payload["success"])
        self.assertTrue(payload["firewalls"])
        self.assertTrue(all(not item["active"] for item in payload["firewalls"]))

    def test_frontend_does_not_embed_demo_credentials_or_fake_active_claims(self):
        root = Path(__file__).resolve().parents[1]
        app_js = (root / "web" / "static" / "js" / "app.js").read_text(
            encoding="utf-8"
        )
        index_html = (root / "web" / "static" / "index.html").read_text(
            encoding="utf-8"
        )

        forbidden_js = [
            "api.login('admin', 'admin')",
            "For demo purposes",
            "Running in demo mode",
            "VPN Active",
            "7-layer protection",
            "Trackers Blocked",
        ]
        forbidden_html = [
            "All queries encrypted",
            "Search the web (Encrypted)",
            "Multi-Hop Active",
            "8 Types Active",
            "Everything encrypted",
            "<span>Connected</span>",
        ]

        for value in forbidden_js:
            self.assertNotIn(value, app_js)
        for value in forbidden_html:
            self.assertNotIn(value, index_html)

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
