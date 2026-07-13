"""Tests for production TLS reverse-proxy configuration validation."""

import importlib.util
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify_production_proxy_config.py"
SPEC = importlib.util.spec_from_file_location("verify_production_proxy_config", SCRIPT)
proxy_config = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = proxy_config
SPEC.loader.exec_module(proxy_config)


def _valid_config():
    return {
        "services": {
            "thirstys-waterfall": {
                "environment": {
                    "CORS_ORIGINS": "https://thirstys-waterfall.example.com",
                },
                "expose": ["8080"],
                "networks": {"thirstys_private": None},
            },
            "caddy": {
                "depends_on": {
                    "thirstys-waterfall": {"condition": "service_healthy"}
                },
                "environment": {
                    "THIRSTYS_PUBLIC_HOST": "thirstys-waterfall.example.com",
                    "CADDY_ACME_EMAIL": "ops@example.com",
                },
                "ports": [
                    {"published": "80", "target": 80, "protocol": "tcp"},
                    {"published": "443", "target": 443, "protocol": "tcp"},
                ],
                "networks": {"thirstys_private": None},
                "volumes": [
                    {
                        "target": "/etc/caddy/Caddyfile",
                        "read_only": True,
                    },
                    {"target": "/data"},
                    {"target": "/config"},
                ],
                "security_opt": ["no-new-privileges:true"],
                "cap_drop": ["ALL"],
                "cap_add": ["NET_BIND_SERVICE"],
            },
        }
    }


def _valid_caddyfile():
    return "\n".join(
        [
            "email {$CADDY_ACME_EMAIL}",
            "{$THIRSTYS_PUBLIC_HOST} {",
            "header {",
            "Strict-Transport-Security value",
            "X-Content-Type-Options value",
            "X-Frame-Options value",
            "Referrer-Policy value",
            "}",
            "reverse_proxy thirstys-waterfall:8080",
            "}",
        ]
    )


def test_proxy_config_checks_pass_for_hardened_config():
    checks = proxy_config.run_checks(
        compose_config=_valid_config(),
        caddyfile_text=_valid_caddyfile(),
    )

    assert all(check.passed for check in checks)


def test_proxy_config_checks_fail_when_app_is_publicly_published():
    config = _valid_config()
    config["services"]["thirstys-waterfall"]["ports"] = [
        {"published": "8080", "target": 8080, "protocol": "tcp"}
    ]

    checks = proxy_config.run_checks(
        compose_config=config,
        caddyfile_text=_valid_caddyfile(),
    )

    public_check = next(
        check for check in checks if check.name == "app_not_publicly_published"
    )
    assert public_check.passed is False


def test_verify_config_uses_compose_json_output(tmp_path):
    compose_file = tmp_path / "docker-compose.production.yml"
    caddyfile = tmp_path / "Caddyfile"
    compose_file.write_text("services: {}\n", encoding="utf-8")
    caddyfile.write_text(_valid_caddyfile(), encoding="utf-8")

    def command_runner(args, timeout, env):
        assert args[-2:] == ["--format", "json"]
        assert env["THIRSTYS_PUBLIC_HOST"] == "thirstys-waterfall.example.com"
        return proxy_config.CommandResult(args, 0, json.dumps(_valid_config()), "")

    report = proxy_config.verify_config(
        compose_file=compose_file,
        caddyfile=caddyfile,
        command_runner=command_runner,
    )

    assert report["status"] == "passed"
