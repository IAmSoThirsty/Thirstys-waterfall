#!/usr/bin/env python3
"""Validate production TLS reverse-proxy deployment configuration."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


@dataclass(frozen=True)
class CheckResult:
    """One production proxy configuration check."""

    name: str
    passed: bool
    detail: str
    data: Any = None

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "name": self.name,
            "passed": self.passed,
            "detail": self.detail,
        }
        if self.data is not None:
            result["data"] = self.data
        return result


@dataclass(frozen=True)
class CommandResult:
    """Captured command result."""

    args: list[str]
    returncode: int
    stdout: str
    stderr: str


def validation_env() -> dict[str, str]:
    """Return placeholder values for required compose interpolation."""
    env = os.environ.copy()
    env.update(
        {
            "SECRET_KEY": "proxy-config-redacted-secret",
            "JWT_SECRET_KEY": "proxy-config-redacted-jwt-secret",
            "THIRSTYS_ADMIN_USERNAME": "operator",
            "THIRSTYS_ADMIN_PASSWORD_HASH": "proxy-config-redacted-hash",
            "THIRSTYS_PUBLIC_HOST": "thirstys-waterfall.example.com",
            "CADDY_ACME_EMAIL": "ops@example.com",
        }
    )
    return env


def run_command(
    args: list[str],
    *,
    timeout: int = 60,
    env: dict[str, str] | None = None,
) -> CommandResult:
    """Run a command with shell disabled and capture output."""
    try:
        completed = subprocess.run(
            args,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
        return CommandResult(
            args=args,
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = (
            exc.stdout.decode("utf-8", errors="replace")
            if isinstance(exc.stdout, bytes)
            else exc.stdout or ""
        )
        stderr = (
            exc.stderr.decode("utf-8", errors="replace")
            if isinstance(exc.stderr, bytes)
            else exc.stderr or ""
        )
        return CommandResult(
            args=args,
            returncode=124,
            stdout=stdout,
            stderr=stderr + "\ncommand timed out",
        )
    except OSError as exc:
        return CommandResult(args=args, returncode=1, stdout="", stderr=str(exc))


def load_compose_config(
    compose_file: Path,
    *,
    command_runner: Callable[..., CommandResult] = run_command,
) -> tuple[dict[str, Any] | None, CommandResult]:
    """Load normalized Docker Compose JSON configuration."""
    result = command_runner(
        ["docker", "compose", "-f", str(compose_file), "config", "--format", "json"],
        timeout=60,
        env=validation_env(),
    )
    if result.returncode != 0:
        return None, result
    try:
        parsed = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None, result
    if not isinstance(parsed, dict):
        return None, result
    return parsed, result


def service_env(service: dict[str, Any]) -> dict[str, str]:
    """Return normalized service environment."""
    raw_env = service.get("environment") or {}
    if isinstance(raw_env, dict):
        return {str(key): str(value) for key, value in raw_env.items()}
    if isinstance(raw_env, list):
        mapped: dict[str, str] = {}
        for item in raw_env:
            if isinstance(item, str) and "=" in item:
                key, value = item.split("=", 1)
                mapped[key] = value
        return mapped
    return {}


def published_ports(service: dict[str, Any]) -> set[int]:
    """Return published TCP ports from normalized service config."""
    ports: set[int] = set()
    for port in service.get("ports") or []:
        if isinstance(port, dict) and str(port.get("protocol", "tcp")) == "tcp":
            published = port.get("published")
            if published is not None:
                ports.add(int(published))
        elif isinstance(port, str):
            published = port.split(":", 1)[0]
            if published.isdigit():
                ports.add(int(published))
    return ports


def volume_target(service: dict[str, Any], target: str) -> Any | None:
    """Return a volume entry for a given target path."""
    for volume in service.get("volumes") or []:
        if isinstance(volume, dict) and volume.get("target") == target:
            return volume
        if isinstance(volume, str) and f":{target}" in volume:
            return volume
    return None


def is_read_only(volume: Any) -> bool:
    """Return whether a volume entry is read-only."""
    if isinstance(volume, dict):
        return bool(volume.get("read_only")) or volume.get("mode") == "ro"
    if isinstance(volume, str):
        return volume.endswith(":ro") or ":ro," in volume
    return False


def network_names(service: dict[str, Any]) -> set[str]:
    """Return attached network names."""
    networks = service.get("networks") or {}
    if isinstance(networks, dict):
        return set(networks)
    if isinstance(networks, list):
        return {str(network) for network in networks}
    return set()


def run_checks(
    *,
    compose_config: dict[str, Any],
    caddyfile_text: str,
    app_service_name: str = "thirstys-waterfall",
    proxy_service_name: str = "caddy",
) -> list[CheckResult]:
    """Validate the normalized production proxy configuration."""
    services = compose_config.get("services") or {}
    app = services.get(app_service_name) if isinstance(services, dict) else None
    proxy = services.get(proxy_service_name) if isinstance(services, dict) else None
    app = app if isinstance(app, dict) else {}
    proxy = proxy if isinstance(proxy, dict) else {}
    app_env = service_env(app)
    proxy_env = service_env(proxy)

    app_networks = network_names(app)
    proxy_networks = network_names(proxy)
    caddyfile_mount = volume_target(proxy, "/etc/caddy/Caddyfile")

    return [
        CheckResult(
            "services_defined",
            bool(app and proxy),
            "application and reverse-proxy services are defined",
        ),
        CheckResult(
            "app_not_publicly_published",
            not app.get("ports"),
            "application service does not publish host ports directly",
            {"ports": app.get("ports", [])},
        ),
        CheckResult(
            "app_exposes_internal_http",
            "8080" in {str(port) for port in app.get("expose") or []},
            "application exposes port 8080 only to the private compose network",
            {"expose": app.get("expose", [])},
        ),
        CheckResult(
            "proxy_publishes_http_https",
            {80, 443}.issubset(published_ports(proxy)),
            "reverse proxy publishes ports 80 and 443",
            {"published_ports": sorted(published_ports(proxy))},
        ),
        CheckResult(
            "shared_private_network",
            bool(app_networks & proxy_networks),
            "application and proxy share a private compose network",
            {
                "app_networks": sorted(app_networks),
                "proxy_networks": sorted(proxy_networks),
            },
        ),
        CheckResult(
            "proxy_depends_on_healthy_app",
            isinstance(proxy.get("depends_on"), dict)
            and proxy["depends_on"].get(app_service_name, {}).get("condition")
            == "service_healthy",
            "proxy waits for application health before routing",
            proxy.get("depends_on"),
        ),
        CheckResult(
            "proxy_caddyfile_read_only",
            caddyfile_mount is not None and is_read_only(caddyfile_mount),
            "Caddyfile is mounted read-only",
            caddyfile_mount,
        ),
        CheckResult(
            "proxy_tls_host_required",
            proxy_env.get("THIRSTYS_PUBLIC_HOST")
            == "thirstys-waterfall.example.com"
            and "{$THIRSTYS_PUBLIC_HOST}" in caddyfile_text,
            "proxy requires a public host value used by the Caddyfile",
        ),
        CheckResult(
            "proxy_acme_email_required",
            proxy_env.get("CADDY_ACME_EMAIL") == "ops@example.com"
            and "{$CADDY_ACME_EMAIL}" in caddyfile_text,
            "proxy requires an ACME account email used by the Caddyfile",
        ),
        CheckResult(
            "proxy_routes_to_app",
            "reverse_proxy thirstys-waterfall:8080" in caddyfile_text,
            "Caddyfile routes traffic to the private application service",
        ),
        CheckResult(
            "security_headers_present",
            all(
                header in caddyfile_text
                for header in (
                    "Strict-Transport-Security",
                    "X-Content-Type-Options",
                    "X-Frame-Options",
                    "Referrer-Policy",
                )
            ),
            "Caddyfile declares required security headers",
        ),
        CheckResult(
            "app_cors_matches_tls_host",
            app_env.get("CORS_ORIGINS") == "https://thirstys-waterfall.example.com",
            "application CORS origin is scoped to the HTTPS public host",
            {"CORS_ORIGINS": app_env.get("CORS_ORIGINS")},
        ),
        CheckResult(
            "proxy_privileges_limited",
            "no-new-privileges:true" in (proxy.get("security_opt") or [])
            and set(proxy.get("cap_drop") or []) == {"ALL"}
            and set(proxy.get("cap_add") or []) == {"NET_BIND_SERVICE"},
            "proxy drops all capabilities except NET_BIND_SERVICE and enables no-new-privileges",
            {
                "security_opt": proxy.get("security_opt", []),
                "cap_drop": proxy.get("cap_drop", []),
                "cap_add": proxy.get("cap_add", []),
            },
        ),
        CheckResult(
            "proxy_persistence_defined",
            volume_target(proxy, "/data") is not None
            and volume_target(proxy, "/config") is not None,
            "proxy ACME data and runtime config volumes are persistent",
        ),
    ]


def verify_config(
    *,
    compose_file: Path,
    caddyfile: Path,
    command_runner: Callable[..., CommandResult] = run_command,
) -> dict[str, Any]:
    """Validate production proxy config and return a report."""
    compose_config, command = load_compose_config(
        compose_file,
        command_runner=command_runner,
    )
    caddyfile_text = caddyfile.read_text(encoding="utf-8")
    checks = []
    checks.append(
        CheckResult(
            "compose_config_loaded",
            compose_config is not None,
            "docker compose normalized production config loaded",
            {"returncode": command.returncode, "stderr": command.stderr[:1000]},
        )
    )
    if compose_config is not None:
        checks.extend(
            run_checks(
                compose_config=compose_config,
                caddyfile_text=caddyfile_text,
            )
        )
    return {
        "status": "passed" if all(check.passed for check in checks) else "failed",
        "checks_passed": sum(1 for check in checks if check.passed),
        "checks_total": len(checks),
        "checks": [check.as_dict() for check in checks],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate production TLS reverse-proxy deployment config."
    )
    parser.add_argument(
        "--compose-file",
        type=Path,
        default=Path("docker-compose.production.yml"),
    )
    parser.add_argument(
        "--caddyfile",
        type=Path,
        default=Path("deploy/caddy/Caddyfile"),
    )
    args = parser.parse_args(argv)
    report = verify_config(compose_file=args.compose_file, caddyfile=args.caddyfile)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
