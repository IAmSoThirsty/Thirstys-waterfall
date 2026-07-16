#!/usr/bin/env python3
"""Capture service/orchestrator hardening evidence for Standard v3."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

SENSITIVE_NAMES = {
    "SECRET_KEY",
    "JWT_SECRET_KEY",
    "THIRSTYS_ADMIN_PASSWORD_HASH",
}


@dataclass(frozen=True)
class CommandResult:
    """Captured command result."""

    args: list[str]
    returncode: int
    stdout: str
    stderr: str

    @property
    def passed(self) -> bool:
        return self.returncode == 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "args": self.args,
            "returncode": self.returncode,
            "stdout": limit_text(redact_text(self.stdout)),
            "stderr": limit_text(redact_text(self.stderr)),
        }


@dataclass(frozen=True)
class CheckResult:
    """One hardening check."""

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
            result["data"] = redact_value(self.data)
        return result


def utc_now() -> str:
    """Return current UTC timestamp in ISO format."""
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def limit_text(value: str, limit: int = 5000) -> str:
    """Keep evidence output bounded."""
    if len(value) <= limit:
        return value
    return value[:limit] + "\n<truncated>"


def redact_text(value: str) -> str:
    """Redact known secret-bearing assignment values."""
    redacted = value
    for name in SENSITIVE_NAMES:
        redacted = re.sub(
            rf"({re.escape(name)}=)[^\s\"']+",
            r"\1<redacted>",
            redacted,
        )
        redacted = re.sub(
            rf'("{re.escape(name)}"\s*:\s*")[^"]*(")',
            r'\1<redacted>\2',
            redacted,
        )
    return redacted


def redact_value(value: Any) -> Any:
    """Recursively redact evidence data."""
    if isinstance(value, dict):
        return {
            key: "<redacted>" if key in SENSITIVE_NAMES else redact_value(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def compose_validation_env() -> dict[str, str]:
    """Return placeholder env values required only for compose interpolation."""
    env = os.environ.copy()
    env.update(
        {
            "SECRET_KEY": "probe-redacted-secret-key",
            "JWT_SECRET_KEY": "probe-redacted-jwt-secret-key",
            "THIRSTYS_ADMIN_USERNAME": "operator",
            "THIRSTYS_ADMIN_PASSWORD_HASH": "probe-redacted-password-hash",
            "CORS_ORIGINS": "https://operator-console.example",
            "THIRSTYS_IMAGE": (
                "ghcr.io/iamsothirsty/thirstys-waterfall:1.0.4@sha256:"
                + "0" * 64
            ),
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
    *,
    compose_file: Path,
    command_runner: Callable[..., CommandResult] = run_command,
) -> tuple[dict[str, Any] | None, CommandResult]:
    """Load normalized Docker Compose config as JSON."""
    result = command_runner(
        ["docker", "compose", "-f", str(compose_file), "config", "--format", "json"],
        timeout=60,
        env=compose_validation_env(),
    )
    if not result.passed:
        return None, result
    try:
        parsed = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None, result
    if not isinstance(parsed, dict):
        return None, result
    return parsed, result


def service_environment(service: dict[str, Any]) -> dict[str, str]:
    """Return a normalized service environment mapping."""
    raw_env = service.get("environment") or {}
    if isinstance(raw_env, dict):
        return {str(key): str(value) for key, value in raw_env.items()}
    if isinstance(raw_env, list):
        mapped: dict[str, str] = {}
        for item in raw_env:
            if not isinstance(item, str) or "=" not in item:
                continue
            key, value = item.split("=", 1)
            mapped[key] = value
        return mapped
    return {}


def service_volumes(service: dict[str, Any]) -> list[Any]:
    """Return normalized service volume entries."""
    volumes = service.get("volumes") or []
    return volumes if isinstance(volumes, list) else []


def volume_targets(volumes: list[Any]) -> dict[str, Any]:
    """Map volume targets to their normalized volume entry."""
    targets: dict[str, Any] = {}
    for volume in volumes:
        if isinstance(volume, dict):
            target = volume.get("target")
            if isinstance(target, str):
                targets[target] = volume
        elif isinstance(volume, str):
            parts = volume.split(":")
            if len(parts) >= 2:
                targets[parts[1]] = volume
    return targets


def is_read_only_volume(volume: Any) -> bool:
    """Return whether a normalized volume is read-only."""
    if isinstance(volume, dict):
        return bool(volume.get("read_only")) or volume.get("mode") == "ro"
    if isinstance(volume, str):
        return volume.endswith(":ro") or ":ro," in volume
    return False


def dockerfile_user(dockerfile_text: str) -> str | None:
    """Return the last USER directive in a Dockerfile."""
    users = []
    for line in dockerfile_text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split(None, 1)
        if len(parts) == 2 and parts[0].upper() == "USER":
            users.append(parts[1].strip())
    return users[-1] if users else None


def source_uses_required_secret_interpolation(
    compose_source: str,
    secret_name: str,
) -> bool:
    """Return whether compose source requires a secret variable."""
    return f"${{{secret_name}:?" in compose_source


def run_probe(
    *,
    compose_file: Path,
    dockerfile: Path,
    service_name: str,
    captured_at_utc: str,
    compose_config: dict[str, Any] | None = None,
    compose_source: str | None = None,
    dockerfile_text: str | None = None,
    command_runner: Callable[..., CommandResult] = run_command,
) -> dict[str, Any]:
    """Capture service/orchestrator hardening evidence."""
    checks: list[CheckResult] = []
    config_result: CommandResult | None = None
    if compose_config is None:
        compose_config, config_result = load_compose_config(
            compose_file=compose_file,
            command_runner=command_runner,
        )
    else:
        config_result = CommandResult(["<injected-compose-config>"], 0, "{}", "")

    if compose_source is None:
        compose_source = compose_file.read_text(encoding="utf-8")
    if dockerfile_text is None:
        dockerfile_text = dockerfile.read_text(encoding="utf-8")

    checks.append(
        CheckResult(
            "compose_config_captured",
            compose_config is not None,
            "docker compose normalized config captured as JSON",
            config_result.as_dict() if config_result else None,
        )
    )

    services = compose_config.get("services", {}) if compose_config else {}
    service = services.get(service_name) if isinstance(services, dict) else None
    checks.append(
        CheckResult(
            "service_defined",
            isinstance(service, dict),
            f"service {service_name!r} is present",
        )
    )

    service_config: dict[str, Any] = service if isinstance(service, dict) else {}
    env = service_environment(service_config)
    volumes = service_volumes(service_config)
    targets = volume_targets(volumes)
    security_opt = service_config.get("security_opt") or []
    cap_add = service_config.get("cap_add") or []
    deploy_value = service_config.get("deploy")
    deploy: dict[str, Any] = deploy_value if isinstance(deploy_value, dict) else {}
    resources_value = deploy.get("resources")
    resources: dict[str, Any] = (
        resources_value if isinstance(resources_value, dict) else {}
    )
    limits_value = resources.get("limits")
    limits: dict[str, Any] = (
        limits_value if isinstance(limits_value, dict) else {}
    )
    reservations_value = resources.get("reservations")
    reservations = (
        reservations_value if isinstance(reservations_value, dict) else {}
    )
    user = dockerfile_user(dockerfile_text)

    checks.extend(
        [
            CheckResult(
                "production_environment",
                env.get("THIRSTYS_ENV") == "production"
                and env.get("DEBUG", "").lower() == "false"
                and env.get("THIRSTYS_ALLOW_DEMO_LOGIN", "").lower() == "false",
                "service runs with production mode, debug disabled, and demo login disabled",
                {
                    "THIRSTYS_ENV": env.get("THIRSTYS_ENV"),
                    "DEBUG": env.get("DEBUG"),
                    "THIRSTYS_ALLOW_DEMO_LOGIN": env.get("THIRSTYS_ALLOW_DEMO_LOGIN"),
                },
            ),
            CheckResult(
                "required_secrets_interpolated",
                all(
                    source_uses_required_secret_interpolation(compose_source, name)
                    for name in SENSITIVE_NAMES
                ),
                "compose source requires production secret values through ${NAME:?message}",
            ),
            CheckResult(
                "non_root_container_user",
                bool(user and user not in {"0", "root"}),
                "Dockerfile ends with a non-root USER directive",
                {"user": user},
            ),
            CheckResult(
                "no_new_privileges",
                "no-new-privileges:true" in security_opt,
                "service enables no-new-privileges",
                security_opt,
            ),
            CheckResult(
                "not_privileged",
                service_config.get("privileged") is not True,
                "service is not configured as privileged",
                {"privileged": service_config.get("privileged", False)},
            ),
            CheckResult(
                "capabilities_are_explicit",
                set(cap_add) <= {"NET_ADMIN", "NET_RAW"} and bool(cap_add),
                "added Linux capabilities are explicit and limited to documented VPN/firewall scope",
                cap_add,
            ),
            CheckResult(
                "healthcheck_defined",
                isinstance(service_config.get("healthcheck"), dict)
                or isinstance(service_config.get("health_check"), dict),
                "service has an orchestrator healthcheck",
            ),
            CheckResult(
                "restart_policy_defined",
                service_config.get("restart")
                in {"unless-stopped", "always", "on-failure"},
                "service has a restart policy",
                {"restart": service_config.get("restart")},
            ),
            CheckResult(
                "resource_limits_defined",
                bool(limits.get("cpus") and limits.get("memory"))
                and bool(reservations.get("cpus") and reservations.get("memory")),
                "service declares CPU and memory limits and reservations",
                {"limits": limits, "reservations": reservations},
            ),
            CheckResult(
                "persistent_revocation_store",
                env.get("JWT_REVOCATION_DB_PATH", "").startswith("/home/thirsty/")
                and "/home/thirsty/.thirstys_waterfall" in targets,
                "JWT revocation database is under the persistent data volume",
                {
                    "JWT_REVOCATION_DB_PATH": env.get("JWT_REVOCATION_DB_PATH"),
                    "volume_target_present": "/home/thirsty/.thirstys_waterfall"
                    in targets,
                },
            ),
            CheckResult(
                "configuration_mount_read_only",
                "/app/config" in targets and is_read_only_volume(targets["/app/config"]),
                "application config mount is read-only",
                targets.get("/app/config"),
            ),
        ]
    )

    passed = all(check.passed for check in checks)
    return {
        "schema_version": 1,
        "evidence_type": "service_orchestrator_hardening",
        "captured_at_utc": captured_at_utc,
        "target": {
            "compose_file": str(compose_file),
            "dockerfile": str(dockerfile),
            "service": service_name,
        },
        "summary": {
            "passed": passed,
            "checks_passed": sum(1 for check in checks if check.passed),
            "checks_total": len(checks),
        },
        "checks": [check.as_dict() for check in checks],
        "normalized_service_config": redact_value(service_config),
    }


def write_artifact(output_path: Path, artifact: dict[str, Any]) -> None:
    """Write the evidence artifact."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(artifact, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Capture service/orchestrator hardening evidence."
    )
    parser.add_argument("--compose-file", type=Path, default=Path("docker-compose.yml"))
    parser.add_argument("--dockerfile", type=Path, default=Path("Dockerfile"))
    parser.add_argument("--service", default="thirstys-waterfall")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--captured-at-utc", default=utc_now())
    args = parser.parse_args(argv)

    artifact = run_probe(
        compose_file=args.compose_file,
        dockerfile=args.dockerfile,
        service_name=args.service,
        captured_at_utc=args.captured_at_utc,
    )
    write_artifact(args.output, artifact)
    print(
        json.dumps(
            {
                "artifact": str(args.output),
                "passed": artifact["summary"]["passed"],
                "checks_passed": artifact["summary"]["checks_passed"],
                "checks_total": artifact["summary"]["checks_total"],
            },
            indent=2,
        )
    )
    return 0 if artifact["summary"]["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
