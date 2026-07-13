#!/usr/bin/env python3
"""Pull and run a published image on a target host for Standard v3 evidence."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError
from urllib.request import Request, urlopen

DEFAULT_PORT = 18082
DEFAULT_TIMEOUT_SECONDS = 10.0
SECRET_ENV_KEYS = {
    "SECRET_KEY",
    "JWT_SECRET_KEY",
    "THIRSTYS_ADMIN_PASSWORD_HASH",
}


@dataclass(frozen=True)
class CommandResult:
    """Sanitized command execution result."""

    args: list[str]
    returncode: int
    stdout: str
    stderr: str

    @property
    def passed(self) -> bool:
        return self.returncode == 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "args": redact_args(self.args),
            "returncode": self.returncode,
            "stdout": limit_text(self.stdout),
            "stderr": limit_text(self.stderr),
        }


@dataclass(frozen=True)
class CheckResult:
    """One evidence check result."""

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
            result["data"] = redact_json(self.data)
        return result


def utc_now() -> str:
    """Return the current UTC timestamp in ISO format."""
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def limit_text(value: str, limit: int = 4000) -> str:
    """Keep artifact text bounded."""
    if len(value) <= limit:
        return value
    return value[:limit] + "\n<truncated>"


def split_env_arg(value: str) -> tuple[str, str] | None:
    """Split KEY=VALUE environment args."""
    key, separator, env_value = value.partition("=")
    if not separator:
        return None
    return key, env_value


def is_secret_key(key: str) -> bool:
    """Return whether an env key should be redacted."""
    upper = key.upper()
    return upper in SECRET_ENV_KEYS or "PASSWORD" in upper or "SECRET" in upper


def redact_args(args: list[str]) -> list[str]:
    """Redact secret-bearing command arguments."""
    redacted: list[str] = []
    for arg in args:
        env_pair = split_env_arg(arg)
        if env_pair and is_secret_key(env_pair[0]):
            redacted.append(f"{env_pair[0]}=<redacted>")
        else:
            redacted.append(arg)
    return redacted


def redact_json(value: Any) -> Any:
    """Redact token and secret-bearing JSON fields."""
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            if is_secret_key(key) or key.lower() in {
                "access_token",
                "refresh_token",
                "token",
            }:
                redacted[key] = "<redacted>"
            else:
                redacted[key] = redact_json(item)
        return redacted
    if isinstance(value, list):
        return [redact_json(item) for item in value]
    return value


def image_ref_with_digest(image: str, digest: str) -> str:
    """Return an image reference pinned to a digest."""
    if not digest.startswith("sha256:"):
        raise ValueError("image digest must start with sha256:")
    if "@sha256:" in image:
        return image
    return f"{image}@{digest}"


def run_command(args: list[str], timeout: int = 120) -> CommandResult:
    """Run a command and capture output."""
    try:
        completed = subprocess.run(
            args,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return CommandResult(
            args=args,
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            args=args,
            returncode=124,
            stdout=exc.stdout or "",
            stderr=(exc.stderr or "") + "\ncommand timed out",
        )


def request_json(
    url: str,
    *,
    method: str = "GET",
    payload: dict[str, Any] | None = None,
    bearer_token: str | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> tuple[int, Any]:
    """Make a JSON HTTP request and return status/body."""
    data = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"

    request = Request(url, data=data, headers=headers, method=method)
    try:
        with urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", errors="replace")
            return getattr(response, "status", response.getcode()), parse_body(
                body
            )
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return exc.code, parse_body(body)


def parse_body(body: str) -> Any:
    """Parse response body as JSON when possible."""
    if not body:
        return None
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return body[:2000]


def detect_engine(explicit_engine: str | None) -> str:
    """Select docker or podman."""
    if explicit_engine:
        if shutil.which(explicit_engine) is None:
            raise SystemExit(f"container engine not found: {explicit_engine}")
        return explicit_engine
    for engine in ("docker", "podman"):
        if shutil.which(engine):
            return engine
    raise SystemExit("docker or podman is required on the target host")


def container_env_args(
    *,
    port: int,
    admin_username: str,
    admin_password_hash: str,
    cors_origins: str,
    secret_key: str,
    jwt_secret_key: str,
    thirsty_lang_path: Path | None,
) -> list[str]:
    """Build production container environment args."""
    env_args = [
        "-e",
        "THIRSTYS_ENV=production",
        "-e",
        f"SECRET_KEY={secret_key}",
        "-e",
        f"JWT_SECRET_KEY={jwt_secret_key}",
        "-e",
        "WEB_HOST=0.0.0.0",
        "-e",
        "WEB_PORT=8080",
        "-e",
        "WORKERS=1",
        "-e",
        "WORKER_CLASS=gevent",
        "-e",
        f"CORS_ORIGINS={cors_origins}",
        "-e",
        f"THIRSTYS_ADMIN_USERNAME={admin_username}",
        "-e",
        f"THIRSTYS_ADMIN_PASSWORD_HASH={admin_password_hash}",
        "-e",
        "THIRSTYS_ALLOW_DEMO_LOGIN=false",
    ]
    if thirsty_lang_path:
        env_args.extend(
            [
                "-e",
                "THIRSTY_LANG_PATH=/opt/thirsty-lang",
                "-v",
                f"{thirsty_lang_path}:/opt/thirsty-lang:ro",
            ]
        )
    return env_args


def token_from(body: Any, key: str) -> str | None:
    """Read a token from a JSON body."""
    if isinstance(body, dict) and isinstance(body.get(key), str):
        return body[key]
    return None


def check_http_smoke(
    *,
    base_url: str,
    admin_username: str,
    admin_password: str,
    timeout: float,
    http_client: Callable[..., tuple[int, Any]] = request_json,
) -> list[CheckResult]:
    """Run health and auth smoke checks against the container."""
    checks: list[CheckResult] = []
    health_status, health_body = http_client(
        f"{base_url}/health", timeout=timeout
    )
    checks.append(
        CheckResult(
            "health",
            health_status == 200 and isinstance(health_body, dict),
            f"GET /health returned {health_status}",
            health_body,
        )
    )

    default_status, default_body = http_client(
        f"{base_url}/api/auth/login",
        method="POST",
        payload={"username": "admin", "password": "admin"},
        timeout=timeout,
    )
    default_accepted = default_status == 200 and token_from(
        default_body, "access_token"
    )
    checks.append(
        CheckResult(
            "default_login_rejected",
            default_status in {400, 401, 403, 503} and not default_accepted,
            f"default login returned {default_status}",
            default_body,
        )
    )

    login_status, login_body = http_client(
        f"{base_url}/api/auth/login",
        method="POST",
        payload={"username": admin_username, "password": admin_password},
        timeout=timeout,
    )
    access_token = token_from(login_body, "access_token")
    checks.append(
        CheckResult(
            "configured_login",
            login_status == 200 and bool(access_token),
            f"configured login returned {login_status}",
            login_body,
        )
    )

    if access_token:
        policy_status, policy_body = http_client(
            f"{base_url}/api/auth/session-policy",
            bearer_token=access_token,
            timeout=timeout,
        )
        checks.append(
            CheckResult(
                "session_policy",
                policy_status == 200,
                f"session policy returned {policy_status}",
                policy_body,
            )
        )

    return checks


def build_run_args(
    *,
    engine: str,
    name: str,
    port: int,
    env_args: list[str],
    image_ref: str,
) -> list[str]:
    """Build the container run command."""
    return [
        engine,
        "run",
        "-d",
        "--name",
        name,
        "-p",
        f"{port}:8080",
        *env_args,
        image_ref,
    ]


def run_probe(
    *,
    engine: str,
    image: str,
    image_digest: str,
    container_name: str,
    port: int,
    admin_username: str,
    admin_password: str,
    admin_password_hash: str,
    cors_origins: str,
    secret_key: str,
    jwt_secret_key: str,
    thirsty_lang_path: Path | None,
    timeout: float,
    captured_at_utc: str,
    command_runner: Callable[[list[str], int], CommandResult] = run_command,
    http_client: Callable[..., tuple[int, Any]] = request_json,
) -> dict[str, Any]:
    """Pull, run, smoke, inspect, and clean up a published image."""
    image_ref = image_ref_with_digest(image, image_digest)
    commands: list[CommandResult] = []
    checks: list[CheckResult] = []
    cleanup: list[CommandResult] = []

    version = command_runner([engine, "--version"], 30)
    commands.append(version)
    checks.append(
        CheckResult("container_engine_available", version.passed, engine)
    )

    pull = command_runner([engine, "pull", image_ref], 600)
    commands.append(pull)
    checks.append(
        CheckResult(
            "published_image_pull",
            pull.passed,
            f"pulled {image_ref}",
            pull.as_dict(),
        )
    )

    inspect = command_runner(
        [engine, "image", "inspect", image_ref, "--format", "{{json .}}"], 120
    )
    commands.append(inspect)
    inspect_data = (
        parse_body(inspect.stdout.strip()) if inspect.stdout else None
    )
    repo_digests = []
    if isinstance(inspect_data, dict):
        repo_digests = inspect_data.get("RepoDigests") or []
    digest_seen = any(image_digest in digest for digest in repo_digests)
    checks.append(
        CheckResult(
            "image_digest_present",
            inspect.passed and digest_seen,
            "image inspect contains requested digest",
            {"repo_digests": repo_digests},
        )
    )

    cleanup.append(command_runner([engine, "rm", "-f", container_name], 60))
    env_args = container_env_args(
        port=port,
        admin_username=admin_username,
        admin_password_hash=admin_password_hash,
        cors_origins=cors_origins,
        secret_key=secret_key,
        jwt_secret_key=jwt_secret_key,
        thirsty_lang_path=thirsty_lang_path,
    )
    run = command_runner(
        build_run_args(
            engine=engine,
            name=container_name,
            port=port,
            env_args=env_args,
            image_ref=image_ref,
        ),
        120,
    )
    commands.append(run)
    checks.append(
        CheckResult("container_started", run.passed, "container run completed")
    )

    if run.passed:
        base_url = f"http://127.0.0.1:{port}"
        checks.extend(
            check_http_smoke(
                base_url=base_url,
                admin_username=admin_username,
                admin_password=admin_password,
                timeout=timeout,
                http_client=http_client,
            )
        )

    logs = command_runner(
        [engine, "logs", container_name, "--tail", "160"], 60
    )
    commands.append(logs)
    checks.append(
        CheckResult(
            "container_logs_captured",
            logs.passed and bool(logs.stdout or logs.stderr),
            "captured container logs",
            logs.as_dict(),
        )
    )
    cleanup.append(command_runner([engine, "rm", "-f", container_name], 60))

    passed = all(check.passed for check in checks)
    return {
        "schema_version": 1,
        "evidence_type": "published_image_pull_run",
        "captured_at_utc": captured_at_utc,
        "summary": {
            "passed": passed,
            "checks_passed": sum(1 for check in checks if check.passed),
            "checks_total": len(checks),
        },
        "target_runtime": {
            "container_engine": engine,
            "container_name": container_name,
            "port": port,
        },
        "image": {
            "requested": image,
            "digest": image_digest,
            "pinned_reference": image_ref,
        },
        "secrets_recorded": False,
        "commands": [command.as_dict() for command in commands],
        "checks": [check.as_dict() for check in checks],
        "cleanup": [command.as_dict() for command in cleanup],
    }


def write_artifact(output_path: Path, artifact: dict[str, Any]) -> None:
    """Write the evidence artifact."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(artifact, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def optional_path(value: str | None) -> Path | None:
    """Return a Path for non-empty values."""
    if not value:
        return None
    path = Path(value)
    if not path.exists():
        raise SystemExit(f"Thirsty-Lang path does not exist: {path}")
    return path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Create target published-image pull/run evidence."
    )
    parser.add_argument("--image", required=True)
    parser.add_argument("--image-digest", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--engine", default=os.getenv("CONTAINER_ENGINE"))
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument(
        "--container-name",
        default=f"thirstys-target-evidence-{os.getpid()}",
    )
    parser.add_argument(
        "--admin-username",
        default=os.getenv("THIRSTYS_TARGET_USERNAME", "operator"),
    )
    parser.add_argument(
        "--admin-password", default=os.getenv("THIRSTYS_TARGET_PASSWORD")
    )
    parser.add_argument(
        "--admin-password-hash",
        default=os.getenv("THIRSTYS_TARGET_ADMIN_PASSWORD_HASH"),
    )
    parser.add_argument("--cors-origins", default=None)
    parser.add_argument("--secret-key", default=os.getenv("SECRET_KEY"))
    parser.add_argument(
        "--jwt-secret-key", default=os.getenv("JWT_SECRET_KEY")
    )
    parser.add_argument(
        "--thirsty-lang-path",
        default=os.getenv("THIRSTY_LANG_TARGET_PATH"),
    )
    parser.add_argument(
        "--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS
    )
    parser.add_argument("--captured-at-utc", default=utc_now())
    args = parser.parse_args(argv)

    if not args.admin_password:
        raise SystemExit(
            "--admin-password or THIRSTYS_TARGET_PASSWORD required"
        )
    if not args.admin_password_hash:
        raise SystemExit(
            "--admin-password-hash or "
            "THIRSTYS_TARGET_ADMIN_PASSWORD_HASH required"
        )

    engine = detect_engine(args.engine)
    cors_origins = args.cors_origins or f"http://127.0.0.1:{args.port}"
    artifact = run_probe(
        engine=engine,
        image=args.image,
        image_digest=args.image_digest,
        container_name=args.container_name,
        port=args.port,
        admin_username=args.admin_username,
        admin_password=args.admin_password,
        admin_password_hash=args.admin_password_hash,
        cors_origins=cors_origins,
        secret_key=args.secret_key or secrets.token_hex(32),
        jwt_secret_key=args.jwt_secret_key or secrets.token_hex(32),
        thirsty_lang_path=optional_path(args.thirsty_lang_path),
        timeout=args.timeout,
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
