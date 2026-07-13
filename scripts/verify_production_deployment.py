#!/usr/bin/env python3
"""Run the Standard v3 local deployment verification gate.

This script is intentionally conservative: any failed command, health check,
auth check, or retired-identifier check exits non-zero.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Iterable
import secrets

from werkzeug.security import generate_password_hash


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TEST_TIMEOUT_SECONDS = 480
SUBPROCESS_ENCODING = "utf-8"
SENSITIVE_ENV_NAMES = {
    "SECRET_KEY",
    "JWT_SECRET_KEY",
    "THIRSTYS_ADMIN_PASSWORD_HASH",
}
RETIRED_IDENTIFIERS = (
    "Thirsty_Lang",
    "T_A_R_L",
    "Thirst_of_Gods",
    "TSCG",
    "backend=legacy",
    "backend: legacy",
)
CLAIM_MARKERS = (
    "production-grade",
    "simulated",
    "simplified",
    "placeholder",
    "quantum-resistant",
    "god_tier_encrypted",
    "God tier",
    "GOD TIER",
    "7-layer",
    "7 layers",
    'encryption_layers": 7',
    "Would",
    "would",
)
SKIP_DIRS = {
    ".git",
    ".pytest_cache",
    "__pycache__",
    "build",
    "dist",
    "htmlcov",
    "thirstys_waterfall.egg-info",
}


def run(cmd: list[str], *, timeout: int = 120, env: dict[str, str] | None = None) -> str:
    print(f"\n$ {' '.join(cmd)}", flush=True)
    completed = subprocess.run(
        cmd,
        cwd=ROOT,
        env=env,
        text=True,
        encoding=SUBPROCESS_ENCODING,
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
    )
    if completed.stdout:
        print(completed.stdout, end="" if completed.stdout.endswith("\n") else "\n")
    if completed.returncode != 0:
        raise SystemExit(f"Command failed with exit code {completed.returncode}: {' '.join(cmd)}")
    return completed.stdout


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def request_json(url: str, *, method: str = "GET", payload: dict[str, Any] | None = None) -> Any:
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def assert_rejected(url: str, payload: dict[str, Any]) -> None:
    try:
        request_json(url, method="POST", payload=payload)
    except urllib.error.HTTPError as exc:
        if exc.code == 401:
            return
        raise
    raise AssertionError("default admin/admin login was accepted")


def wait_for_health(port: int, expected_backend: str | None) -> dict[str, Any]:
    last_error: Exception | None = None
    for _ in range(30):
        try:
            health = request_json(f"http://127.0.0.1:{port}/health")
            if health.get("status") != "healthy":
                raise AssertionError(f"unexpected health status: {health!r}")
            binding = health.get("sovereign_binding") or {}
            if expected_backend and binding.get("backend") != expected_backend:
                raise AssertionError(
                    f"expected sovereign backend {expected_backend!r}, got {binding!r}"
                )
            return health
        except Exception as exc:  # noqa: BLE001 - report final observed startup failure
            last_error = exc
            time.sleep(1)
    raise AssertionError(f"health check did not pass: {last_error}")


def verify_auth(port: int, admin_password: str) -> None:
    login_url = f"http://127.0.0.1:{port}/api/auth/login"
    good = request_json(
        login_url,
        method="POST",
        payload={"username": "operator", "password": admin_password},
    )
    if not good.get("access_token"):
        raise AssertionError("configured admin login did not return an access token")
    default_username = "admin"
    assert_rejected(
        login_url,
        {"username": default_username, "password": default_username},
    )


def smoke_local_web(thirsty_lang_path: str | None) -> None:
    port = free_port()
    admin_password = secrets.token_urlsafe(18)
    env = os.environ.copy()
    env.update(
        {
            "THIRSTYS_ENV": "production",
            "WEB_HOST": "127.0.0.1",
            "WEB_PORT": str(port),
            "DEBUG": "False",
            "SECRET_KEY": secrets.token_hex(32),
            "JWT_SECRET_KEY": secrets.token_hex(32),
            "CORS_ORIGINS": f"http://127.0.0.1:{port}",
            "THIRSTYS_ADMIN_USERNAME": "operator",
            "THIRSTYS_ADMIN_PASSWORD_HASH": generate_password_hash(admin_password),
            "THIRSTYS_ALLOW_DEMO_LOGIN": "false",
        }
    )
    if thirsty_lang_path:
        env["THIRSTY_LANG_PATH"] = thirsty_lang_path

    print(f"\n$ local web smoke on 127.0.0.1:{port}", flush=True)
    proc = subprocess.Popen(
        [sys.executable, "web/app.py"],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding=SUBPROCESS_ENCODING,
        errors="replace",
    )
    try:
        health = wait_for_health(port, "thirsty-lang" if thirsty_lang_path else None)
        verify_auth(port, admin_password)
        print(
            "local web smoke passed: "
            f"status={health.get('status')} backend={(health.get('sovereign_binding') or {}).get('backend')}"
        )
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=10)


def docker_run_json(cmd: list[str], *, timeout: int = 120) -> str:
    return run(["docker", *cmd], timeout=timeout)


def redact_arg(value: str) -> str:
    for name in SENSITIVE_ENV_NAMES:
        if value.startswith(f"{name}="):
            return f"{name}=<redacted>"
    return value


def redacted_command(cmd: list[str]) -> str:
    return " ".join(redact_arg(value) for value in cmd)


def compose_validation_env() -> dict[str, str]:
    admin_password = secrets.token_urlsafe(18)
    env = os.environ.copy()
    env.update(
        {
            "SECRET_KEY": secrets.token_hex(32),
            "JWT_SECRET_KEY": secrets.token_hex(32),
            "THIRSTYS_ADMIN_USERNAME": "operator",
            "THIRSTYS_ADMIN_PASSWORD_HASH": generate_password_hash(admin_password),
            "CORS_ORIGINS": "http://localhost:8080",
        }
    )
    return env


def docker_env_args(port: int, thirsty_lang_path: str | None, password_hash: str) -> list[str]:
    env_args = [
        "-e",
        "THIRSTYS_ENV=production",
        "-e",
        f"SECRET_KEY={secrets.token_hex(32)}",
        "-e",
        f"JWT_SECRET_KEY={secrets.token_hex(32)}",
        "-e",
        "WEB_HOST=0.0.0.0",
        "-e",
        "WEB_PORT=8080",
        "-e",
        "WORKERS=1",
        "-e",
        "WORKER_CLASS=gevent",
        "-e",
        f"CORS_ORIGINS=http://localhost:{port}",
        "-e",
        "THIRSTYS_ADMIN_USERNAME=operator",
        "-e",
        f"THIRSTYS_ADMIN_PASSWORD_HASH={password_hash}",
        "-e",
        "THIRSTYS_ALLOW_DEMO_LOGIN=false",
    ]
    if thirsty_lang_path:
        env_args.extend(
            [
                "-e",
                "THIRSTY_LANG_PATH=/opt/thirsty-lang",  # pragma: allowlist secret
                "-v",
                f"{thirsty_lang_path}:/opt/thirsty-lang:ro",
            ]
        )
    return env_args


def docker_logs(name: str, *, tail: str = "120") -> str:
    return subprocess.run(
        ["docker", "logs", name, "--tail", tail],
        cwd=ROOT,
        text=True,
        encoding=SUBPROCESS_ENCODING,
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    ).stdout


def run_smoke_container(
    image: str,
    name: str,
    port: int,
    env_args: list[str],
    expected_backend: str | None,
    admin_password: str,
) -> dict[str, Any]:
    docker_run_json(["rm", "-f", name], timeout=30) if container_exists(name) else ""

    cmd = [
        "run",
        "-d",
        "--name",
        name,
        "-p",
        f"{port}:8080",
        *env_args,
        image,
    ]
    print(f"\n$ docker {redacted_command(cmd)}", flush=True)
    try:
        subprocess.check_output(
            ["docker", *cmd],
            cwd=ROOT,
            text=True,
            encoding=SUBPROCESS_ENCODING,
            errors="replace",
        )
    except subprocess.CalledProcessError as exc:
        raise SystemExit(
            f"Command failed with exit code {exc.returncode}: docker {redacted_command(cmd)}"
        ) from exc
    try:
        health = wait_for_health(port, expected_backend)
        verify_auth(port, admin_password)
        logs = docker_logs(name)
        if not logs.strip():
            raise AssertionError("container startup/log capture was empty")
        print(
            "docker container verified: "
            f"name={name} status={health.get('status')} "
            f"backend={(health.get('sovereign_binding') or {}).get('backend')} "
            f"log_bytes={len(logs.encode('utf-8'))}"
        )
        return health
    except Exception:
        print(docker_logs(name, tail="160"))
        raise
    finally:
        subprocess.run(["docker", "rm", "-f", name], cwd=ROOT, stdout=subprocess.DEVNULL)


def smoke_docker(image: str, thirsty_lang_path: str | None) -> None:
    name = f"thirstys-verify-{int(time.time())}"
    port = free_port()
    admin_password = secrets.token_urlsafe(18)
    password_hash = generate_password_hash(admin_password)
    env_args = docker_env_args(port, thirsty_lang_path, password_hash)
    health = run_smoke_container(
        image,
        name,
        port,
        env_args,
        "thirsty-lang" if thirsty_lang_path else None,
        admin_password,
    )
    print(
        "docker smoke passed: "
        f"status={health.get('status')} backend={(health.get('sovereign_binding') or {}).get('backend')}"
    )


def smoke_docker_rollback(image: str, thirsty_lang_path: str | None) -> None:
    timestamp = int(time.time())
    current_name = f"thirstys-current-{timestamp}"
    rollback_name = f"thirstys-rollback-{timestamp}"
    rollback_image = f"{image}-rollback-good"
    port = free_port()
    admin_password = secrets.token_urlsafe(18)
    password_hash = generate_password_hash(admin_password)
    env_args = docker_env_args(port, thirsty_lang_path, password_hash)
    expected_backend = "thirsty-lang" if thirsty_lang_path else None

    docker_run_json(["tag", image, rollback_image], timeout=60)
    run_smoke_container(image, current_name, port, env_args, expected_backend, admin_password)
    rollback_health = run_smoke_container(
        rollback_image,
        rollback_name,
        port,
        env_args,
        expected_backend,
        admin_password,
    )
    print(
        "docker rollback smoke passed: "
        f"from={image} to={rollback_image} "
        f"status={rollback_health.get('status')} "
        f"backend={(rollback_health.get('sovereign_binding') or {}).get('backend')}"
    )


def container_exists(name: str) -> bool:
    completed = subprocess.run(
        ["docker", "ps", "-a", "--filter", f"name={name}", "--format", "{{.Names}}"],
        cwd=ROOT,
        text=True,
        encoding=SUBPROCESS_ENCODING,
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    return name in completed.stdout.splitlines()


def scan_retired_identifiers(paths: Iterable[Path]) -> None:
    findings: list[str] = []
    for base in paths:
        if not base.exists():
            continue
        files = [base] if base.is_file() else base.rglob("*")
        for path in files:
            if path.is_dir() or any(part in SKIP_DIRS for part in path.parts):
                continue
            if path.suffix.lower() not in {".py", ".md", ".txt", ".toml", ".yml", ".yaml", ".example", ".lock"}:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            for symbol in RETIRED_IDENTIFIERS:
                if symbol in text:
                    findings.append(f"{path.relative_to(ROOT)}: {symbol}")
    if findings:
        raise SystemExit("retired Thirsty-Lang compatibility identifiers remain:\n" + "\n".join(findings))
    print("retired Thirsty-Lang compatibility identifier scan passed")


def scan_claim_markers(paths: Iterable[Path]) -> None:
    findings: list[str] = []
    for base in paths:
        if not base.exists():
            continue
        files = [base] if base.is_file() else base.rglob("*")
        for path in files:
            if path.is_dir() or any(part in SKIP_DIRS for part in path.parts):
                continue
            if path.suffix.lower() not in {".py", ".md", ".js", ".ts", ".tsx", ".html", ".css"}:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            for lineno, line in enumerate(text.splitlines(), start=1):
                for marker in CLAIM_MARKERS:
                    if marker in line:
                        findings.append(f"{path.relative_to(ROOT)}:{lineno}: {marker}")
    if findings:
        raise SystemExit("claim-stub markers remain:\n" + "\n".join(findings))
    print("claim-stub marker scan passed")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--thirsty-lang-path",
        default=os.environ.get("THIRSTY_LANG_PATH"),
        help="Optional enhanced Thirsty-Lang checkout to require during smoke tests.",
    )
    parser.add_argument("--image", default="thirstys-waterfall:codex-verify")
    parser.add_argument("--skip-docker", action="store_true")
    parser.add_argument(
        "--skip-docker-build",
        action="store_true",
        help="Smoke test the supplied Docker image without rebuilding it first.",
    )
    parser.add_argument(
        "--target-evidence-manifest",
        type=Path,
        help="Validate a Standard v3 target deployment evidence manifest.",
    )
    parser.add_argument(
        "--require-target-evidence",
        action="store_true",
        help="Fail closed unless --target-evidence-manifest is provided.",
    )
    parser.add_argument("--skip-tests", action="store_true")
    parser.add_argument(
        "--test-timeout",
        type=int,
        default=DEFAULT_TEST_TIMEOUT_SECONDS,
        help="Maximum seconds allowed for the complete pytest suite.",
    )
    args = parser.parse_args(argv)

    if args.test_timeout <= 0:
        raise SystemExit("--test-timeout must be a positive integer")
    if args.thirsty_lang_path and not Path(args.thirsty_lang_path).exists():
        raise SystemExit(f"THIRSTY_LANG_PATH does not exist: {args.thirsty_lang_path}")
    if args.require_target_evidence and args.target_evidence_manifest is None:
        raise SystemExit(
            "target deployment evidence is required; pass --target-evidence-manifest"
        )
    if args.target_evidence_manifest is not None:
        manifest_path = args.target_evidence_manifest
        if not manifest_path.is_absolute():
            manifest_path = ROOT / manifest_path
        run(
            [
                sys.executable,
                "scripts/verify_target_deployment_evidence.py",
                str(manifest_path),
            ],
            timeout=60,
        )

    scan_retired_identifiers(
        [
            ROOT / "thirstys_waterfall",
            ROOT / "tests",
            ROOT / "docs",
            ROOT / "README.md",
            ROOT / ".env.example",
            ROOT / "pyproject.toml",
            ROOT / "requirements.txt",
            ROOT / "requirements-deploy.lock",
        ]
    )
    scan_claim_markers(
        [
            ROOT / "thirstys_waterfall",
            ROOT / "src",
            ROOT / "tests",
            ROOT / "examples",
            ROOT / "web" / "app.py",
            ROOT / "web" / "gunicorn.conf.py",
            ROOT / "web" / "static" / "js",
            ROOT / "README.md",
            ROOT / "docs" / "DOS_TRAP_MODE.md",
            ROOT / "docs" / "mfa_authentication.md",
            ROOT / "docs" / "network_stealth.md",
            ROOT / "docs" / "NEW_FEATURES.md",
            ROOT / "docs" / "SHOWCASE.md",
            ROOT / "docs" / "COMPETITION_COMPARISON.md",
        ]
    )
    run([sys.executable, "-m", "compileall", "-q", "scripts", "thirstys_waterfall", "tests", "web"])
    run(
        [
            "flake8",
            "scripts/",
            "thirstys_waterfall/",
            "web/",
            "tests/",
            "--count",
            "--max-line-length=127",
            "--statistics",
        ]
    )
    run([sys.executable, "-m", "mypy"])
    run(["bandit", "-r", "thirstys_waterfall/", "-q"])
    run(["safety", "check", "-r", "requirements-deploy.lock", "--json"])
    if not args.skip_tests:
        run(
            [sys.executable, "-m", "pytest", "-q"],
            timeout=args.test_timeout,
        )
    run([sys.executable, "-m", "pip", "wheel", ".", "--no-deps", "--no-build-isolation", "-w", "..\\wheelhouse"], timeout=180)
    smoke_local_web(args.thirsty_lang_path)

    if not args.skip_docker:
        run(["docker", "compose", "config", "--quiet"], timeout=60, env=compose_validation_env())
        if not args.skip_docker_build:
            run(["docker", "build", "-t", args.image, "."], timeout=420)
        smoke_docker(args.image, args.thirsty_lang_path)
        smoke_docker_rollback(args.image, args.thirsty_lang_path)

    print("\nStandard v3 local deployment verification passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
