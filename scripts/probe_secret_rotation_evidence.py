#!/usr/bin/env python3
"""Capture target secret rotation evidence for Standard v3."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import Request, urlopen

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from target_evidence_common import (  # noqa: E402
    CheckResult,
    CommandResult,
    parse_json_command,
    run_command,
    utc_now,
    write_artifact,
)

DEFAULT_TIMEOUT_SECONDS = 10.0


def normalize_base_url(base_url: str) -> str:
    """Normalize a target base URL."""
    normalized = base_url.strip()
    if not normalized.startswith(("http://", "https://")):
        raise ValueError("base URL must start with http:// or https://")
    return normalized.rstrip("/") + "/"


def redact_body(body: Any) -> Any:
    """Redact token-bearing response fields."""
    if isinstance(body, dict):
        redacted: dict[str, Any] = {}
        for key, value in body.items():
            if key.lower() in {"access_token", "refresh_token", "token"}:
                redacted[key] = "<redacted>"
            else:
                redacted[key] = redact_body(value)
        return redacted
    if isinstance(body, list):
        return [redact_body(value) for value in body]
    return body


def parse_body(raw_body: bytes) -> Any:
    """Parse a JSON response body when possible."""
    text = raw_body.decode("utf-8", errors="replace")
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text[:1000]


def request_login(
    *,
    base_url: str,
    username: str,
    password: str,
    timeout: float,
) -> tuple[int | None, Any]:
    """Attempt a target login."""
    url = urljoin(normalize_base_url(base_url), "api/auth/login")
    request = Request(
        url,
        data=json.dumps({"username": username, "password": password}).encode(
            "utf-8"
        ),
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            return getattr(response, "status", response.getcode()), parse_body(
                response.read()
            )
    except HTTPError as exc:
        return exc.code, parse_body(exc.read())
    except (OSError, URLError) as exc:
        return None, str(exc)


def login_accepted(status: int | None, body: Any) -> bool:
    """Return whether a login response includes an access token."""
    return (
        status == 200
        and isinstance(body, dict)
        and isinstance(body.get("access_token"), str)
        and bool(body["access_token"])
    )


def run_probe(
    *,
    base_url: str,
    username: str,
    old_password: str,
    new_password: str,
    rotation_commands: list[list[str]],
    require_pre_rotation_old_login: bool,
    timeout: float,
    captured_at_utc: str,
    command_runner: Callable[[list[str], int], CommandResult] = run_command,
    login_client: Callable[..., tuple[int | None, Any]] = request_login,
) -> dict[str, Any]:
    """Capture secret rotation evidence."""
    checks: list[CheckResult] = []
    if require_pre_rotation_old_login:
        pre_status, pre_body = login_client(
            base_url=base_url,
            username=username,
            password=old_password,
            timeout=timeout,
        )
        checks.append(
            CheckResult(
                "old_credentials_accepted_before_rotation",
                login_accepted(pre_status, pre_body),
                f"old credentials before rotation returned {pre_status}",
                redact_body(pre_body),
            )
        )

    rotation_results = [
        command_runner(command, 300) for command in rotation_commands
    ]
    if rotation_results:
        checks.append(
            CheckResult(
                "rotation_commands_executed",
                all(result.passed for result in rotation_results),
                "all secret rotation commands exited successfully",
                [result.as_dict() for result in rotation_results],
            )
        )

    old_status, old_body = login_client(
        base_url=base_url,
        username=username,
        password=old_password,
        timeout=timeout,
    )
    new_status, new_body = login_client(
        base_url=base_url,
        username=username,
        password=new_password,
        timeout=timeout,
    )

    checks.append(
        CheckResult(
            "old_credentials_rejected",
            not login_accepted(old_status, old_body)
            and old_status in {400, 401, 403, 503},
            f"old credentials returned {old_status}",
            redact_body(old_body),
        )
    )
    checks.append(
        CheckResult(
            "new_credentials_accepted",
            login_accepted(new_status, new_body),
            f"new credentials returned {new_status}",
            redact_body(new_body),
        )
    )

    passed = all(check.passed for check in checks)
    return {
        "schema_version": 1,
        "evidence_type": "secret_rotation",
        "captured_at_utc": captured_at_utc,
        "target": {"base_url": base_url, "username": username},
        "summary": {
            "passed": passed,
            "checks_passed": sum(1 for check in checks if check.passed),
            "checks_total": len(checks),
        },
        "checks": [check.as_dict() for check in checks],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Capture target secret rotation evidence."
    )
    parser.add_argument("--base-url", required=True)
    parser.add_argument(
        "--username", default=os.environ.get("THIRSTYS_TARGET_USERNAME")
    )
    parser.add_argument(
        "--old-password",
        default=os.environ.get("THIRSTYS_TARGET_OLD_PASSWORD"),
    )
    parser.add_argument(
        "--new-password",
        default=os.environ.get("THIRSTYS_TARGET_NEW_PASSWORD"),
    )
    parser.add_argument(
        "--rotation-command",
        action="append",
        default=[],
        type=parse_json_command,
        help="Secret rotation command as JSON array.",
    )
    parser.add_argument(
        "--require-pre-rotation-old-login",
        action="store_true",
        help=(
            "Require the old credential to authenticate before rotation "
            "commands run."
        ),
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS
    )
    parser.add_argument("--captured-at-utc", default=utc_now())
    args = parser.parse_args(argv)

    if not args.username:
        raise SystemExit("--username or THIRSTYS_TARGET_USERNAME is required")
    if not args.old_password:
        raise SystemExit(
            "--old-password or THIRSTYS_TARGET_OLD_PASSWORD is required"
        )
    if not args.new_password:
        raise SystemExit(
            "--new-password or THIRSTYS_TARGET_NEW_PASSWORD is required"
        )

    artifact = run_probe(
        base_url=args.base_url,
        username=args.username,
        old_password=args.old_password,
        new_password=args.new_password,
        rotation_commands=args.rotation_command,
        require_pre_rotation_old_login=args.require_pre_rotation_old_login,
        timeout=args.timeout,
        captured_at_utc=args.captured_at_utc,
    )
    write_artifact(args.output, artifact)
    print(json.dumps({"artifact": str(args.output), **artifact["summary"]}))
    return 0 if artifact["summary"]["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
