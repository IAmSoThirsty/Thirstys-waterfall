#!/usr/bin/env python3
"""Capture target rollback execution evidence for Standard v3."""

from __future__ import annotations

import argparse
import json
import sys
import time
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


def request_health(base_url: str, timeout: float) -> tuple[int | None, Any]:
    """Request the target health endpoint."""
    url = urljoin(normalize_base_url(base_url), "health")
    request = Request(url, headers={"Accept": "application/json"})
    try:
        with urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", errors="replace")
            return getattr(response, "status", response.getcode()), body[:1000]
    except HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="replace")[:1000]
    except (OSError, URLError) as exc:
        return None, str(exc)


def wait_for_health(
    base_url: str,
    timeout: float,
    *,
    health_client: Callable[[str, float], tuple[int | None, Any]],
) -> tuple[int | None, Any]:
    """Wait briefly for a restarted target to become healthy."""
    deadline = time.monotonic() + max(timeout, 1.0) * 6
    last_result: tuple[int | None, Any] = (None, "health check not attempted")
    while time.monotonic() <= deadline:
        last_result = health_client(base_url, timeout)
        if last_result[0] == 200:
            return last_result
        time.sleep(1)
    return last_result


def run_probe(
    *,
    rollback_commands: list[list[str]],
    validation_commands: list[list[str]],
    base_url: str | None,
    timeout: float,
    captured_at_utc: str,
    command_runner: Callable[[list[str], int], CommandResult] = run_command,
    health_client: Callable[
        [str, float], tuple[int | None, Any]
    ] = request_health,
) -> dict[str, Any]:
    """Capture rollback execution evidence."""
    checks: list[CheckResult] = []

    pre_health = None
    post_health = None
    if base_url:
        pre_health = health_client(base_url, timeout)

    rollback_results = [
        command_runner(command, 300) for command in rollback_commands
    ]
    validation_results = [
        command_runner(command, 120) for command in validation_commands
    ]

    if base_url:
        post_health = wait_for_health(
            base_url, timeout, health_client=health_client
        )

    checks.append(
        CheckResult(
            "rollback_commands_executed",
            bool(rollback_results)
            and all(result.passed for result in rollback_results),
            "all rollback commands exited successfully",
            [result.as_dict() for result in rollback_results],
        )
    )

    validation_passed = bool(validation_results) and all(
        result.passed for result in validation_results
    )
    post_health_passed = post_health is not None and post_health[0] == 200
    checks.append(
        CheckResult(
            "post_rollback_validation",
            validation_passed or post_health_passed,
            "post-rollback validation command or health check passed",
            {
                "validation_commands": [
                    result.as_dict() for result in validation_results
                ],
                "pre_health": pre_health,
                "post_health": post_health,
            },
        )
    )

    passed = all(check.passed for check in checks)
    return {
        "schema_version": 1,
        "evidence_type": "target_rollback",
        "captured_at_utc": captured_at_utc,
        "summary": {
            "passed": passed,
            "checks_passed": sum(1 for check in checks if check.passed),
            "checks_total": len(checks),
        },
        "checks": [check.as_dict() for check in checks],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Capture target rollback execution evidence."
    )
    parser.add_argument(
        "--rollback-command",
        action="append",
        required=True,
        type=parse_json_command,
        help="Rollback command as JSON array.",
    )
    parser.add_argument(
        "--validation-command",
        action="append",
        default=[],
        type=parse_json_command,
        help="Post-rollback validation command as JSON array.",
    )
    parser.add_argument("--base-url")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS
    )
    parser.add_argument("--captured-at-utc", default=utc_now())
    args = parser.parse_args(argv)

    artifact = run_probe(
        rollback_commands=args.rollback_command,
        validation_commands=args.validation_command,
        base_url=args.base_url,
        timeout=args.timeout,
        captured_at_utc=args.captured_at_utc,
    )
    write_artifact(args.output, artifact)
    print(json.dumps({"artifact": str(args.output), **artifact["summary"]}))
    return 0 if artifact["summary"]["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
