#!/usr/bin/env python3
"""Probe a live target for Standard v3 health/auth evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import Request, urlopen

DEFAULT_TIMEOUT_SECONDS = 10.0


@dataclass(frozen=True)
class HttpResult:
    """HTTP response captured without secrets."""

    status_code: int
    body: Any


@dataclass(frozen=True)
class CheckResult:
    """One target evidence check."""

    name: str
    passed: bool
    method: str
    url: str
    status_code: int | None
    detail: str
    body: Any = None

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "name": self.name,
            "passed": self.passed,
            "method": self.method,
            "url": self.url,
            "status_code": self.status_code,
            "detail": self.detail,
        }
        if self.body is not None:
            result["body"] = redact_body(self.body)
        return result


def utc_now() -> str:
    """Return the current UTC timestamp in ISO format."""
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def normalize_base_url(base_url: str) -> str:
    """Normalize a target base URL for endpoint joins."""
    normalized = base_url.strip()
    if not normalized:
        raise ValueError("base URL cannot be empty")
    if not normalized.startswith(("http://", "https://")):
        raise ValueError("base URL must start with http:// or https://")
    return normalized.rstrip("/") + "/"


def endpoint_url(base_url: str, endpoint: str) -> str:
    """Build an endpoint URL from the normalized base URL."""
    return urljoin(normalize_base_url(base_url), endpoint.lstrip("/"))


def redact_body(body: Any) -> Any:
    """Remove token-bearing fields from a JSON body."""
    if isinstance(body, dict):
        redacted: dict[str, Any] = {}
        for key, value in body.items():
            if key.lower() in {
                "access_token",
                "refresh_token",
                "token",
                "password",
            }:
                redacted[key] = "<redacted>"
            else:
                redacted[key] = redact_body(value)
        return redacted
    if isinstance(body, list):
        return [redact_body(value) for value in body]
    return body


def parse_body(raw_body: bytes) -> Any:
    """Parse JSON bodies and keep short text for non-JSON responses."""
    text = raw_body.decode("utf-8", errors="replace")
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text[:2000]


def request_json(
    *,
    url: str,
    method: str = "GET",
    payload: dict[str, Any] | None = None,
    bearer_token: str | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> HttpResult:
    """Send an HTTP request and return status/body."""
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
            status_code = getattr(response, "status", response.getcode())
            return HttpResult(
                status_code=status_code, body=parse_body(response.read())
            )
    except HTTPError as exc:
        return HttpResult(status_code=exc.code, body=parse_body(exc.read()))


def token_fingerprint(token: str) -> str:
    """Return a non-secret token fingerprint for evidence correlation."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def get_token(body: Any, key: str) -> str | None:
    """Read a token string from a JSON response body."""
    if isinstance(body, dict) and isinstance(body.get(key), str) and body[key]:
        return body[key]
    return None


def session_policy_is_shared(body: Any) -> bool:
    """Return whether a session policy reports a shared revocation store."""
    if not isinstance(body, dict):
        return False
    policy = body.get("session_policy")
    return (
        isinstance(policy, dict)
        and policy.get("revocation_store_shared") is True
    )


def check_health(base_url: str, timeout: float) -> CheckResult:
    """Check unauthenticated target health."""
    url = endpoint_url(base_url, "/health")
    try:
        result = request_json(url=url, timeout=timeout)
    except (OSError, URLError) as exc:
        return CheckResult(
            "health", False, "GET", url, None, f"request failed: {exc}"
        )
    passed = result.status_code == 200 and isinstance(result.body, dict)
    return CheckResult(
        "health",
        passed,
        "GET",
        url,
        result.status_code,
        "health endpoint returned JSON",
        result.body,
    )


def check_default_login_rejected(
    base_url: str,
    *,
    username: str,
    password: str,
    timeout: float,
) -> CheckResult:
    """Check that default/demo credentials are rejected."""
    url = endpoint_url(base_url, "/api/auth/login")
    try:
        result = request_json(
            url=url,
            method="POST",
            payload={"username": username, "password": password},
            timeout=timeout,
        )
    except (OSError, URLError) as exc:
        return CheckResult(
            "default_login_rejected",
            False,
            "POST",
            url,
            None,
            f"request failed: {exc}",
        )

    accepted = result.status_code == 200 and get_token(
        result.body, "access_token"
    )
    passed = result.status_code in {400, 401, 403, 503} and not accepted
    return CheckResult(
        "default_login_rejected",
        passed,
        "POST",
        url,
        result.status_code,
        (
            "default credentials rejected"
            if passed
            else "default credentials were not rejected"
        ),
        result.body,
    )


def check_configured_login(
    base_url: str,
    *,
    username: str,
    password: str,
    timeout: float,
) -> tuple[CheckResult, str | None, str | None]:
    """Check configured login and return issued tokens."""
    url = endpoint_url(base_url, "/api/auth/login")
    try:
        result = request_json(
            url=url,
            method="POST",
            payload={"username": username, "password": password},
            timeout=timeout,
        )
    except (OSError, URLError) as exc:
        return (
            CheckResult(
                "configured_login",
                False,
                "POST",
                url,
                None,
                f"request failed: {exc}",
            ),
            None,
            None,
        )

    access_token = get_token(result.body, "access_token")
    refresh_token = get_token(result.body, "refresh_token")
    passed = result.status_code == 200 and bool(access_token and refresh_token)
    return (
        CheckResult(
            "configured_login",
            passed,
            "POST",
            url,
            result.status_code,
            (
                "configured credentials issued access and refresh tokens"
                if passed
                else "configured login failed"
            ),
            result.body,
        ),
        access_token,
        refresh_token,
    )


def check_session_policy(
    *,
    name: str,
    base_url: str,
    access_token: str,
    timeout: float,
    require_shared_store: bool,
) -> CheckResult:
    """Check authenticated session policy."""
    url = endpoint_url(base_url, "/api/auth/session-policy")
    try:
        result = request_json(
            url=url, bearer_token=access_token, timeout=timeout
        )
    except (OSError, URLError) as exc:
        return CheckResult(
            name, False, "GET", url, None, f"request failed: {exc}"
        )

    shared_ok = not require_shared_store or session_policy_is_shared(
        result.body
    )
    passed = result.status_code == 200 and shared_ok
    detail = "session policy accepted token"
    if require_shared_store:
        detail = (
            "session policy accepted token and reports shared revocation store"
        )
    if result.status_code == 200 and not shared_ok:
        detail = "session policy does not report a shared revocation store"
    return CheckResult(
        name, passed, "GET", url, result.status_code, detail, result.body
    )


def check_logout(
    base_url: str, *, access_token: str, timeout: float
) -> CheckResult:
    """Check logout revokes the current token."""
    url = endpoint_url(base_url, "/api/auth/logout")
    try:
        result = request_json(
            url=url, method="POST", bearer_token=access_token, timeout=timeout
        )
    except (OSError, URLError) as exc:
        return CheckResult(
            "logout_revokes_token",
            False,
            "POST",
            url,
            None,
            f"request failed: {exc}",
        )

    passed = (
        result.status_code == 200
        and isinstance(result.body, dict)
        and result.body.get("revoked") is True
    )
    return CheckResult(
        "logout_revokes_token",
        passed,
        "POST",
        url,
        result.status_code,
        (
            "logout reported token revocation"
            if passed
            else "logout did not report token revocation"
        ),
        result.body,
    )


def check_revoked_token_rejected(
    *,
    name: str,
    base_url: str,
    access_token: str,
    timeout: float,
) -> CheckResult:
    """Check a revoked token is rejected."""
    url = endpoint_url(base_url, "/api/auth/session-policy")
    try:
        result = request_json(
            url=url, bearer_token=access_token, timeout=timeout
        )
    except (OSError, URLError) as exc:
        return CheckResult(
            name, False, "GET", url, None, f"request failed: {exc}"
        )

    passed = result.status_code == 401
    return CheckResult(
        name,
        passed,
        "GET",
        url,
        result.status_code,
        (
            "revoked token rejected"
            if passed
            else "revoked token was not rejected"
        ),
        result.body,
    )


def build_artifact(
    *,
    base_url: str,
    peer_base_urls: list[str],
    username_supplied: bool,
    checks: list[CheckResult],
    access_token: str | None,
    captured_at_utc: str,
) -> dict[str, Any]:
    """Build the evidence artifact."""
    passed = all(check.passed for check in checks)
    artifact: dict[str, Any] = {
        "schema_version": 1,
        "evidence_type": "target_health_auth_logs",
        "captured_at_utc": captured_at_utc,
        "target": {"base_url": normalize_base_url(base_url)},
        "peers": [
            {"base_url": normalize_base_url(peer)} for peer in peer_base_urls
        ],
        "credentials": {
            "configured_username_supplied": username_supplied,
            "password_recorded": False,
            "tokens_recorded": False,
        },
        "token_fingerprint_sha256": (
            token_fingerprint(access_token) if access_token else None
        ),
        "summary": {
            "passed": passed,
            "checks_passed": sum(1 for check in checks if check.passed),
            "checks_total": len(checks),
            "shared_revocation_checked": bool(peer_base_urls),
        },
        "checks": [check.as_dict() for check in checks],
    }
    return artifact


def run_probe(
    *,
    base_url: str,
    username: str,
    password: str,
    default_username: str,
    default_password: str,
    peer_base_urls: list[str],
    timeout: float,
    captured_at_utc: str,
) -> dict[str, Any]:
    """Run all target checks and return an evidence artifact."""
    normalized_peer_urls = [
        normalize_base_url(peer) for peer in peer_base_urls
    ]
    checks: list[CheckResult] = [
        check_health(base_url, timeout),
        check_default_login_rejected(
            base_url,
            username=default_username,
            password=default_password,
            timeout=timeout,
        ),
    ]

    login_check, access_token, _refresh_token = check_configured_login(
        base_url,
        username=username,
        password=password,
        timeout=timeout,
    )
    checks.append(login_check)

    if access_token:
        checks.append(
            check_session_policy(
                name="session_policy",
                base_url=base_url,
                access_token=access_token,
                timeout=timeout,
                require_shared_store=bool(normalized_peer_urls),
            )
        )
        for index, peer_base_url in enumerate(normalized_peer_urls, start=1):
            checks.append(
                check_session_policy(
                    name=f"peer_{index}_session_policy_before_logout",
                    base_url=peer_base_url,
                    access_token=access_token,
                    timeout=timeout,
                    require_shared_store=True,
                )
            )

        checks.append(
            check_logout(base_url, access_token=access_token, timeout=timeout)
        )
        checks.append(
            check_revoked_token_rejected(
                name="revoked_token_rejected",
                base_url=base_url,
                access_token=access_token,
                timeout=timeout,
            )
        )
        for index, peer_base_url in enumerate(normalized_peer_urls, start=1):
            checks.append(
                check_revoked_token_rejected(
                    name=f"peer_{index}_revoked_token_rejected_after_logout",
                    base_url=peer_base_url,
                    access_token=access_token,
                    timeout=timeout,
                )
            )
    else:
        no_access_token = (
            "skipped because configured login did not issue "
            "an access token"
        )
        checks.append(
            CheckResult(
                "session_policy",
                False,
                "GET",
                endpoint_url(base_url, "/api/auth/session-policy"),
                None,
                no_access_token,
            )
        )
        checks.append(
            CheckResult(
                "logout_revokes_token",
                False,
                "POST",
                endpoint_url(base_url, "/api/auth/logout"),
                None,
                no_access_token,
            )
        )
        checks.append(
            CheckResult(
                "revoked_token_rejected",
                False,
                "GET",
                endpoint_url(base_url, "/api/auth/session-policy"),
                None,
                no_access_token,
            )
        )

    return build_artifact(
        base_url=base_url,
        peer_base_urls=normalized_peer_urls,
        username_supplied=bool(username),
        checks=checks,
        access_token=access_token,
        captured_at_utc=captured_at_utc,
    )


def write_artifact(output_path: Path, artifact: dict[str, Any]) -> None:
    """Write the evidence artifact."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Probe a live target for Standard v3 health/auth evidence."
    )
    parser.add_argument(
        "--base-url", required=True, help="Base URL for the deployed target."
    )
    parser.add_argument(
        "--peer-base-url",
        action="append",
        default=[],
        help="Additional worker/container URL to test.",
    )
    parser.add_argument(
        "--username", default=os.getenv("THIRSTYS_TARGET_USERNAME")
    )
    parser.add_argument(
        "--password", default=os.getenv("THIRSTYS_TARGET_PASSWORD")
    )
    parser.add_argument("--default-username", default="admin")
    parser.add_argument("--default-password", default="admin")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS
    )
    parser.add_argument("--captured-at-utc", default=utc_now())
    args = parser.parse_args(argv)

    if not args.username:
        raise SystemExit("--username or THIRSTYS_TARGET_USERNAME is required")
    if not args.password:
        raise SystemExit("--password or THIRSTYS_TARGET_PASSWORD is required")

    artifact = run_probe(
        base_url=args.base_url,
        username=args.username,
        password=args.password,
        default_username=args.default_username,
        default_password=args.default_password,
        peer_base_urls=args.peer_base_url,
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
