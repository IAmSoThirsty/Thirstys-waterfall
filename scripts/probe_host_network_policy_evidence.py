#!/usr/bin/env python3
"""Capture target host network policy evidence for Standard v3."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import socket
import ssl
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

DEFAULT_TIMEOUT_SECONDS = 10.0


@dataclass(frozen=True)
class CommandResult:
    """Captured host command result."""

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
            "stdout": limit_text(self.stdout),
            "stderr": limit_text(self.stderr),
        }


@dataclass(frozen=True)
class CheckResult:
    """One network-policy check."""

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


def utc_now() -> str:
    """Return current UTC timestamp in ISO format."""
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def limit_text(value: str, limit: int = 5000) -> str:
    """Keep captured output bounded."""
    if len(value) <= limit:
        return value
    return value[:limit] + "\n<truncated>"


def run_command(args: list[str], timeout: int = 30) -> CommandResult:
    """Run a host command and capture output."""
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
    except (OSError, subprocess.TimeoutExpired) as exc:
        return CommandResult(
            args=args, returncode=1, stdout="", stderr=str(exc)
        )


def platform_commands(system_name: str) -> dict[str, list[list[str]]]:
    """Return network and firewall commands for the current platform."""
    lowered = system_name.lower()
    if lowered == "windows":
        return {
            "listening_ports": [["netstat", "-ano", "-p", "tcp"]],
            "firewall_policy": [
                ["netsh", "advfirewall", "show", "allprofiles"],
                [
                    "netsh",
                    "advfirewall",
                    "firewall",
                    "show",
                    "rule",
                    "name=all",
                ],
            ],
        }
    if lowered == "darwin":
        return {
            "listening_ports": [["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"]],
            "firewall_policy": [["pfctl", "-sr"]],
        }
    return {
        "listening_ports": [
            ["ss", "-ltnp"],
            ["netstat", "-ltnp"],
        ],
        "firewall_policy": [
            ["nft", "list", "ruleset"],
            ["ufw", "status", "verbose"],
            ["iptables", "-S"],
        ],
    }


def request_preflight(
    *,
    base_url: str,
    origin: str,
    timeout: float,
) -> tuple[int, dict[str, str], str]:
    """Send an unauthenticated CORS preflight request."""
    url = base_url.rstrip("/") + "/api/auth/login"
    request = Request(
        url,
        method="OPTIONS",
        headers={
            "Origin": origin,
            "Access-Control-Request-Method": "POST",
            "Accept": "application/json",
        },
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            return (
                getattr(response, "status", response.getcode()),
                dict(response.headers.items()),
                response.read().decode("utf-8", errors="replace")[:1000],
            )
    except HTTPError as exc:
        return (
            exc.code,
            dict(exc.headers.items()),
            exc.read().decode("utf-8", errors="replace")[:1000],
        )


def capture_tls(
    *,
    host: str,
    port: int,
    timeout: float,
) -> dict[str, Any]:
    """Capture verified TLS certificate and cipher evidence."""
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    with socket.create_connection((host, port), timeout=timeout) as raw_socket:
        with context.wrap_socket(
            raw_socket, server_hostname=host
        ) as tls_socket:
            cert = tls_socket.getpeercert()
            return {
                "version": tls_socket.version(),
                "cipher": tls_socket.cipher(),
                "subject": cert.get("subject"),
                "issuer": cert.get("issuer"),
                "notBefore": cert.get("notBefore"),
                "notAfter": cert.get("notAfter"),
                "subjectAltName": cert.get("subjectAltName"),
            }


def parse_base_url(base_url: str) -> tuple[str, int, str]:
    """Parse base URL and return host, port, scheme."""
    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("base URL must start with http:// or https://")
    if not parsed.hostname:
        raise ValueError("base URL must include a hostname")
    default_port = 443 if parsed.scheme == "https" else 80
    return parsed.hostname, parsed.port or default_port, parsed.scheme


def output_contains_ports(output: str, expected_ports: list[int]) -> bool:
    """Return whether command output includes all expected ports."""
    return all(
        f":{port}" in output or f".{port}" in output or f" {port} " in output
        for port in expected_ports
    )


def run_command_group(
    *,
    group_name: str,
    commands: list[list[str]],
    command_runner: Callable[[list[str], int], CommandResult],
) -> list[CommandResult]:
    """Run a group of host evidence commands."""
    del group_name
    return [command_runner(command, 45) for command in commands]


def run_probe(
    *,
    base_url: str,
    expected_origin: str,
    expected_ports: list[int],
    allow_http: bool,
    timeout: float,
    captured_at_utc: str,
    system_name: str | None = None,
    command_runner: Callable[[list[str], int], CommandResult] = run_command,
    preflight_client: Callable[
        ..., tuple[int, dict[str, str], str]
    ] = request_preflight,
    tls_client: Callable[..., dict[str, Any]] = capture_tls,
) -> dict[str, Any]:
    """Capture host network policy evidence."""
    host, port, scheme = parse_base_url(base_url)
    if port not in expected_ports:
        expected_ports = [*expected_ports, port]

    checks: list[CheckResult] = []
    evidence_system = system_name or platform.system()
    command_sets = platform_commands(evidence_system)
    listening_results = run_command_group(
        group_name="listening_ports",
        commands=command_sets["listening_ports"],
        command_runner=command_runner,
    )
    firewall_results = run_command_group(
        group_name="firewall_policy",
        commands=command_sets["firewall_policy"],
        command_runner=command_runner,
    )
    listening_output = "\n".join(
        result.stdout + "\n" + result.stderr for result in listening_results
    )
    firewall_output = "\n".join(
        result.stdout + "\n" + result.stderr for result in firewall_results
    )

    checks.append(
        CheckResult(
            "listening_ports_captured",
            any(
                result.passed and result.stdout for result in listening_results
            ),
            "captured listening port command output",
            [result.as_dict() for result in listening_results],
        )
    )
    checks.append(
        CheckResult(
            "expected_ports_visible",
            output_contains_ports(listening_output, expected_ports),
            f"expected ports visible: {expected_ports}",
        )
    )
    checks.append(
        CheckResult(
            "firewall_policy_captured",
            any(
                result.passed and result.stdout for result in firewall_results
            ),
            "captured host firewall policy command output",
            [result.as_dict() for result in firewall_results],
        )
    )

    if scheme != "https" and not allow_http:
        checks.append(
            CheckResult(
                "tls_required",
                False,
                "production network evidence requires HTTPS unless "
                "--allow-http is set",
            )
        )
    elif scheme == "https":
        try:
            tls_data = tls_client(host=host, port=port, timeout=timeout)
            checks.append(
                CheckResult(
                    "tls_certificate_captured",
                    True,
                    "captured verified TLS certificate evidence",
                    tls_data,
                )
            )
        except (OSError, ssl.SSLError) as exc:
            checks.append(
                CheckResult(
                    "tls_certificate_captured",
                    False,
                    f"TLS capture failed: {exc}",
                )
            )
        except Exception as exc:  # noqa: BLE001 - evidence capture failure
            checks.append(
                CheckResult(
                    "tls_certificate_captured",
                    False,
                    f"TLS capture failed: {exc}",
                )
            )
    else:
        checks.append(
            CheckResult(
                "tls_certificate_captured",
                True,
                "HTTP explicitly allowed for this capture",
            )
        )

    try:
        status, headers, body = preflight_client(
            base_url=base_url, origin=expected_origin, timeout=timeout
        )
        allow_origin = headers.get("Access-Control-Allow-Origin", "")
        checks.append(
            CheckResult(
                "cors_origin_enforced",
                status in {200, 204}
                and allow_origin == expected_origin
                and allow_origin != "*",
                f"CORS preflight returned {status}",
                {
                    "headers": headers,
                    "body": body,
                    "expected_origin": expected_origin,
                },
            )
        )
    except (OSError, URLError) as exc:
        checks.append(
            CheckResult(
                "cors_origin_enforced",
                False,
                f"CORS preflight failed: {exc}",
            )
        )

    passed = all(check.passed for check in checks)
    return {
        "schema_version": 1,
        "evidence_type": "host_network_policy",
        "captured_at_utc": captured_at_utc,
        "target": {
            "base_url": base_url,
            "host": host,
            "port": port,
            "scheme": scheme,
            "expected_ports": expected_ports,
            "expected_origin": expected_origin,
        },
        "host": {
            "evidence_system": evidence_system,
            "platform": platform.platform(),
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
        "summary": {
            "passed": passed,
            "checks_passed": sum(1 for check in checks if check.passed),
            "checks_total": len(checks),
        },
        "checks": [check.as_dict() for check in checks],
        "captured_outputs": {
            "listening_ports": [
                result.as_dict() for result in listening_results
            ],
            "firewall_policy": [
                result.as_dict() for result in firewall_results
            ],
        },
        "captured_output_hashes": {
            "listening_ports_sha256": hashlib.sha256(
                listening_output.encode("utf-8")
            ).hexdigest(),
            "firewall_policy_sha256": hashlib.sha256(
                firewall_output.encode("utf-8")
            ).hexdigest(),
        },
    }


def write_artifact(output_path: Path, artifact: dict[str, Any]) -> None:
    """Write the evidence artifact."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(artifact, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def parse_port(value: str) -> int:
    """Parse a TCP port argument."""
    port = int(value)
    if port < 1 or port > 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Capture target host network policy evidence."
    )
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--expected-origin", required=True)
    parser.add_argument(
        "--expected-public-port",
        action="append",
        type=parse_port,
        default=[],
    )
    parser.add_argument("--allow-http", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS
    )
    parser.add_argument("--captured-at-utc", default=utc_now())
    args = parser.parse_args(argv)

    artifact = run_probe(
        base_url=args.base_url,
        expected_origin=args.expected_origin,
        expected_ports=args.expected_public_port,
        allow_http=args.allow_http,
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
