"""Tests for published image pull/run target evidence probing."""

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROBE_SCRIPT = ROOT / "scripts" / "probe_target_image_evidence.py"

PROBE_SPEC = importlib.util.spec_from_file_location(
    "probe_target_image_evidence", PROBE_SCRIPT
)
probe = importlib.util.module_from_spec(PROBE_SPEC)
assert PROBE_SPEC.loader is not None
sys.modules[PROBE_SPEC.name] = probe
PROBE_SPEC.loader.exec_module(probe)


def _command_runner(args, timeout):
    if args[:2] == ["docker", "--version"]:
        return probe.CommandResult(args, 0, "Docker version 27.0.0\n", "")
    if args[:2] == ["docker", "pull"]:
        return probe.CommandResult(args, 0, "pulled\n", "")
    if args[:3] == ["docker", "image", "inspect"]:
        return probe.CommandResult(
            args,
            0,
            json.dumps(
                {"RepoDigests": ["ghcr.io/test/app@sha256:" + ("a" * 64)]}
            ),
            "",
        )
    if args[:3] == ["docker", "rm", "-f"]:
        return probe.CommandResult(args, 0, "removed\n", "")
    if args[:2] == ["docker", "run"]:
        return probe.CommandResult(args, 0, "container-id\n", "")
    if args[:2] == ["docker", "logs"]:
        return probe.CommandResult(args, 0, "startup complete\n", "")
    raise AssertionError(f"unexpected command: {args}")


def _http_client(
    url, method="GET", payload=None, bearer_token=None, timeout=10
):
    if url.endswith("/health"):
        return 200, {"status": "healthy"}
    if url.endswith("/api/auth/login") and payload == {
        "username": "admin",
        "password": "admin",
    }:
        return 401, {"error": "Invalid credentials"}
    if url.endswith("/api/auth/login"):
        return 200, {
            "access_token": "secret-access-token",
            "refresh_token": "secret-refresh-token",
        }
    if url.endswith("/api/auth/session-policy"):
        return 200, {"session_policy": {"token_revocation_enabled": True}}
    raise AssertionError(f"unexpected request: {method} {url}")


def test_published_image_probe_writes_redacted_passing_artifact(tmp_path):
    output = tmp_path / "published-image-pull-run.json"
    artifact = probe.run_probe(
        engine="docker",
        image="ghcr.io/test/app:1.2.3",
        image_digest="sha256:" + ("a" * 64),
        container_name="tw-evidence",
        port=18082,
        admin_username="operator",
        admin_password="correct-password",
        admin_password_hash="hash-secret",
        cors_origins="http://127.0.0.1:18082",
        secret_key="secret-key",
        jwt_secret_key="jwt-secret-key",
        thirsty_lang_path=None,
        timeout=1,
        captured_at_utc="2026-07-13T03:00:00Z",
        command_runner=_command_runner,
        http_client=_http_client,
    )
    probe.write_artifact(output, artifact)
    artifact_text = output.read_text(encoding="utf-8")

    assert artifact["summary"]["passed"] is True
    assert artifact["evidence_type"] == "published_image_pull_run"
    assert "correct-password" not in artifact_text
    assert "hash-secret" not in artifact_text
    assert "secret-access-token" not in artifact_text
    assert "secret-refresh-token" not in artifact_text
    assert "secret-key" not in artifact_text
    assert "jwt-secret-key" not in artifact_text
    assert "THIRSTYS_ADMIN_PASSWORD_HASH=<redacted>" in artifact_text


def test_published_image_probe_retries_until_health_is_ready(monkeypatch):
    responses = iter(
        [
            (0, {"error": "not ready"}),
            (0, {"error": "still not ready"}),
            (200, {"status": "healthy"}),
        ]
    )

    def delayed_http_client(
        url, method="GET", payload=None, bearer_token=None, timeout=10
    ):
        if url.endswith("/health"):
            return next(responses)
        return _http_client(
            url,
            method=method,
            payload=payload,
            bearer_token=bearer_token,
            timeout=timeout,
        )

    monkeypatch.setattr(probe.time, "sleep", lambda _seconds: None)

    artifact = probe.run_probe(
        engine="docker",
        image="ghcr.io/test/app:1.2.3",
        image_digest="sha256:" + ("a" * 64),
        container_name="tw-evidence",
        port=18082,
        admin_username="operator",
        admin_password="correct-password",
        admin_password_hash="hash-secret",
        cors_origins="http://127.0.0.1:18082",
        secret_key="secret-key",
        jwt_secret_key="jwt-secret-key",
        thirsty_lang_path=None,
        timeout=1,
        captured_at_utc="2026-07-13T03:00:00Z",
        command_runner=_command_runner,
        http_client=delayed_http_client,
    )
    health_check = next(
        check for check in artifact["checks"] if check["name"] == "health"
    )

    assert artifact["summary"]["passed"] is True
    assert health_check["passed"] is True


def test_published_image_probe_fails_when_digest_is_absent():
    def command_runner(args, timeout):
        if args[:2] == ["docker", "--version"]:
            return probe.CommandResult(args, 0, "Docker version 27.0.0\n", "")
        if args[:2] == ["docker", "pull"]:
            return probe.CommandResult(args, 0, "pulled\n", "")
        if args[:3] == ["docker", "image", "inspect"]:
            return probe.CommandResult(
                args,
                0,
                json.dumps(
                    {"RepoDigests": ["ghcr.io/test/app@sha256:" + ("b" * 64)]}
                ),
                "",
            )
        if args[:3] == ["docker", "rm", "-f"]:
            return probe.CommandResult(args, 0, "removed\n", "")
        if args[:2] == ["docker", "run"]:
            return probe.CommandResult(args, 0, "container-id\n", "")
        if args[:2] == ["docker", "logs"]:
            return probe.CommandResult(args, 0, "startup complete\n", "")
        raise AssertionError(f"unexpected command: {args}")

    artifact = probe.run_probe(
        engine="docker",
        image="ghcr.io/test/app:1.2.3",
        image_digest="sha256:" + ("a" * 64),
        container_name="tw-evidence",
        port=18082,
        admin_username="operator",
        admin_password="correct-password",
        admin_password_hash="hash-secret",
        cors_origins="http://127.0.0.1:18082",
        secret_key="secret-key",
        jwt_secret_key="jwt-secret-key",
        thirsty_lang_path=None,
        timeout=1,
        captured_at_utc="2026-07-13T03:00:00Z",
        command_runner=command_runner,
        http_client=_http_client,
    )
    digest_check = next(
        check
        for check in artifact["checks"]
        if check["name"] == "image_digest_present"
    )

    assert artifact["summary"]["passed"] is False
    assert digest_check["passed"] is False
