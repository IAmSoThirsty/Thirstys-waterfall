"""Tests for live target health/auth evidence probing."""

import importlib.util
import json
import sys
from pathlib import Path
from urllib.error import HTTPError

ROOT = Path(__file__).resolve().parents[1]
PROBE_SCRIPT = ROOT / "scripts" / "probe_target_auth_evidence.py"

PROBE_SPEC = importlib.util.spec_from_file_location(
    "probe_target_auth_evidence", PROBE_SCRIPT
)
probe = importlib.util.module_from_spec(PROBE_SPEC)
assert PROBE_SPEC.loader is not None
sys.modules[PROBE_SPEC.name] = probe
PROBE_SPEC.loader.exec_module(probe)


class FakeResponse:
    def __init__(self, status: int, body: dict):
        self.status = status
        self._body = json.dumps(body).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def getcode(self):
        return self.status

    def read(self):
        return self._body


def _http_error(url: str, status: int, body: dict) -> HTTPError:
    response = FakeResponse(status, body)
    return HTTPError(url, status, "error", {}, response)


def test_probe_writes_passing_auth_and_shared_revocation_artifact(
    tmp_path, monkeypatch
):
    output = tmp_path / "target-health-auth.json"
    state = {"logged_out": False}

    def fake_urlopen(request, timeout):
        url = request.full_url
        method = request.get_method()
        body = json.loads(request.data.decode("utf-8")) if request.data else {}

        if url.endswith("/health") and method == "GET":
            return FakeResponse(200, {"status": "healthy"})

        if url.endswith("/api/auth/login") and method == "POST":
            if body == {
                "username": "operator",
                "password": "correct-password",
            }:
                return FakeResponse(
                    200,
                    {
                        "access_token": "access-token-secret",
                        "refresh_token": "refresh-token-secret",
                        "session_policy": {
                            "token_revocation_enabled": True,
                            "revocation_store_shared": True,
                        },
                    },
                )
            raise _http_error(url, 401, {"error": "Invalid credentials"})

        if url.endswith("/api/auth/session-policy") and method == "GET":
            if state["logged_out"]:
                raise _http_error(
                    url, 401, {"error": "Token has been revoked"}
                )
            return FakeResponse(
                200,
                {
                    "session_policy": {
                        "token_revocation_enabled": True,
                        "revocation_store_shared": True,
                    }
                },
            )

        if url.endswith("/api/auth/logout") and method == "POST":
            state["logged_out"] = True
            return FakeResponse(
                200,
                {
                    "revoked": True,
                    "session_policy": {
                        "token_revocation_enabled": True,
                        "revocation_store_shared": True,
                    },
                },
            )

        raise AssertionError(f"unexpected request: {method} {url}")

    monkeypatch.setattr(probe, "urlopen", fake_urlopen)

    exit_code = probe.main(
        [
            "--base-url",
            "https://target.example",
            "--peer-base-url",
            "https://target-worker-2.example",
            "--username",
            "operator",
            "--password",
            "correct-password",
            "--output",
            str(output),
            "--captured-at-utc",
            "2026-07-13T02:30:00Z",
        ]
    )
    artifact_text = output.read_text(encoding="utf-8")
    artifact = json.loads(artifact_text)

    assert exit_code == 0
    assert artifact["summary"]["passed"] is True
    assert artifact["summary"]["shared_revocation_checked"] is True
    assert {check["name"] for check in artifact["checks"]} >= {
        "health",
        "default_login_rejected",
        "configured_login",
        "session_policy",
        "peer_1_session_policy_before_logout",
        "logout_revokes_token",
        "revoked_token_rejected",
        "peer_1_revoked_token_rejected_after_logout",
    }
    assert "correct-password" not in artifact_text
    assert "access-token-secret" not in artifact_text
    assert "refresh-token-secret" not in artifact_text
    assert artifact["token_fingerprint_sha256"] == probe.token_fingerprint(
        "access-token-secret"
    )


def test_probe_fails_when_default_credentials_are_accepted(
    tmp_path, monkeypatch
):
    output = tmp_path / "target-health-auth.json"
    state = {"logged_out": False}

    def fake_urlopen(request, timeout):
        url = request.full_url
        method = request.get_method()
        if url.endswith("/health") and method == "GET":
            return FakeResponse(200, {"status": "healthy"})
        if url.endswith("/api/auth/login") and method == "POST":
            return FakeResponse(
                200,
                {
                    "access_token": "issued-token",
                    "refresh_token": "issued-refresh-token",
                },
            )
        if url.endswith("/api/auth/session-policy") and method == "GET":
            if state["logged_out"]:
                raise _http_error(
                    url, 401, {"error": "Token has been revoked"}
                )
            return FakeResponse(
                200,
                {
                    "session_policy": {
                        "token_revocation_enabled": True,
                        "revocation_store_shared": False,
                    }
                },
            )
        if url.endswith("/api/auth/logout") and method == "POST":
            state["logged_out"] = True
            return FakeResponse(200, {"revoked": True})
        raise AssertionError(f"unexpected request: {method} {url}")

    monkeypatch.setattr(probe, "urlopen", fake_urlopen)

    exit_code = probe.main(
        [
            "--base-url",
            "https://target.example",
            "--username",
            "operator",
            "--password",
            "correct-password",
            "--output",
            str(output),
        ]
    )
    artifact = json.loads(output.read_text(encoding="utf-8"))

    assert exit_code == 1
    default_check = next(
        check
        for check in artifact["checks"]
        if check["name"] == "default_login_rejected"
    )
    assert default_check["passed"] is False
    assert artifact["summary"]["passed"] is False
