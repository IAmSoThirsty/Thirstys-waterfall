"""Tests for structured target evidence probes."""

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


def _load_script(name: str):
    path = SCRIPTS / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


rollback = _load_script("probe_target_rollback_evidence")
rotation = _load_script("probe_secret_rotation_evidence")
platform_backend = _load_script("probe_platform_backend_evidence")
common = _load_script("target_evidence_common")


def _passing_command(args, timeout):
    return common.CommandResult(args, 0, "ok\n", "")


def test_target_rollback_probe_requires_execution_and_validation():
    artifact = rollback.run_probe(
        rollback_commands=[["deployctl", "rollback", "previous"]],
        validation_commands=[["deployctl", "status"]],
        base_url=None,
        timeout=1,
        captured_at_utc="2026-07-13T04:00:00Z",
        command_runner=_passing_command,
    )

    assert artifact["evidence_type"] == "target_rollback"
    assert artifact["summary"]["passed"] is True


def test_target_rollback_probe_waits_for_post_rollback_health(monkeypatch):
    health_results = iter([(None, "starting"), (200, "healthy")])

    monkeypatch.setattr(rollback.time, "sleep", lambda _seconds: None)

    artifact = rollback.run_probe(
        rollback_commands=[["deployctl", "rollback", "previous"]],
        validation_commands=[],
        base_url="http://target.local",
        timeout=1,
        captured_at_utc="2026-07-13T04:00:00Z",
        command_runner=_passing_command,
        health_client=lambda base_url, timeout: next(health_results),
    )

    assert artifact["summary"]["passed"] is True


def test_target_rollback_probe_fails_without_validation_signal():
    artifact = rollback.run_probe(
        rollback_commands=[["deployctl", "rollback", "previous"]],
        validation_commands=[],
        base_url=None,
        timeout=1,
        captured_at_utc="2026-07-13T04:00:00Z",
        command_runner=_passing_command,
    )

    assert artifact["summary"]["passed"] is False


def test_secret_rotation_probe_checks_old_and_new_credentials():
    def login_client(base_url, username, password, timeout):
        if password == "old":
            return 401, {"msg": "bad credentials"}
        return 200, {"access_token": "secret-token"}

    artifact = rotation.run_probe(
        base_url="https://prod.example",
        username="operator",
        old_password="old",
        new_password="new",
        rotation_commands=[["deployctl", "rotate-secrets"]],
        require_pre_rotation_old_login=False,
        timeout=1,
        captured_at_utc="2026-07-13T04:00:00Z",
        command_runner=_passing_command,
        login_client=login_client,
    )
    new_check = next(
        check
        for check in artifact["checks"]
        if check["name"] == "new_credentials_accepted"
    )

    assert artifact["evidence_type"] == "secret_rotation"
    assert artifact["summary"]["passed"] is True
    assert json.dumps(new_check).find("secret-token") == -1


def test_secret_rotation_probe_fails_when_old_credentials_still_work():
    def login_client(base_url, username, password, timeout):
        return 200, {"access_token": "token"}

    artifact = rotation.run_probe(
        base_url="https://prod.example",
        username="operator",
        old_password="old",
        new_password="new",
        rotation_commands=[],
        require_pre_rotation_old_login=False,
        timeout=1,
        captured_at_utc="2026-07-13T04:00:00Z",
        login_client=login_client,
    )

    assert artifact["summary"]["passed"] is False


def test_secret_rotation_probe_can_require_old_login_before_rotation():
    calls = []

    def login_client(base_url, username, password, timeout):
        calls.append(password)
        if len(calls) == 1 and password == "old":
            return 200, {"access_token": "old-token"}
        if password == "old":
            return 401, {"msg": "bad credentials"}
        return 200, {"access_token": "new-token"}

    artifact = rotation.run_probe(
        base_url="https://prod.example",
        username="operator",
        old_password="old",
        new_password="new",
        rotation_commands=[["deployctl", "rotate-secrets"]],
        require_pre_rotation_old_login=True,
        timeout=1,
        captured_at_utc="2026-07-13T04:00:00Z",
        command_runner=_passing_command,
        login_client=login_client,
    )
    pre_check = next(
        check
        for check in artifact["checks"]
        if check["name"] == "old_credentials_accepted_before_rotation"
    )

    assert artifact["summary"]["passed"] is True
    assert pre_check["passed"] is True
    assert calls == ["old", "old", "new"]


def test_secret_rotation_probe_fails_when_required_pre_rotation_login_fails():
    def login_client(base_url, username, password, timeout):
        if password == "new":
            return 200, {"access_token": "new-token"}
        return 401, {"msg": "bad credentials"}

    artifact = rotation.run_probe(
        base_url="https://prod.example",
        username="operator",
        old_password="old",
        new_password="new",
        rotation_commands=[["deployctl", "rotate-secrets"]],
        require_pre_rotation_old_login=True,
        timeout=1,
        captured_at_utc="2026-07-13T04:00:00Z",
        command_runner=_passing_command,
        login_client=login_client,
    )

    assert artifact["summary"]["passed"] is False


def test_platform_backend_probe_captures_apply_and_rollback():
    artifact = platform_backend.run_probe(
        backend="windows-firewall",
        apply_commands=[["netsh", "advfirewall", "set", "allprofiles"]],
        rollback_commands=[["netsh", "advfirewall", "reset"]],
        verify_commands=[["netsh", "advfirewall", "show", "allprofiles"]],
        narrowed_claim_file=None,
        captured_at_utc="2026-07-13T04:00:00Z",
        command_runner=_passing_command,
    )

    assert artifact["evidence_type"] == "platform_backend_execution"
    assert artifact["summary"]["passed"] is True


def test_platform_backend_probe_accepts_narrowed_claim_file(tmp_path):
    claim = tmp_path / "claim.md"
    claim.write_text(
        "Production scope excludes VPN backend.\n", encoding="utf-8"
    )

    artifact = platform_backend.run_probe(
        backend="vpn",
        apply_commands=[],
        rollback_commands=[],
        verify_commands=[],
        narrowed_claim_file=claim,
        captured_at_utc="2026-07-13T04:00:00Z",
    )

    assert artifact["summary"]["passed"] is True
