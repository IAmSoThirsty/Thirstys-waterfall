"""Tests for target evidence wiring in the production verifier."""

import hashlib
import importlib.util
import json
import sys
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "verify_production_deployment.py"
TARGET_SCRIPT = (
    Path(__file__).resolve().parents[1] / "scripts" / "verify_target_deployment_evidence.py"
)
SPEC = importlib.util.spec_from_file_location("verify_production_deployment", SCRIPT)
production_verifier = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = production_verifier
SPEC.loader.exec_module(production_verifier)

TARGET_SPEC = importlib.util.spec_from_file_location(
    "verify_target_deployment_evidence_for_production_test", TARGET_SCRIPT
)
target_evidence = importlib.util.module_from_spec(TARGET_SPEC)
assert TARGET_SPEC.loader is not None
sys.modules[TARGET_SPEC.name] = target_evidence
TARGET_SPEC.loader.exec_module(target_evidence)


def _write_artifact(root: Path, name: str) -> dict[str, str]:
    path = root / name
    path.write_text(f"{name}\n", encoding="utf-8")
    return {
        "artifact": name,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def _valid_manifest(root: Path) -> Path:
    evidence = []
    for evidence_type in target_evidence.REQUIRED_EVIDENCE_TYPES:
        evidence.append(
            {
                "type": evidence_type,
                "status": "passed",
                "summary": f"{evidence_type} evidence captured",
                "captured_at_utc": "2026-07-12T17:30:00Z",
                **_write_artifact(root, f"{evidence_type}.log"),
            }
        )

    manifest_path = root / "target-evidence.json"
    manifest_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "deployment": {
                    "environment": "production",
                    "target_host": "prod-host-1",
                    "image": "ghcr.io/iamsothirsty/thirstys-waterfall:1.0.2",
                    "image_digest": "sha256:" + "a" * 64,
                    "captured_at_utc": "2026-07-12T17:30:00Z",
                },
                "evidence": evidence,
            }
        ),
        encoding="utf-8",
    )
    return manifest_path


def _stub_expensive_verifier_steps(monkeypatch, calls):
    monkeypatch.setattr(production_verifier, "scan_retired_identifiers", lambda paths: None)
    monkeypatch.setattr(production_verifier, "scan_claim_markers", lambda paths: None)
    monkeypatch.setattr(production_verifier, "smoke_local_web", lambda thirsty_lang_path: None)
    monkeypatch.setattr(production_verifier, "smoke_docker", lambda image, thirsty_lang_path: None)
    monkeypatch.setattr(
        production_verifier,
        "smoke_docker_rollback",
        lambda image, thirsty_lang_path: None,
    )
    monkeypatch.setattr(
        production_verifier,
        "run",
        lambda cmd, **kwargs: calls.append(cmd) or "",
    )


def test_main_validates_target_evidence_manifest_when_supplied(tmp_path, monkeypatch):
    calls = []
    manifest_path = _valid_manifest(tmp_path)
    _stub_expensive_verifier_steps(monkeypatch, calls)

    exit_code = production_verifier.main(
        [
            "--skip-tests",
            "--skip-docker",
            "--target-evidence-manifest",
            str(manifest_path),
        ]
    )

    assert exit_code == 0
    assert [
        sys.executable,
        "scripts/verify_target_deployment_evidence.py",
        str(manifest_path),
    ] in calls


def test_require_target_evidence_fails_without_manifest(monkeypatch):
    monkeypatch.setattr(
        production_verifier,
        "run",
        lambda cmd, **kwargs: (_ for _ in ()).throw(AssertionError("run should not be called")),
    )

    try:
        production_verifier.main(["--skip-tests", "--skip-docker", "--require-target-evidence"])
    except SystemExit as exc:
        assert "target deployment evidence is required" in str(exc)
    else:
        raise AssertionError("missing target evidence did not fail closed")
