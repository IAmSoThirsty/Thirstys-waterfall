"""Tests for target deployment evidence validation."""

import hashlib
import importlib.util
import json
import sys
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "verify_target_deployment_evidence.py"
SPEC = importlib.util.spec_from_file_location("verify_target_deployment_evidence", SCRIPT)
target_evidence = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = target_evidence
SPEC.loader.exec_module(target_evidence)


def _write_artifact(root: Path, name: str, content: str) -> dict[str, str]:
    path = root / name
    path.write_text(content, encoding="utf-8")
    return {
        "artifact": name,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def _valid_manifest(root: Path) -> Path:
    evidence = []
    for evidence_type in target_evidence.REQUIRED_EVIDENCE_TYPES:
        artifact = _write_artifact(root, f"{evidence_type}.log", f"{evidence_type}\n")
        evidence.append(
            {
                "type": evidence_type,
                "status": "passed",
                "summary": f"{evidence_type} evidence captured",
                "captured_at_utc": "2026-07-12T17:30:00Z",
                **artifact,
            }
        )

    manifest = {
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
    manifest_path = root / "target-evidence.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest_path


def test_valid_target_evidence_manifest_passes(tmp_path):
    manifest_path = _valid_manifest(tmp_path)

    issues = target_evidence.validate_manifest(manifest_path)

    assert issues == []


def test_missing_required_evidence_type_fails(tmp_path):
    manifest_path = _valid_manifest(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["evidence"] = [
        entry for entry in manifest["evidence"] if entry["type"] != "target_rollback"
    ]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    issues = target_evidence.validate_manifest(manifest_path)

    assert any("missing required type: target_rollback" in issue.message for issue in issues)


def test_artifact_must_stay_inside_evidence_folder(tmp_path):
    manifest_path = _valid_manifest(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["evidence"][0]["artifact"] = "../outside.log"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    issues = target_evidence.validate_manifest(manifest_path)

    assert any("inside the evidence folder" in issue.message for issue in issues)


def test_artifact_sha_mismatch_fails(tmp_path):
    manifest_path = _valid_manifest(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["evidence"][0]["sha256"] = "0" * 64
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    issues = target_evidence.validate_manifest(manifest_path)

    assert any("does not match artifact content" in issue.message for issue in issues)


def test_main_returns_nonzero_for_invalid_manifest(tmp_path, capsys):
    manifest_path = tmp_path / "bad.json"
    manifest_path.write_text("{}", encoding="utf-8")

    exit_code = target_evidence.main([str(manifest_path)])
    output = capsys.readouterr().out

    assert exit_code == 1
    assert "validation failed" in output
