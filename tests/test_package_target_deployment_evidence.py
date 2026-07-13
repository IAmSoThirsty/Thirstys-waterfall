"""Tests for target evidence package creation."""

import hashlib
import importlib.util
import json
import sys
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

SCRIPT = SCRIPTS / "package_target_deployment_evidence.py"
VALIDATOR_SCRIPT = SCRIPTS / "verify_target_deployment_evidence.py"

PACKAGE_SPEC = importlib.util.spec_from_file_location(
    "package_target_deployment_evidence", SCRIPT
)
packager = importlib.util.module_from_spec(PACKAGE_SPEC)
assert PACKAGE_SPEC.loader is not None
sys.modules[PACKAGE_SPEC.name] = packager
PACKAGE_SPEC.loader.exec_module(packager)

VALIDATOR_SPEC = importlib.util.spec_from_file_location(
    "verify_target_deployment_evidence_for_package_test", VALIDATOR_SCRIPT
)
validator = importlib.util.module_from_spec(VALIDATOR_SPEC)
assert VALIDATOR_SPEC.loader is not None
sys.modules[VALIDATOR_SPEC.name] = validator
VALIDATOR_SPEC.loader.exec_module(validator)


def _write_artifact(root: Path, name: str, content: str) -> dict[str, str]:
    path = root / name
    path.write_text(content, encoding="utf-8")
    return {
        "artifact": name,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def _valid_manifest(root: Path) -> Path:
    evidence = []
    for evidence_type in validator.REQUIRED_EVIDENCE_TYPES:
        evidence.append(
            {
                "type": evidence_type,
                "status": "passed",
                "summary": f"{evidence_type} evidence captured",
                "captured_at_utc": "2026-07-12T17:30:00Z",
                **_write_artifact(root, f"{evidence_type}.log", f"{evidence_type}\n"),
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
                    "image": "ghcr.io/iamsothirsty/thirstys-waterfall:1.0.3",
                    "image_digest": "sha256:" + "a" * 64,
                    "captured_at_utc": "2026-07-12T17:30:00Z",
                },
                "evidence": evidence,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return manifest_path


def test_package_valid_bundle_copies_manifest_artifacts_and_zip(tmp_path):
    source = tmp_path / "source"
    output = tmp_path / "packages"
    source.mkdir()
    manifest_path = _valid_manifest(source)

    report = packager.copy_bundle(
        manifest_path=manifest_path,
        output_dir=output,
        package_zip=True,
        package_name="prod-evidence",
    )
    package_dir = output / "prod-evidence"
    package_manifest = json.loads(
        (package_dir / "package-manifest.json").read_text(encoding="utf-8")
    )

    assert report["status"] == "passed"
    assert report["artifact_count"] == len(validator.REQUIRED_EVIDENCE_TYPES)
    assert (package_dir / "target-evidence.json").is_file()
    assert (package_dir / "target_rollback.log").is_file()
    assert package_manifest["copied_artifacts"][0]["sha256"]
    assert (output / "prod-evidence.zip").is_file()
    with zipfile.ZipFile(output / "prod-evidence.zip") as archive:
        assert "prod-evidence/package-manifest.json" in archive.namelist()


def test_package_rejects_invalid_bundle(tmp_path):
    source = tmp_path / "source"
    output = tmp_path / "packages"
    source.mkdir()
    manifest_path = _valid_manifest(source)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["evidence"][0]["sha256"] = "0" * 64
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    try:
        packager.copy_bundle(
            manifest_path=manifest_path,
            output_dir=output,
            package_zip=False,
            package_name=None,
        )
    except SystemExit as exc:
        assert "target evidence bundle is invalid" in str(exc)
    else:
        raise AssertionError("invalid evidence bundle was packaged")


def test_package_refuses_to_replace_existing_output_without_overwrite(tmp_path):
    source = tmp_path / "source"
    output = tmp_path / "packages"
    source.mkdir()
    manifest_path = _valid_manifest(source)

    packager.copy_bundle(
        manifest_path=manifest_path,
        output_dir=output,
        package_zip=True,
        package_name="prod-evidence",
    )

    try:
        packager.copy_bundle(
            manifest_path=manifest_path,
            output_dir=output,
            package_zip=True,
            package_name="prod-evidence",
        )
    except SystemExit as exc:
        assert "pass --overwrite to replace it" in str(exc)
    else:
        raise AssertionError("existing evidence package was overwritten")

    report = packager.copy_bundle(
        manifest_path=manifest_path,
        output_dir=output,
        package_zip=True,
        package_name="prod-evidence",
        overwrite=True,
    )
    assert report["status"] == "passed"


def test_package_rejects_path_traversing_package_name(tmp_path):
    source = tmp_path / "source"
    output = tmp_path / "packages"
    source.mkdir()
    manifest_path = _valid_manifest(source)

    try:
        packager.copy_bundle(
            manifest_path=manifest_path,
            output_dir=output,
            package_zip=False,
            package_name="../outside",
        )
    except SystemExit as exc:
        assert "package name must be a single directory name" in str(exc)
    else:
        raise AssertionError("unsafe package name was accepted")


def test_package_refuses_existing_zip_before_copying_bundle(tmp_path):
    source = tmp_path / "source"
    output = tmp_path / "packages"
    source.mkdir()
    output.mkdir()
    manifest_path = _valid_manifest(source)
    (output / "prod-evidence.zip").write_text("existing archive", encoding="utf-8")

    try:
        packager.copy_bundle(
            manifest_path=manifest_path,
            output_dir=output,
            package_zip=True,
            package_name="prod-evidence",
        )
    except SystemExit as exc:
        assert "package archive already exists" in str(exc)
    else:
        raise AssertionError("existing archive was overwritten")

    assert not (output / "prod-evidence").exists()
