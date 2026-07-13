"""Tests for target deployment evidence bundle collection."""

import importlib.util
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
COLLECTOR_SCRIPT = ROOT / "scripts" / "collect_target_deployment_evidence.py"
VALIDATOR_SCRIPT = ROOT / "scripts" / "verify_target_deployment_evidence.py"

COLLECTOR_SPEC = importlib.util.spec_from_file_location(
    "collect_target_deployment_evidence", COLLECTOR_SCRIPT
)
collector = importlib.util.module_from_spec(COLLECTOR_SPEC)
assert COLLECTOR_SPEC.loader is not None
sys.modules[COLLECTOR_SPEC.name] = collector
COLLECTOR_SPEC.loader.exec_module(collector)

VALIDATOR_SPEC = importlib.util.spec_from_file_location(
    "verify_target_deployment_evidence_for_collector_test", VALIDATOR_SCRIPT
)
validator = importlib.util.module_from_spec(VALIDATOR_SPEC)
assert VALIDATOR_SPEC.loader is not None
sys.modules[VALIDATOR_SPEC.name] = validator
VALIDATOR_SPEC.loader.exec_module(validator)


def _base_args(output_dir: Path) -> list[str]:
    return [
        "--output-dir",
        str(output_dir),
        "--target-host",
        "prod-host-1",
        "--image",
        "ghcr.io/iamsothirsty/thirstys-waterfall:1.0.2",
        "--image-digest",
        "sha256:" + "a" * 64,
        "--captured-at-utc",
        "2026-07-12T17:30:00Z",
    ]


def test_complete_collected_bundle_validates(tmp_path):
    source_dir = tmp_path / "source"
    output_dir = tmp_path / "bundle"
    source_dir.mkdir()
    args = _base_args(output_dir)

    for evidence_type in collector.REQUIRED_EVIDENCE_TYPES:
        if evidence_type == "target_identity":
            continue
        artifact = source_dir / f"{evidence_type}.log"
        artifact.write_text(f"{evidence_type} passed\n", encoding="utf-8")
        args.extend(["--evidence", f"{evidence_type}={artifact}"])

    exit_code = collector.main(args)
    manifest_path = output_dir / "target-evidence.json"

    assert exit_code == 0
    assert validator.validate_manifest(manifest_path) == []


def test_incomplete_collected_bundle_stays_fail_closed(tmp_path):
    output_dir = tmp_path / "bundle"

    exit_code = collector.main(_base_args(output_dir))
    manifest_path = output_dir / "target-evidence.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    issues = validator.validate_manifest(manifest_path)

    assert exit_code == 0
    assert any(entry["status"] == "pending" for entry in manifest["evidence"])
    assert any(issue.field.endswith(".status") and issue.message == "must be passed" for issue in issues)


def test_require_complete_rejects_pending_bundle(tmp_path):
    output_dir = tmp_path / "bundle"
    args = [*_base_args(output_dir), "--require-complete"]

    try:
        collector.main(args)
    except SystemExit as exc:
        assert "target evidence bundle is incomplete" in str(exc)
    else:
        raise AssertionError("incomplete target bundle was accepted")
