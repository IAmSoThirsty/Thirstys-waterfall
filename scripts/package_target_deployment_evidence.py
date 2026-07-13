#!/usr/bin/env python3
"""Package a validated Standard v3 target deployment evidence bundle."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import verify_target_deployment_evidence as target_evidence


def utc_now() -> str:
    """Return current UTC timestamp in ISO format."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def relative_artifacts(manifest_path: Path, manifest: dict[str, Any]) -> list[tuple[str, Path]]:
    """Return manifest-declared artifact names and resolved paths."""
    artifacts: list[tuple[str, Path]] = []
    evidence = manifest.get("evidence", [])
    if not isinstance(evidence, list):
        return artifacts
    for entry in evidence:
        if not isinstance(entry, dict):
            continue
        artifact_name = entry.get("artifact")
        artifact_path = target_evidence.resolve_artifact(manifest_path, artifact_name)
        if artifact_path is not None:
            artifacts.append((str(artifact_name), artifact_path))
    return artifacts


def copy_bundle(
    *,
    manifest_path: Path,
    output_dir: Path,
    package_zip: bool,
    package_name: str | None,
    overwrite: bool = False,
) -> dict[str, Any]:
    """Copy a validated target evidence bundle and write package metadata."""
    issues = target_evidence.validate_manifest(manifest_path)
    if issues:
        details = "\n".join(f"- {issue.field}: {issue.message}" for issue in issues)
        raise SystemExit(f"target evidence bundle is invalid:\n{details}")

    manifest = target_evidence.load_manifest(manifest_path)
    source_root = manifest_path.resolve().parent
    package_segment = package_name or source_root.name
    package_path = Path(package_segment)
    if package_path.is_absolute() or len(package_path.parts) != 1 or package_segment in {"", ".", ".."}:
        raise SystemExit("package name must be a single directory name")

    output_dir.mkdir(parents=True, exist_ok=True)
    package_root = output_dir / package_segment
    zip_path = output_dir / f"{package_segment}.zip" if package_zip else None
    if package_root.exists():
        if not overwrite:
            raise SystemExit(
                f"package output already exists: {package_root}; pass --overwrite to replace it"
            )
        shutil.rmtree(package_root)
    if zip_path is not None and zip_path.exists():
        if not overwrite:
            raise SystemExit(
                f"package archive already exists: {zip_path}; pass --overwrite to replace it"
            )
        zip_path.unlink()
    package_root.mkdir(parents=True, exist_ok=True)

    shutil.copy2(manifest_path, package_root / manifest_path.name)
    copied_artifacts: list[dict[str, Any]] = []
    for artifact_name, artifact_path in relative_artifacts(manifest_path, manifest):
        destination = package_root / artifact_name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(artifact_path, destination)
        copied_artifacts.append(
            {
                "artifact": artifact_name,
                "sha256": target_evidence.sha256_file(destination),
                "bytes": destination.stat().st_size,
            }
        )

    package_manifest = {
        "schema_version": 1,
        "packaged_at_utc": utc_now(),
        "source_manifest": str(manifest_path),
        "source_root": str(source_root),
        "target_manifest": manifest,
        "copied_artifacts": copied_artifacts,
        "package_files": [
            "target-evidence.json",
            *[artifact["artifact"] for artifact in copied_artifacts],
        ],
    }
    package_manifest_path = package_root / "package-manifest.json"
    package_manifest_path.write_text(
        json.dumps(package_manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    if zip_path is not None:
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(package_root.rglob("*")):
                if path.is_file():
                    archive.write(path, path.relative_to(output_dir))

    return {
        "status": "passed",
        "package_dir": str(package_root),
        "package_manifest": str(package_manifest_path),
        "zip": str(zip_path) if zip_path else None,
        "artifact_count": len(copied_artifacts),
        "evidence_types": [entry["type"] for entry in manifest["evidence"]],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Package a validated Standard v3 target deployment evidence bundle."
    )
    parser.add_argument("manifest", type=Path, help="Path to target-evidence.json")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--package-name")
    parser.add_argument("--zip", action="store_true", dest="package_zip")
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Replace an existing package directory or archive.",
    )
    args = parser.parse_args(argv)

    report = copy_bundle(
        manifest_path=args.manifest,
        output_dir=args.output_dir,
        package_zip=args.package_zip,
        package_name=args.package_name,
        overwrite=args.overwrite,
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
