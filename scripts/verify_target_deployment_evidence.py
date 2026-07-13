#!/usr/bin/env python3
"""Validate Standard v3 target deployment evidence bundles."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REQUIRED_EVIDENCE_TYPES = (
    "target_identity",
    "published_image_pull_run",
    "target_health_auth_logs",
    "target_rollback",
    "secret_rotation",
    "shared_revocation_store",
    "host_network_policy",
    "service_orchestrator_hardening",
    "platform_backend_execution",
)


@dataclass(frozen=True)
class EvidenceIssue:
    """Validation issue for one evidence field."""

    field: str
    message: str


def load_manifest(path: Path) -> dict[str, Any]:
    """Load a JSON evidence manifest."""
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("manifest root must be a JSON object")
    return data


def sha256_file(path: Path) -> str:
    """Return the SHA-256 digest for a file."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_utc_timestamp(value: Any) -> bool:
    """Return whether a value is an ISO timestamp with timezone."""
    if not isinstance(value, str) or not value:
        return False
    candidate = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset() is not None


def resolve_artifact(manifest_path: Path, artifact: Any) -> Path | None:
    """Resolve an artifact path while keeping it inside the manifest folder."""
    if not isinstance(artifact, str) or not artifact:
        return None
    evidence_root = manifest_path.resolve().parent
    artifact_path = (evidence_root / artifact).resolve()
    if evidence_root != artifact_path and evidence_root not in artifact_path.parents:
        return None
    return artifact_path


def validate_manifest(manifest_path: Path) -> list[EvidenceIssue]:
    """Validate the manifest and referenced evidence artifacts."""
    issues: list[EvidenceIssue] = []
    try:
        manifest = load_manifest(manifest_path)
    except Exception as exc:  # noqa: BLE001 - report manifest parsing failure
        return [EvidenceIssue("manifest", f"cannot load manifest: {exc}")]

    if manifest.get("schema_version") != 1:
        issues.append(EvidenceIssue("schema_version", "must be 1"))

    deployment = manifest.get("deployment")
    if not isinstance(deployment, dict):
        issues.append(EvidenceIssue("deployment", "must be an object"))
        deployment = {}

    for field in ("environment", "target_host", "image", "image_digest"):
        if not isinstance(deployment.get(field), str) or not deployment.get(field):
            issues.append(EvidenceIssue(f"deployment.{field}", "must be a non-empty string"))

    image_digest = deployment.get("image_digest")
    if isinstance(image_digest, str) and not image_digest.startswith("sha256:"):
        issues.append(EvidenceIssue("deployment.image_digest", "must start with sha256:"))

    if not parse_utc_timestamp(deployment.get("captured_at_utc")):
        issues.append(
            EvidenceIssue(
                "deployment.captured_at_utc",
                "must be an ISO timestamp with timezone",
            )
        )

    evidence = manifest.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        return issues + [EvidenceIssue("evidence", "must be a non-empty list")]

    seen_types: set[str] = set()
    for index, entry in enumerate(evidence):
        prefix = f"evidence[{index}]"
        if not isinstance(entry, dict):
            issues.append(EvidenceIssue(prefix, "must be an object"))
            continue

        evidence_type = entry.get("type")
        if evidence_type not in REQUIRED_EVIDENCE_TYPES:
            issues.append(
                EvidenceIssue(
                    f"{prefix}.type",
                    f"must be one of {', '.join(REQUIRED_EVIDENCE_TYPES)}",
                )
            )
        else:
            seen_types.add(evidence_type)

        if entry.get("status") != "passed":
            issues.append(EvidenceIssue(f"{prefix}.status", "must be passed"))

        if not isinstance(entry.get("summary"), str) or not entry.get("summary"):
            issues.append(EvidenceIssue(f"{prefix}.summary", "must be a non-empty string"))

        if not parse_utc_timestamp(entry.get("captured_at_utc")):
            issues.append(
                EvidenceIssue(
                    f"{prefix}.captured_at_utc",
                    "must be an ISO timestamp with timezone",
                )
            )

        artifact_path = resolve_artifact(manifest_path, entry.get("artifact"))
        if artifact_path is None:
            issues.append(
                EvidenceIssue(
                    f"{prefix}.artifact",
                    "must be a relative path inside the evidence folder",
                )
            )
            continue
        if not artifact_path.is_file():
            issues.append(EvidenceIssue(f"{prefix}.artifact", "file does not exist"))
            continue

        expected_sha = entry.get("sha256")
        if not isinstance(expected_sha, str) or len(expected_sha) != 64:
            issues.append(EvidenceIssue(f"{prefix}.sha256", "must be a 64-character SHA-256 hex digest"))
            continue
        actual_sha = sha256_file(artifact_path)
        if actual_sha != expected_sha.lower():
            issues.append(EvidenceIssue(f"{prefix}.sha256", "does not match artifact content"))

    for evidence_type in REQUIRED_EVIDENCE_TYPES:
        if evidence_type not in seen_types:
            issues.append(EvidenceIssue("evidence", f"missing required type: {evidence_type}"))

    return issues


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate a Standard v3 target deployment evidence manifest."
    )
    parser.add_argument("manifest", type=Path, help="Path to target-evidence.json")
    args = parser.parse_args(argv)

    issues = validate_manifest(args.manifest)
    if issues:
        print("Target deployment evidence validation failed:")
        for issue in issues:
            print(f"- {issue.field}: {issue.message}")
        return 1

    checked_at = datetime.now(timezone.utc).isoformat()
    print(
        json.dumps(
            {
                "status": "passed",
                "checked_at_utc": checked_at,
                "required_evidence_types": list(REQUIRED_EVIDENCE_TYPES),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
