#!/usr/bin/env python3
"""Create a Standard v3 target deployment evidence bundle."""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import platform
import shutil
import socket
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

REQUIRED_PROOF = {
    "target_identity": "host, OS, runtime, deployment user, and network identity",
    "published_image_pull_run": "published image digest pulled and run on the target",
    "target_health_auth_logs": "target health, login, default-login rejection, logout, and revoked-token rejection logs",
    "target_rollback": "rollback executed on the target host or orchestrator",
    "secret_rotation": "target secrets rotated and old credentials rejected",
    "shared_revocation_store": "every API worker/container uses the same JWT revocation store",
    "host_network_policy": "host firewall, exposed ports, CORS/origin, TLS/proxy, and boundary evidence",
    "service_orchestrator_hardening": "service manager or orchestrator restart, health, resource, privilege, and persistence hardening",
    "platform_backend_execution": "real OS VPN/firewall backend apply/rollback or narrowed production claim",
}


@dataclass(frozen=True)
class SuppliedEvidence:
    """Evidence artifact supplied by the operator."""

    evidence_type: str
    path: Path


def utc_now() -> str:
    """Return the current UTC timestamp in ISO format."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    """Return the SHA-256 digest for a file."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_key_value(raw: str, option_name: str) -> tuple[str, str]:
    """Parse TYPE=VALUE style arguments."""
    key, separator, value = raw.partition("=")
    if not separator or not key or not value:
        raise argparse.ArgumentTypeError(f"{option_name} must use TYPE=VALUE")
    if key not in REQUIRED_EVIDENCE_TYPES:
        raise argparse.ArgumentTypeError(
            f"{option_name} type must be one of {', '.join(REQUIRED_EVIDENCE_TYPES)}"
        )
    return key, value


def parse_evidence_arg(raw: str) -> SuppliedEvidence:
    """Parse a supplied evidence artifact argument."""
    evidence_type, value = parse_key_value(raw, "--evidence")
    path = Path(value)
    if not path.is_file():
        raise argparse.ArgumentTypeError(f"--evidence file does not exist: {path}")
    return SuppliedEvidence(evidence_type=evidence_type, path=path)


def parse_summary_arg(raw: str) -> tuple[str, str]:
    """Parse a supplied evidence summary argument."""
    return parse_key_value(raw, "--summary")


def target_addresses() -> list[str]:
    """Return network addresses visible from the target host."""
    addresses: set[str] = set()
    try:
        infos = socket.getaddrinfo(socket.gethostname(), None)
    except OSError:
        return []
    for info in infos:
        address = info[4][0]
        if address:
            addresses.add(address)
    return sorted(addresses)


def write_target_identity(path: Path, captured_at_utc: str) -> None:
    """Write target identity evidence captured from the current host."""
    lines = [
        f"captured_at_utc={captured_at_utc}",
        f"hostname={socket.gethostname()}",
        f"fqdn={socket.getfqdn()}",
        f"platform={platform.platform()}",
        f"system={platform.system()}",
        f"release={platform.release()}",
        f"version={platform.version()}",
        f"machine={platform.machine()}",
        f"processor={platform.processor()}",
        f"python={sys.version.split()[0]}",
        f"user={getpass.getuser()}",
        f"cwd={Path.cwd()}",
    ]
    for index, address in enumerate(target_addresses(), start=1):
        lines.append(f"address_{index}={address}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def safe_artifact_name(evidence_type: str, source: Path | None) -> str:
    """Return a stable artifact file name for the evidence type."""
    suffix = ".log"
    if source and source.suffix:
        suffix = source.suffix
    return f"{evidence_type}{suffix}"


def copy_artifact(source: Path, destination: Path) -> None:
    """Copy an operator artifact into the evidence directory."""
    if source.resolve() == destination.resolve():
        return
    shutil.copy2(source, destination)


def write_pending_artifact(path: Path, evidence_type: str, captured_at_utc: str) -> None:
    """Write a pending evidence artifact that keeps verification fail-closed."""
    path.write_text(
        "\n".join(
            [
                f"evidence_type={evidence_type}",
                "status=pending",
                f"captured_at_utc={captured_at_utc}",
                f"required_proof={REQUIRED_PROOF[evidence_type]}",
                "attach_real_artifact=true",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def build_manifest(
    *,
    output_dir: Path,
    environment: str,
    target_host: str,
    image: str,
    image_digest: str,
    captured_at_utc: str,
    supplied: dict[str, SuppliedEvidence],
    summaries: dict[str, str],
) -> dict[str, Any]:
    """Create evidence artifacts and return the manifest object."""
    output_dir.mkdir(parents=True, exist_ok=True)
    evidence_entries: list[dict[str, Any]] = []

    for evidence_type in REQUIRED_EVIDENCE_TYPES:
        supplied_artifact = supplied.get(evidence_type)
        artifact_name = safe_artifact_name(evidence_type, supplied_artifact.path if supplied_artifact else None)
        artifact_path = output_dir / artifact_name

        if supplied_artifact:
            copy_artifact(supplied_artifact.path, artifact_path)
            status = "passed"
            summary = summaries.get(evidence_type, f"{evidence_type} evidence attached")
        elif evidence_type == "target_identity":
            write_target_identity(artifact_path, captured_at_utc)
            status = "passed"
            summary = summaries.get(evidence_type, "Target identity captured on this host")
        else:
            write_pending_artifact(artifact_path, evidence_type, captured_at_utc)
            status = "pending"
            summary = summaries.get(evidence_type, f"{evidence_type} evidence not attached")

        evidence_entries.append(
            {
                "type": evidence_type,
                "status": status,
                "summary": summary,
                "captured_at_utc": captured_at_utc,
                "artifact": artifact_name,
                "sha256": sha256_file(artifact_path),
            }
        )

    return {
        "schema_version": 1,
        "deployment": {
            "environment": environment,
            "target_host": target_host,
            "image": image,
            "image_digest": image_digest,
            "captured_at_utc": captured_at_utc,
        },
        "evidence": evidence_entries,
    }


def write_manifest(output_dir: Path, manifest: dict[str, Any]) -> Path:
    """Write the target evidence manifest."""
    manifest_path = output_dir / "target-evidence.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Create a Standard v3 target deployment evidence bundle."
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--environment", default="production")
    parser.add_argument("--target-host", default=socket.getfqdn())
    parser.add_argument("--image", required=True)
    parser.add_argument("--image-digest", required=True)
    parser.add_argument("--captured-at-utc", default=utc_now())
    parser.add_argument(
        "--evidence",
        action="append",
        default=[],
        type=parse_evidence_arg,
        metavar="TYPE=PATH",
        help="Attach an evidence artifact for a required type.",
    )
    parser.add_argument(
        "--summary",
        action="append",
        default=[],
        type=parse_summary_arg,
        metavar="TYPE=TEXT",
        help="Set the manifest summary for an evidence type.",
    )
    parser.add_argument(
        "--require-complete",
        action="store_true",
        help="Exit non-zero unless every required evidence type is attached or captured.",
    )
    args = parser.parse_args(argv)

    if not args.image_digest.startswith("sha256:"):
        raise SystemExit("--image-digest must start with sha256:")

    supplied: dict[str, SuppliedEvidence] = {}
    for item in args.evidence:
        if item.evidence_type in supplied:
            raise SystemExit(f"duplicate evidence type: {item.evidence_type}")
        supplied[item.evidence_type] = item

    summaries = dict(args.summary)
    manifest = build_manifest(
        output_dir=args.output_dir,
        environment=args.environment,
        target_host=args.target_host,
        image=args.image,
        image_digest=args.image_digest,
        captured_at_utc=args.captured_at_utc,
        supplied=supplied,
        summaries=summaries,
    )
    manifest_path = write_manifest(args.output_dir, manifest)
    pending = [entry["type"] for entry in manifest["evidence"] if entry["status"] != "passed"]

    print(
        json.dumps(
            {
                "manifest": str(manifest_path),
                "pending_evidence": pending,
            },
            indent=2,
        )
    )

    if args.require_complete and pending:
        raise SystemExit("target evidence bundle is incomplete: " + ", ".join(pending))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
