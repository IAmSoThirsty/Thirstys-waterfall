#!/usr/bin/env python3
"""Build the wheel and sdist twice and require byte-for-byte equality."""

from __future__ import annotations

import argparse
import copy
import gzip
import hashlib
import importlib.metadata
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Sequence


ROOT = Path(__file__).resolve().parents[1]
MINIMUM_ZIP_EPOCH = 315532800
IGNORED_SOURCE_PATTERNS = (
    ".coverage",
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "*.egg-info",
    "__pycache__",
    "build",
    "dist",
    "htmlcov",
    "venv",
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _source_date_epoch() -> int:
    configured = os.environ.get("SOURCE_DATE_EPOCH")
    if configured is None:
        completed = subprocess.run(
            ["git", "log", "-1", "--pretty=%ct"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        configured = completed.stdout.strip()

    try:
        epoch = int(configured)
    except ValueError as exc:
        raise SystemExit("SOURCE_DATE_EPOCH must be an integer Unix timestamp") from exc
    if epoch < MINIMUM_ZIP_EPOCH:
        raise SystemExit(
            f"SOURCE_DATE_EPOCH must be at least {MINIMUM_ZIP_EPOCH} for ZIP output"
        )
    return epoch


def _run_build(source: Path, output: Path, epoch: int) -> None:
    env = os.environ.copy()
    env.update(
        {
            "PYTHONHASHSEED": "0",
            "SOURCE_DATE_EPOCH": str(epoch),
        }
    )
    command = [
        sys.executable,
        "-m",
        "build",
        "--no-isolation",
        "--outdir",
        str(output),
        str(source),
    ]
    print(f"+ {' '.join(command)}", flush=True)
    completed = subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=300,
    )
    if completed.returncode != 0:
        print(completed.stdout)
        raise subprocess.CalledProcessError(completed.returncode, command)


def _artifact_hashes(output: Path) -> dict[str, str]:
    artifacts = sorted(path for path in output.iterdir() if path.is_file())
    wheels = [path for path in artifacts if path.suffix == ".whl"]
    sdists = [path for path in artifacts if path.name.endswith(".tar.gz")]
    if len(wheels) != 1 or len(sdists) != 1 or len(artifacts) != 2:
        names = ", ".join(path.name for path in artifacts) or "none"
        raise SystemExit(f"expected one wheel and one sdist; found: {names}")
    return {path.name: _sha256(path) for path in artifacts}


def _normalize_sdist(output: Path, epoch: int) -> None:
    source = next(path for path in output.iterdir() if path.name.endswith(".tar.gz"))
    normalized = source.with_name(f".{source.name}.normalized")
    with tarfile.open(source, "r:gz") as source_archive:
        members = sorted(source_archive.getmembers(), key=lambda member: member.name)
        with normalized.open("wb") as output_stream:
            with gzip.GzipFile(
                filename="",
                mode="wb",
                fileobj=output_stream,
                compresslevel=9,
                mtime=epoch,
            ) as gzip_stream:
                with tarfile.open(
                    fileobj=gzip_stream,
                    mode="w",
                    format=tarfile.PAX_FORMAT,
                ) as normalized_archive:
                    for source_member in members:
                        member = copy.copy(source_member)
                        member.uid = 0
                        member.gid = 0
                        member.uname = "root"
                        member.gname = "root"
                        member.mtime = epoch
                        member.pax_headers = {
                            key: value
                            for key, value in member.pax_headers.items()
                            if key not in {"atime", "ctime", "mtime"}
                        }
                        file_data = (
                            source_archive.extractfile(source_member)
                            if source_member.isfile()
                            else None
                        )
                        normalized_archive.addfile(member, file_data)
    normalized.replace(source)


def _sdist_diagnostics(output: Path) -> dict[str, object]:
    sdist = next(path for path in output.iterdir() if path.name.endswith(".tar.gz"))
    compressed = sdist.read_bytes()
    payload_digest = hashlib.sha256()
    with gzip.open(sdist, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            payload_digest.update(chunk)
    return {
        "gzip_mtime": int.from_bytes(compressed[4:8], "little"),
        "tar_sha256": payload_digest.hexdigest(),
    }


def _toolchain_versions() -> dict[str, str]:
    versions = {"python": sys.version.split()[0]}
    for distribution in ("build", "setuptools", "wheel"):
        versions[distribution] = importlib.metadata.version(distribution)
    return versions


def verify_reproducible_build(output_dir: Path | None = None) -> dict[str, object]:
    epoch = _source_date_epoch()
    with tempfile.TemporaryDirectory(prefix="thirstys-waterfall-build-") as temporary:
        temporary_root = Path(temporary)
        build_outputs: list[Path] = []
        for build_number in (1, 2):
            source = temporary_root / f"source-{build_number}"
            output = temporary_root / f"dist-{build_number}"
            shutil.copytree(
                ROOT,
                source,
                ignore=shutil.ignore_patterns(*IGNORED_SOURCE_PATTERNS),
            )
            output.mkdir()
            _run_build(source, output, epoch)
            _normalize_sdist(output, epoch)
            build_outputs.append(output)

        first_hashes = _artifact_hashes(build_outputs[0])
        second_hashes = _artifact_hashes(build_outputs[1])
        if first_hashes != second_hashes:
            raise SystemExit(
                "reproducible build verification failed:\n"
                + json.dumps(
                    {
                        "first_build": first_hashes,
                        "second_build": second_hashes,
                        "first_sdist": _sdist_diagnostics(build_outputs[0]),
                        "second_sdist": _sdist_diagnostics(build_outputs[1]),
                    },
                    indent=2,
                    sort_keys=True,
                )
            )

        if output_dir is not None:
            destination = output_dir.resolve()
            if destination.exists() and any(destination.iterdir()):
                raise SystemExit(f"output directory is not empty: {destination}")
            destination.mkdir(parents=True, exist_ok=True)
            for artifact in build_outputs[0].iterdir():
                if artifact.is_file():
                    shutil.copy2(artifact, destination / artifact.name)

        result: dict[str, object] = {
            "schema_version": 1,
            "source_date_epoch": epoch,
            "toolchain": _toolchain_versions(),
            "artifacts": [
                {
                    "filename": name,
                    "sha256": digest,
                    "size": (build_outputs[0] / name).stat().st_size,
                }
                for name, digest in sorted(first_hashes.items())
            ],
        }
        print(json.dumps(result, indent=2, sort_keys=True))
        return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="Copy the verified artifact pair into this empty directory",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    verify_reproducible_build(args.output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
