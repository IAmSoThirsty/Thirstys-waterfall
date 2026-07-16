#!/usr/bin/env python3
"""Fail closed when release metadata does not describe one coherent version."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility
    import tomli as tomllib


SEMVER_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
IMAGE_PATTERN = re.compile(
    r"^ghcr\.io/iamsothirsty/thirstys-waterfall:"
    r"(?P<version>[0-9]+\.[0-9]+\.[0-9]+)"
    r"@sha256:[0-9a-f]{64}$"
)


def read_project_version(path: Path) -> str:
    """Return the PEP 621 project version."""
    project = tomllib.loads(path.read_text(encoding="utf-8")).get("project")
    if not isinstance(project, dict) or not isinstance(project.get("version"), str):
        raise ValueError(f"{path} does not define project.version")
    return project["version"]


def read_environment_image(path: Path) -> str:
    """Return the production image configured by the environment template."""
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line.startswith("THIRSTYS_IMAGE="):
            return line.split("=", 1)[1].strip()
    raise ValueError(f"{path} does not define THIRSTYS_IMAGE")


def validate_release_metadata(
    expected_version: str,
    *,
    project_file: Path,
    changelog_file: Path,
    environment_example: Path,
) -> list[str]:
    """Return every release metadata mismatch."""
    issues: list[str] = []
    if not SEMVER_PATTERN.fullmatch(expected_version):
        return [
            "expected version must use stable semantic version form X.Y.Z; "
            f"received {expected_version!r}"
        ]

    try:
        project_version = read_project_version(project_file)
    except (OSError, ValueError, tomllib.TOMLDecodeError) as exc:
        issues.append(str(exc))
    else:
        if project_version != expected_version:
            issues.append(
                f"{project_file} declares {project_version!r}, expected "
                f"{expected_version!r}"
            )

    try:
        changelog = changelog_file.read_text(encoding="utf-8")
    except OSError as exc:
        issues.append(str(exc))
    else:
        heading = re.compile(
            rf"^## \[{re.escape(expected_version)}\] - \d{{4}}-\d{{2}}-\d{{2}}$",
            re.MULTILINE,
        )
        if not heading.search(changelog):
            issues.append(
                f"{changelog_file} has no dated [{expected_version}] release section"
            )

    try:
        image = read_environment_image(environment_example)
    except (OSError, ValueError) as exc:
        issues.append(str(exc))
    else:
        match = IMAGE_PATTERN.fullmatch(image)
        if match is None:
            issues.append(
                f"{environment_example} THIRSTYS_IMAGE must reference the versioned "
                "GHCR image pinned by a 64-character sha256 digest"
            )
        elif match.group("version") != expected_version:
            issues.append(
                f"{environment_example} references image version "
                f"{match.group('version')!r}, expected {expected_version!r}"
            )

    return issues


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify that release metadata uses one exact semantic version."
    )
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--project-file", type=Path, default=Path("pyproject.toml"))
    parser.add_argument("--changelog-file", type=Path, default=Path("CHANGELOG.md"))
    parser.add_argument(
        "--environment-example",
        type=Path,
        default=Path(".env.production.example"),
    )
    args = parser.parse_args(argv)

    issues = validate_release_metadata(
        args.expected_version,
        project_file=args.project_file,
        changelog_file=args.changelog_file,
        environment_example=args.environment_example,
    )
    if issues:
        print("Release metadata verification failed:")
        for issue in issues:
            print(f"- {issue}")
        return 1

    print(f"Release metadata verified for v{args.expected_version}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
