"""Tests for fail-closed release version verification."""

import importlib.util
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify_release_version.py"
SPEC = importlib.util.spec_from_file_location("verify_release_version", SCRIPT)
release_version = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = release_version
SPEC.loader.exec_module(release_version)


def _metadata(tmp_path: Path, *, version: str = "1.2.3") -> tuple[Path, Path, Path]:
    project = tmp_path / "pyproject.toml"
    changelog = tmp_path / "CHANGELOG.md"
    environment = tmp_path / ".env.production.example"
    project.write_text(
        f'[project]\nname = "example"\nversion = "{version}"\n',
        encoding="utf-8",
    )
    changelog.write_text(
        f"# Changelog\n\n## [{version}] - 2026-07-16\n\n- Verified.\n",
        encoding="utf-8",
    )
    environment.write_text(
        "THIRSTYS_IMAGE="
        f"ghcr.io/iamsothirsty/thirstys-waterfall:{version}@sha256:"
        + "a" * 64
        + "\n",
        encoding="utf-8",
    )
    return project, changelog, environment


def test_release_metadata_accepts_one_coherent_version(tmp_path):
    project, changelog, environment = _metadata(tmp_path)

    issues = release_version.validate_release_metadata(
        "1.2.3",
        project_file=project,
        changelog_file=changelog,
        environment_example=environment,
    )

    assert issues == []


def test_release_metadata_reports_every_version_mismatch(tmp_path):
    project, changelog, environment = _metadata(tmp_path, version="1.2.2")

    issues = release_version.validate_release_metadata(
        "1.2.3",
        project_file=project,
        changelog_file=changelog,
        environment_example=environment,
    )

    assert len(issues) == 3
    assert any("pyproject.toml declares '1.2.2'" in issue for issue in issues)
    assert any("no dated [1.2.3]" in issue for issue in issues)
    assert any("image version '1.2.2'" in issue for issue in issues)


def test_release_metadata_rejects_non_stable_version_before_file_access(tmp_path):
    issues = release_version.validate_release_metadata(
        "v1.2.3",
        project_file=tmp_path / "missing.toml",
        changelog_file=tmp_path / "missing.md",
        environment_example=tmp_path / "missing.env",
    )

    assert issues == [
        "expected version must use stable semantic version form X.Y.Z; "
        "received 'v1.2.3'"
    ]


def test_release_metadata_rejects_tag_only_production_image(tmp_path):
    project, changelog, environment = _metadata(tmp_path)
    environment.write_text(
        "THIRSTYS_IMAGE=ghcr.io/iamsothirsty/thirstys-waterfall:1.2.3\n",
        encoding="utf-8",
    )

    issues = release_version.validate_release_metadata(
        "1.2.3",
        project_file=project,
        changelog_file=changelog,
        environment_example=environment,
    )

    assert any("pinned by a 64-character sha256 digest" in issue for issue in issues)


def test_release_version_cli_fails_closed_on_stale_metadata(tmp_path):
    project, changelog, environment = _metadata(tmp_path, version="1.2.2")

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--expected-version",
            "1.2.3",
            "--project-file",
            str(project),
            "--changelog-file",
            str(changelog),
            "--environment-example",
            str(environment),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert "Release metadata verification failed:" in result.stdout
    assert "expected '1.2.3'" in result.stdout
