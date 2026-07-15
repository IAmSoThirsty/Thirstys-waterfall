"""Tests for deterministic wheel and source-distribution verification."""

import gzip
import importlib.util
import io
import sys
import tarfile
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "verify_reproducible_build.py"
SPEC = importlib.util.spec_from_file_location("verify_reproducible_build", SCRIPT)
reproducible_build = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = reproducible_build
SPEC.loader.exec_module(reproducible_build)


def _write_sdist(path: Path, *, archive_mtime: int, member_mtime: int) -> None:
    with path.open("wb") as output:
        with gzip.GzipFile(fileobj=output, mode="wb", mtime=archive_mtime) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                directory = tarfile.TarInfo("package-1.0")
                directory.type = tarfile.DIRTYPE
                directory.mtime = member_mtime
                directory.uid = 1000
                directory.gid = 1000
                archive.addfile(directory)

                payload = b"deterministic payload\n"
                member = tarfile.TarInfo("package-1.0/module.py")
                member.size = len(payload)
                member.mtime = member_mtime
                member.uid = 1000
                member.gid = 1000
                member.pax_headers = {"atime": str(member_mtime + 1)}
                archive.addfile(member, io.BytesIO(payload))


def test_normalize_sdist_removes_time_and_owner_variation(tmp_path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    first_sdist = first / "package-1.0.tar.gz"
    second_sdist = second / "package-1.0.tar.gz"
    _write_sdist(first_sdist, archive_mtime=1_700_000_001, member_mtime=1_700_000_002)
    _write_sdist(second_sdist, archive_mtime=1_800_000_001, member_mtime=1_800_000_002)

    reproducible_build._normalize_sdist(first, 1_750_000_000)
    reproducible_build._normalize_sdist(second, 1_750_000_000)

    assert reproducible_build._sha256(first_sdist) == reproducible_build._sha256(second_sdist)
    assert reproducible_build._sdist_diagnostics(first) == {
        "gzip_mtime": 1_750_000_000,
        "tar_sha256": reproducible_build._sdist_diagnostics(second)["tar_sha256"],
    }


def test_artifact_hashes_requires_one_wheel_and_one_sdist(tmp_path):
    (tmp_path / "package-1.0-py3-none-any.whl").write_bytes(b"wheel")
    (tmp_path / "package-1.0.tar.gz").write_bytes(b"sdist")

    hashes = reproducible_build._artifact_hashes(tmp_path)

    assert set(hashes) == {
        "package-1.0-py3-none-any.whl",
        "package-1.0.tar.gz",
    }


def test_source_date_epoch_rejects_pre_zip_timestamp(monkeypatch):
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1")

    try:
        reproducible_build._source_date_epoch()
    except SystemExit as exc:
        assert "must be at least" in str(exc)
    else:
        raise AssertionError("pre-ZIP SOURCE_DATE_EPOCH did not fail closed")


def test_source_date_epoch_requires_explicit_value_without_git(monkeypatch):
    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)
    monkeypatch.setattr(
        reproducible_build.subprocess,
        "run",
        lambda *args, **kwargs: (_ for _ in ()).throw(FileNotFoundError("git")),
    )

    try:
        reproducible_build._source_date_epoch()
    except SystemExit as exc:
        assert "required when Git metadata is unavailable" in str(exc)
    else:
        raise AssertionError("missing Git metadata did not fail closed")


def test_prepare_output_directory_rejects_file(tmp_path):
    output_path = tmp_path / "dist"
    output_path.write_text("not a directory", encoding="utf-8")

    try:
        reproducible_build._prepare_output_directory(output_path)
    except SystemExit as exc:
        assert "output path is not a directory" in str(exc)
    else:
        raise AssertionError("file output path did not fail closed")
