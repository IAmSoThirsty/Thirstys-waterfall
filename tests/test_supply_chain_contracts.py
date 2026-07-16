"""Static fail-closed contracts for dependency and artifact supply chains."""

import re
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility
    import tomli as tomllib


ROOT = Path(__file__).resolve().parents[1]


def _requirement_lines(path: Path) -> list[str]:
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def test_compiled_locks_pin_and_hash_every_package():
    requirement_pattern = re.compile(r"^[A-Za-z0-9_.-]+==[^\s\\]+ \\$")
    hash_pattern = re.compile(r"^    --hash=sha256:[0-9a-f]{64}(?: \\)?$")

    for filename in ("requirements-build.lock", "requirements-deploy.lock"):
        lines = (ROOT / filename).read_text(encoding="utf-8").splitlines()
        requirement_indexes = [
            index for index, line in enumerate(lines) if requirement_pattern.fullmatch(line)
        ]
        assert requirement_indexes, f"no pinned requirements found in {filename}"
        for index in requirement_indexes:
            following_lines = lines[index + 1:]
            hashes = []
            for line in following_lines:
                if hash_pattern.fullmatch(line):
                    hashes.append(line)
                    continue
                break
            assert hashes, f"missing hash for {lines[index]} in {filename}"


def test_direct_requirements_are_present_in_compiled_locks():
    for source_name, lock_name in (
        ("requirements-build.in", "requirements-build.lock"),
        ("requirements-deploy.in", "requirements-deploy.lock"),
    ):
        lock_text = (ROOT / lock_name).read_text(encoding="utf-8").lower()
        for requirement in _requirement_lines(ROOT / source_name):
            assert requirement.lower() in lock_text


def test_build_backend_matches_audited_build_toolchain():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    build_requirements = set(project["build-system"]["requires"])
    locked_direct_requirements = set(_requirement_lines(ROOT / "requirements-build.in"))

    assert build_requirements == {"setuptools==83.0.0", "wheel==0.47.0"}
    assert build_requirements < locked_direct_requirements


def test_runtime_image_is_pinned_and_excludes_build_toolchain():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    builder, runtime = dockerfile.split("FROM ${PYTHON_IMAGE} AS runtime", maxsplit=1)

    assert "python:3.11-slim@sha256:" in builder
    assert "requirements-build.lock" in builder
    assert "--require-hashes -r requirements-build.lock" in builder
    assert "gcc" in builder
    assert "gcc" not in runtime
    assert "requirements-build.lock" not in runtime
    assert "--require-hashes -r requirements-deploy.lock" in runtime
    assert "--no-deps /wheels/*.whl" in runtime


def test_production_compose_requires_pinned_images():
    compose = (ROOT / "docker-compose.production.yml").read_text(encoding="utf-8")

    assert "${THIRSTYS_IMAGE:?" in compose
    assert "${THIRSTYS_IMAGE:-" not in compose
    assert "build:" not in compose
    assert re.search(r"caddy:2\.10-alpine@sha256:[0-9a-f]{64}", compose)


def test_release_workflow_fails_closed_on_version_or_branch_drift():
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(
        encoding="utf-8"
    )

    assert "validate-release:" in workflow
    assert "needs: validate-release" in workflow
    assert "verify_release_version.py --expected-version" in workflow
    assert "git merge-base --is-ancestor" in workflow
    assert "Manual releases must run from" in workflow


def test_all_github_actions_are_pinned_to_commit_shas():
    action_pattern = re.compile(r"^\s*uses:\s*[^@\s]+@([0-9a-f]{40})(?:\s+#.*)?$")
    for workflow in (ROOT / ".github" / "workflows").glob("*.yml"):
        uses_lines = [
            line
            for line in workflow.read_text(encoding="utf-8").splitlines()
            if "uses:" in line
        ]
        assert uses_lines, f"workflow has no actions: {workflow.name}"
        for line in uses_lines:
            assert action_pattern.fullmatch(line), (
                f"mutable or malformed action reference in {workflow.name}: {line}"
            )


def test_governed_paths_use_current_audit_and_reproducible_build_gates():
    governed_files = [
        ROOT / "pyproject.toml",
        ROOT / "scripts" / "verify_production_deployment.py",
        ROOT / ".github" / "workflows" / "ci.yml",
        ROOT / ".github" / "workflows" / "release.yml",
    ]
    combined = "\n".join(path.read_text(encoding="utf-8") for path in governed_files)

    assert "safety check" not in combined
    assert "pip_audit" in combined or "pip-audit" in combined
    assert "verify_reproducible_build.py" in combined


def test_active_docs_name_the_current_dependency_scanner():
    active_docs = [
        ROOT / "README.md",
        ROOT / "SECURITY.md",
        ROOT / "docs" / "operations" / "README_CLAIM_ACCEPTANCE.md",
    ]
    retired_phrases = (
        "Bandit, Safety",
        "Bandit/Safety",
        "Safety dependency checker",
        "safety>=2.3.0",
        "**safety**",
    )

    for path in active_docs:
        contents = path.read_text(encoding="utf-8")
        assert "pip-audit" in contents, f"current scanner missing from {path.name}"
        for phrase in retired_phrases:
            assert phrase not in contents, (
                f"retired phrase {phrase!r} found in {path.name}"
            )
