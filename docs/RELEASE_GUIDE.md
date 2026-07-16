# Release Guide

This is the governed release path for Thirstys Waterfall. A release is not a
production deployment: the published artifacts and image must still be deployed
to a selected target and verified with the target evidence gate.

## Pre-Release Requirements

- The release commit is merged into the repository default branch.
- CI and CodeQL pass for that exact commit.
- `pyproject.toml`, `CHANGELOG.md`, and `.env.production.example` name the same
  stable semantic version.
- The production environment template is later updated with the immutable GHCR
  digest emitted by the successful release.
- No production secrets are present in the repository or release inputs.

`setup.py` is only a compatibility entry point. Package version metadata lives in
`pyproject.toml`.

## Prepare Release Metadata

For a patch release such as `1.0.4`:

1. Set `project.version` in `pyproject.toml`.
2. Add a dated `## [1.0.4]` section to `CHANGELOG.md`.
3. Keep the matching versioned GHCR reference and intentionally unusable zero
   digest in `.env.production.example`; replace that zero digest with the real
   published digest after the release succeeds.
4. Run the fail-closed metadata gate:

```powershell
python scripts\verify_release_version.py --expected-version 1.0.4
```

Commit these changes on a branch, open a pull request, wait for all required
checks, and merge through the protected default branch. Do not push release
preparation directly to `main`.

## Run The Automated Release

Dispatch the release workflow from the merged default branch:

```powershell
gh workflow run release.yml `
  --repo IAmSoThirsty/Thirstys-waterfall `
  --ref main `
  -f version=1.0.4
```

The workflow rejects:

- a manual dispatch from a non-default branch;
- a commit not contained in the default branch;
- a non-stable version string;
- version drift among the workflow input, package metadata, changelog, and
  production image template.
- a tag-only production image reference without a SHA-256 digest.

After validation it runs the cross-platform tests, builds reproducible wheel and
source artifacts, builds and smoke-tests the Docker image, pushes the versioned
and `latest` GHCR tags, verifies the immutable digest of the pushed versioned
image, uploads that deployment input as release evidence, and creates the
GitHub release.

Monitor the run and require a successful conclusion:

```powershell
gh run list `
  --repo IAmSoThirsty/Thirstys-waterfall `
  --workflow release.yml `
  --limit 1
```

## Post-Release Verification

Inspect the release and immutable image digest:

```powershell
gh release view v1.0.4 `
  --repo IAmSoThirsty/Thirstys-waterfall

docker buildx imagetools inspect `
  ghcr.io/iamsothirsty/thirstys-waterfall:1.0.4
```

Update `THIRSTYS_IMAGE` in `.env.production.example` to the exact form emitted by
the registry:

```text
ghcr.io/iamsothirsty/thirstys-waterfall:1.0.4@sha256:<64-hex-digest>
```

Then pull and verify those exact published bytes locally before target rollout:

```powershell
docker pull $env:THIRSTYS_IMAGE
python scripts\verify_production_deployment.py `
  --skip-tests `
  --skip-docker-build `
  --image $env:THIRSTYS_IMAGE `
  --thirsty-lang-path "T:\01-Projects\thirsty_lang_exploration_0754"
```

Record the release URL, workflow run, commit SHA, package hashes, and image digest
in `docs/operations/PRODUCTION_DEPLOYMENT_VERIFICATION.md` and the continuity map.

## Production Rollout

Production Compose requires `THIRSTYS_IMAGE`; it has no source-build fallback.
Use the exact version and digest verified above, inject real target secrets, and
validate the normalized proxy configuration before starting services:

```powershell
python scripts\verify_production_proxy_config.py `
  --compose-file docker-compose.production.yml `
  --caddyfile deploy\caddy\Caddyfile

docker compose `
  --env-file .env.production `
  -f docker-compose.production.yml `
  config --quiet

docker compose `
  --env-file .env.production `
  -f docker-compose.production.yml `
  up -d --no-build
```

The target is accepted only after live health/auth/log, TLS boundary, secret
rotation, service hardening, rollback, host network policy, shared revocation,
and platform-backend evidence passes `verify_target_deployment_evidence.py`.

## Rollback

Do not delete, move, or reuse a published release tag. Roll back the deployment by
setting `THIRSTYS_IMAGE` to the previous known-good version and digest, running
Compose with `--no-build`, then executing the target health/auth checks. Preserve
the failed release and deployment evidence for audit. If source correction is
required, publish a new patch version.

## PyPI

Manual workflow dispatch publishes GitHub and GHCR artifacts but does not run the
tag-push-only PyPI job. PyPI publication requires the configured `pypi`
environment and `PYPI_API_TOKEN`; it must not be treated as successful unless that
job runs and passes.
