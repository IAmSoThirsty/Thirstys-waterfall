# Production Deployment Verification

Standard: Thirsty's Standard v3

Status: local verification, hosted CI, CodeQL, release workflow, GHCR publishing, and published-image local smoke are verified. Full target-host production deployment verification still requires target host, target rollback, secret rotation, host network policy, and operations log evidence.

## Local Verification Gate

Run the full local gate from the repository root:

```powershell
python scripts\verify_production_deployment.py --thirsty-lang-path "T:\00-Active\thirsty_lang_exploration_0754"
```

What this proves locally:

- Retired Thirsty-Lang compatibility identifiers are rejected from source, tests, docs, and deployment files.
- Python syntax compilation passes.
- Flake8 syntax/undefined-name gate passes.
- Full-repo Bandit passes.
- Locked deployment dependency vulnerability check passes.
- Full pytest suite passes.
- Wheel build passes.
- Local web process starts and serves `/health`.
- Local web production-mode startup uses explicit `SECRET_KEY`, `JWT_SECRET_KEY`, admin credentials, and non-wildcard `CORS_ORIGINS`.
- Enhanced Thirsty-Lang binding reports backend `thirsty-lang` when the checkout is supplied.
- Configured admin login succeeds.
- Default `admin/admin` login is rejected.
- `docker compose config` validates with required production secret interpolation supplied.
- Docker image builds.
- Docker container starts in production mode and passes the same health/auth smoke checks with explicit secrets.
- Docker container startup logs are captured and must be non-empty.
- Docker command logging redacts secret-bearing values before printing verifier commands.
- Local Docker rollback smoke starts a tagged last-known-good image with the same environment shape and passes health/auth/log checks.

If Docker is unavailable, run the non-container portion only:

```powershell
python scripts\verify_production_deployment.py --skip-docker --thirsty-lang-path "T:\00-Active\thirsty_lang_exploration_0754"
```

That is useful development evidence, but it is not enough for production Deployment Verified.

To smoke-test a release image that was already built by CI instead of rebuilding it inside the verifier:

```powershell
python scripts\verify_production_deployment.py --skip-tests --skip-docker-build --image thirstys-waterfall:<version>
```

This mode is used by the release workflow so the Docker smoke covers the actual loaded release image tag. It was also run locally against the pulled release image `ghcr.io/iamsothirsty/thirstys-waterfall:1.0.1`.

## Release Evidence

- Release workflow run: `29137207054`
- Main CodeQL run: `29138022895`
- Main CI run: `29138022899`
- Commit: `7b459a7ab0fa0873152a614ab2f751a8a037bedf`
- GitHub release: `v1.0.1`
- Wheel asset: `thirstys_waterfall-1.0.1-py3-none-any.whl`, digest `sha256:5edf2d5f5c7e956f43b26f1893f6f635b86d6023c91c7f84620b0e3238d077d7`
- Source asset: `thirstys_waterfall-1.0.1.tar.gz`, digest `sha256:be1f850612e46ca740ba560876c1e72cc7f9d0aadadf87b60214dbe6b3c5f825`
- GHCR image: `ghcr.io/iamsothirsty/thirstys-waterfall:1.0.1`
- GHCR digest: `sha256:0e35d575f8d431795fccaf53c804000d6aeec29414512a5f9c2da404de80473f`
- Published image pull: `docker pull ghcr.io/iamsothirsty/thirstys-waterfall:1.0.1` succeeded.
- Published image verifier: `python scripts\verify_production_deployment.py --skip-tests --skip-docker-build --image ghcr.io/iamsothirsty/thirstys-waterfall:1.0.1 --thirsty-lang-path "T:\00-Active\thirsty_lang_exploration_0754"` passed.

## Deployment Inputs

Required production environment values:

- `SECRET_KEY`
- `JWT_SECRET_KEY`
- `THIRSTYS_ADMIN_USERNAME`
- `THIRSTYS_ADMIN_PASSWORD_HASH`
- `CORS_ORIGINS`

Recommended production environment values:

- `THIRSTY_LANG_PATH` or a packaged equivalent if sovereign startup policy is required.
- `THIRSTY_WATERFALL_INIT_POLICY` if the default `INIT_PROTOCOL`-only policy is not sufficient.
- `REDIS_URL` if rate limit state must persist across web workers or containers.
- `ACCESS_LOG` and `ERROR_LOG` destinations if stdout/stderr collection is not handled by the runtime.

Generate the admin password hash:

```powershell
python -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('replace-this-password'))"
```

## Docker Verification

Build:

```powershell
docker build -t thirstys-waterfall:codex-verify .
```

Run a local smoke container:

```powershell
docker run --rm -p 18082:8080 `
  -e THIRSTYS_ENV=production `
  -e SECRET_KEY="<generated-secret>" `
  -e JWT_SECRET_KEY="<generated-jwt-secret>" `
  -e WEB_HOST=0.0.0.0 `
  -e WEB_PORT=8080 `
  -e WORKERS=1 `
  -e WORKER_CLASS=gevent `
  -e CORS_ORIGINS=http://localhost:18082 `
  -e THIRSTY_LANG_PATH=/opt/thirsty-lang `
  -e THIRSTYS_ADMIN_USERNAME=operator `
  -e THIRSTYS_ADMIN_PASSWORD_HASH="<generated-hash>" `
  -e THIRSTYS_ALLOW_DEMO_LOGIN=false `
  -v "T:\00-Active\thirsty_lang_exploration_0754:/opt/thirsty-lang:ro" `
  thirstys-waterfall:codex-verify
```

Health check:

```powershell
Invoke-RestMethod http://127.0.0.1:18082/health
```

Expected health fields:

- `status` is `healthy`.
- `sovereign_binding.available` is `true` when the enhanced Thirsty-Lang checkout is mounted.
- `sovereign_binding.backend` is `thirsty-lang` when the enhanced Thirsty-Lang checkout is mounted.

## Rollback

The verifier proves local Docker rollback mechanics, but rollback is not accepted as fully proven until it has been executed against the actual deployment target. The intended target rollback procedure is:

1. Keep the last known-good image tag available in the registry.
2. Stop the current container or service.
3. Start the last known-good image with the same environment and volume bindings.
4. Run `/health`.
5. Run configured admin login smoke.
6. Confirm `admin/admin` remains rejected.
7. Capture container/service logs for the rollback window.

Docker rollback example:

```powershell
docker pull <registry>/thirstys-waterfall:<last-known-good-tag>
docker stop thirstys-waterfall
docker rm thirstys-waterfall
docker run -d --name thirstys-waterfall --restart unless-stopped `
  --env-file .env `
  -p 8080:8080 `
  <registry>/thirstys-waterfall:<last-known-good-tag>
Invoke-RestMethod http://127.0.0.1:8080/health
```

## Secret Rotation

Required rotation events:

- Any suspected exposure.
- Any operator departure.
- Any production environment migration.
- At least every 90 days.

Rotation checklist:

1. Generate new `SECRET_KEY` and `JWT_SECRET_KEY`.
2. Generate a new admin password hash.
3. Update the deployment secret store.
4. Restart the service.
5. Verify `/health`.
6. Verify configured login succeeds.
7. Verify old credentials fail.
8. Revoke old secrets in the backing secret manager.
9. Record the rotation date and operator in the deployment log.

## Evidence Still Required For Full Production Deployment Verified

- GitHub Actions run for the exact commit being deployed. Current release evidence: run `29137207054` for commit `7b459a7ab0fa0873152a614ab2f751a8a037bedf`.
- CodeQL/security workflow evidence for the exact commit being deployed. Current main evidence: CodeQL run `29138022895` passed for commit `b380b2b14a7bcf0bc6682e598ca687493f73951f`; release commit evidence is from the pre-CodeQL release run and should be refreshed on the next release.
- Published image digest from the target registry. Current release evidence: `sha256:0e35d575f8d431795fccaf53c804000d6aeec29414512a5f9c2da404de80473f`.
- Pull-and-run evidence using the published image, not only a local image. Current local published-image evidence exists; target-host pull/run evidence is still missing.
- Rollback execution evidence on the target host or orchestrator, not only local Docker rollback smoke.
- Production log capture from startup, health check, login smoke, and shutdown/rollback on the target host, not only local container log capture.
- Real platform evidence for claimed VPN/firewall backends, or README claim narrowing.
- Review and reconciliation of remaining simulated, simplified, placeholder, and demo-mode paths.
