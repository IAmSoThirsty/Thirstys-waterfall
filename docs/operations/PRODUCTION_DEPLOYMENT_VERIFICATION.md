# Production Deployment Verification

Standard: Thirsty's Standard v3

Status: local verification, hosted CI, CodeQL, release workflow, GHCR publishing, and published-image local smoke are verified. Full target-host production deployment verification still requires target host, target rollback, secret rotation, host network policy, and operations log evidence.

Target evidence manifests are validated with:

```powershell
python scripts\verify_target_deployment_evidence.py evidence\target-deployment\target-evidence.json
```

The manifest format and required artifact types are documented in
`docs/operations/TARGET_DEPLOYMENT_EVIDENCE.md`.

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

This mode is used by the release workflow so the Docker smoke covers the actual loaded release image tag. It was also run locally against the pulled release image `ghcr.io/iamsothirsty/thirstys-waterfall:1.0.2`.

## Release Evidence

- Release workflow run: `29138685612`
- Main CodeQL run: `29138681694`
- Main CI run: `29138681714`
- Commit: `8261b212e1c2d8ecb3ca8adccbb535f2ce30710a`
- GitHub release: `v1.0.2`
- Wheel asset: `thirstys_waterfall-1.0.2-py3-none-any.whl`, digest `sha256:9e2a06a2c3f4a33bc78edd389a47d6e720aac07fafbdda2e44bb6737e3724119`
- Source asset: `thirstys_waterfall-1.0.2.tar.gz`, digest `sha256:689213e6cd8c339cfb349852ef972ce867c77b2254eae8846519884cc1e243e6`
- GHCR image: `ghcr.io/iamsothirsty/thirstys-waterfall:1.0.2`
- GHCR digest: `sha256:4095d4d28f4d39aa9859783d2a9f170be919aba0435061f3d6ee9b3af95db059`
- Published image pull: `docker pull ghcr.io/iamsothirsty/thirstys-waterfall:1.0.2` succeeded.
- Published image verifier: `python scripts\verify_production_deployment.py --skip-tests --skip-docker-build --image ghcr.io/iamsothirsty/thirstys-waterfall:1.0.2 --thirsty-lang-path "T:\00-Active\thirsty_lang_exploration_0754"` passed.

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

- GitHub Actions run for the exact commit being deployed. Current release evidence: run `29138685612` for commit `8261b212e1c2d8ecb3ca8adccbb535f2ce30710a`.
- CodeQL/security workflow evidence for the exact commit being deployed. Current main evidence: CodeQL run `29138681694` passed for commit `8261b212e1c2d8ecb3ca8adccbb535f2ce30710a`.
- Published image digest from the target registry. Current release evidence: `sha256:4095d4d28f4d39aa9859783d2a9f170be919aba0435061f3d6ee9b3af95db059`.
- Pull-and-run evidence using the published image, not only a local image. Current local published-image evidence exists; target-host pull/run evidence is still missing.
- Rollback execution evidence on the target host or orchestrator, not only local Docker rollback smoke.
- Production log capture from startup, health check, login smoke, and shutdown/rollback on the target host, not only local container log capture.
- Real platform evidence for claimed VPN/firewall backends, or README claim narrowing.
- Review and reconciliation of remaining simulated, simplified, placeholder, and demo-mode paths.
