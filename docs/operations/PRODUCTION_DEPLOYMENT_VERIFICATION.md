# Production Deployment Verification

Standard: Thirsty's Standard v3

Status: local verification, hosted CI, CodeQL, release workflow, GHCR publishing, published-image local smoke, production TLS reverse-proxy config validation, and a local Docker target evidence manifest with service/orchestrator hardening are verified. External/public production deployment verification still requires non-local target/proxy logs, live TLS certificate/boundary evidence, external service/orchestrator hardening evidence, and real OS backend evidence or narrowed claims.

Target evidence manifests are validated with:

```powershell
python scripts\verify_target_deployment_evidence.py evidence\target-deployment\target-evidence.json
```

The main verifier can also validate the same target evidence bundle:

```powershell
python scripts\verify_production_deployment.py --target-evidence-manifest evidence\target-deployment\target-evidence.json
```

For a target-host deployment acceptance run, fail closed when that bundle is
missing:

```powershell
python scripts\verify_production_deployment.py --require-target-evidence --target-evidence-manifest evidence\target-deployment\target-evidence.json
```

The manifest format and required artifact types are documented in
`docs/operations/TARGET_DEPLOYMENT_EVIDENCE.md`.

## Local Verification Gate

Run the full local gate from the repository root:

```powershell
python scripts\verify_production_deployment.py --thirsty-lang-path "T:\01-Projects\thirsty_lang_exploration_0754"
```

The complete pytest subprocess has a bounded 480-second default. Use
`--test-timeout <seconds>` only when a slower target requires a larger explicit
bound; nonpositive values fail closed.

What this proves locally:

- Retired Thirsty-Lang compatibility identifiers are rejected from source, tests, docs, and deployment files.
- Python syntax compilation passes.
- Full Flake8 lint gate passes with a 127-character line limit.
- Mypy passes for 108 explicitly enrolled source files: the production
  deployment/evidence scripts plus 95 runtime files covering platform,
  Thirsty-Lang binding, browser, configuration, VPN, firewall, privacy,
  storage, utility, remote-access, media-download, root orchestration,
  AI assistant, ad-annihilator, setup, theme, Consigliere, Wi-Fi, and network
  stealth surfaces.
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
python scripts\verify_production_deployment.py --skip-docker --thirsty-lang-path "T:\01-Projects\thirsty_lang_exploration_0754"
```

That is useful development evidence, but it is not enough for production Deployment Verified.

To smoke-test a release image that was already built by CI instead of rebuilding it inside the verifier:

```powershell
python scripts\verify_production_deployment.py --skip-tests --skip-docker-build --image thirstys-waterfall:<version>
```

This mode is used by the release workflow so the Docker smoke covers the actual loaded release image tag. It was also run locally against the pulled release image `ghcr.io/iamsothirsty/thirstys-waterfall:1.0.3`.

## Release Evidence

- Release workflow run: `29226584539`
- Main CodeQL run: `29226577880`
- Main CI run: `29226577874`
- Commit: `a83c9dc940d40409a5c9531864b07521d735b13b`
- GitHub release: `v1.0.3`
- Wheel asset: `thirstys_waterfall-1.0.3-py3-none-any.whl`, digest `sha256:b6dbcb244542f8c5ec3baa22b575c44a6cc8e2a4473a34bcce39a06dcc52ac66`
- Source asset: `thirstys_waterfall-1.0.3.tar.gz`, digest `sha256:feda347d202f78dc3442a2329075228d77a272fad7b249040dedecb34b5c586d`
- GHCR image: `ghcr.io/iamsothirsty/thirstys-waterfall:1.0.3`
- GHCR digest: `sha256:9bcb45941b19bd8ae1b848c5ffecaca8df9a15472ca02efb45999e283fe564bc`
- Published image pull: `docker pull ghcr.io/iamsothirsty/thirstys-waterfall:1.0.3` succeeded.
- Published image verifier: `python scripts\verify_production_deployment.py --skip-tests --skip-docker-build --image ghcr.io/iamsothirsty/thirstys-waterfall:1.0.3 --thirsty-lang-path "T:\01-Projects\thirsty_lang_exploration_0754"` passed.
- Target evidence fail-closed check without a manifest: `python scripts\verify_production_deployment.py --skip-docker --skip-tests --require-target-evidence --thirsty-lang-path "T:\01-Projects\thirsty_lang_exploration_0754"` fails with `target deployment evidence is required; pass --target-evidence-manifest`.

## Local Docker Target Evidence

- Local manifest: `evidence\target-deployment\local-docker-v1.0.3-20260713T070000Z\target-evidence.json`
- Strict verifier: `python scripts\verify_production_deployment.py --skip-docker --skip-tests --require-target-evidence --target-evidence-manifest evidence\target-deployment\local-docker-v1.0.3-20260713T070000Z\target-evidence.json --thirsty-lang-path "T:\01-Projects\thirsty_lang_exploration_0754"` passed on branch `harden/service-orchestrator-evidence`.
- Evidence types present: `target_identity`, `published_image_pull_run`, `target_health_auth_logs`, `target_rollback`, `secret_rotation`, `shared_revocation_store`, `host_network_policy`, `service_orchestrator_hardening`, and `platform_backend_execution`.
- Scope caveat: this bundle proves a local Docker target with explicit local HTTP boundary, local Docker service-hardening evidence, and a narrowed platform-backend claim. It does not prove an external/public target, TLS/proxy boundary, external service manager/orchestrator hardening, or real OS VPN/firewall backend execution.

## Production TLS Proxy Configuration

The production deployment configuration places the web service behind Caddy,
publishes only ports `80` and `443` from the proxy, keeps the application
container on a private Compose network, scopes CORS to
`https://${THIRSTYS_PUBLIC_HOST}`, mounts the Caddyfile read-only, and stores
ACME data in persistent volumes.

```powershell
Copy-Item .env.production.example .env.production
# edit .env.production with real secrets, THIRSTYS_PUBLIC_HOST, and CADDY_ACME_EMAIL
python scripts\verify_production_proxy_config.py `
  --compose-file docker-compose.production.yml `
  --caddyfile deploy\caddy\Caddyfile
docker compose --env-file .env.production -f docker-compose.production.yml up -d
```

Current local config evidence: `python scripts\verify_production_proxy_config.py --compose-file docker-compose.production.yml --caddyfile deploy\caddy\Caddyfile` passed with 15/15 checks. This proves the repository's production proxy configuration shape. It does not prove that a public host has been deployed, that ACME issued a certificate, or that target proxy logs and live TLS evidence have been captured.

## Evidence Package Retention

Target evidence should be packaged after validation so the manifest and
artifacts can be retained together with a second package-level manifest:

```powershell
python scripts\package_target_deployment_evidence.py `
  evidence\target-deployment\target-evidence.json `
  --output-dir evidence\packages `
  --package-name prod-host-1-20260713 `
  --zip
```

Current local package evidence: `python scripts\package_target_deployment_evidence.py evidence\target-deployment\local-docker-v1.0.3-20260713T070000Z\target-evidence.json --output-dir evidence\packages --package-name local-docker-v1.0.3-20260713T070000Z --zip --overwrite` passed and copied all 9 required evidence artifacts. Generated `evidence\packages\...` outputs remain local and ignored by git unless deliberately retained elsewhere.

Package replacement is fail-closed by default. If a package directory or archive
already exists, the command exits non-zero unless `--overwrite` is provided.

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
- `JWT_REVOCATION_DB_PATH` set to a writable SQLite path shared by every API worker/container when more than one worker or host serves API traffic.

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
  -e JWT_REVOCATION_DB_PATH=/home/thirsty/.thirstys_waterfall/revoked_tokens.sqlite3 `
  -v "T:\01-Projects\thirsty_lang_exploration_0754:/opt/thirsty-lang:ro" `
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

- GitHub Actions run for the exact commit being deployed. Current release evidence: run `29226584539` for commit `a83c9dc940d40409a5c9531864b07521d735b13b`.
- CodeQL/security workflow evidence for the exact commit being deployed. Current main evidence: CodeQL run `29226577880` passed for commit `a83c9dc940d40409a5c9531864b07521d735b13b`.
- Published image digest from the target registry. Current release evidence: `sha256:9bcb45941b19bd8ae1b848c5ffecaca8df9a15472ca02efb45999e283fe564bc`.
- External/public pull-and-run evidence using the published image. Current local Docker target pull/run evidence exists.
- External target/proxy logs for startup, health check, login smoke, shutdown, and rollback. Current local container log evidence exists.
- Live TLS/proxy boundary evidence for any public deployment. The current local Docker target evidence explicitly allows local HTTP, and the production proxy config verifier only proves deployable config shape.
- Service manager/orchestrator hardening evidence for the chosen external target. Current local Docker service-hardening evidence exists.
- Real platform evidence for claimed VPN/firewall backends, or production-scope claim narrowing.
- Review and reconciliation of remaining simulated, simplified, placeholder, and demo-mode paths.
- Whole-runtime type-check adoption. The current hard mypy gate covers the 13
  production deployment and target-evidence scripts plus 95 explicitly
  enrolled runtime files. The remaining 12 unenrolled runtime files are the
  defect-bearing settings and security packages.
- External/public target packaged evidence archive created after the external/public manifest passes validation. Current package proof is local Docker target evidence only.
