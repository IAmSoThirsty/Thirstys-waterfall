# Target Deployment Evidence

Status: required before full Standard v3 production acceptance.

Local Docker smoke, hosted CI, CodeQL, release publishing, and published-image
local rollback evidence are not enough to mark this repository production
ready. Full acceptance requires a target evidence bundle validated by:

```powershell
python scripts\verify_target_deployment_evidence.py evidence\target-deployment\target-evidence.json
```

## Manifest Shape

The manifest must be JSON with `schema_version: 1`, a `deployment` object, and
an `evidence` list. Every evidence entry must point to an artifact file inside
the evidence folder and include the artifact SHA-256 digest.

```json
{
  "schema_version": 1,
  "deployment": {
    "environment": "production",
    "target_host": "prod-host-1",
    "image": "ghcr.io/iamsothirsty/thirstys-waterfall:1.0.3",
    "image_digest": "sha256:<published digest>",
    "captured_at_utc": "2026-07-12T17:30:00Z"
  },
  "evidence": [
    {
      "type": "target_identity",
      "status": "passed",
      "summary": "Target host identity captured before deployment.",
      "captured_at_utc": "2026-07-12T17:30:00Z",
      "artifact": "target-identity.log",
      "sha256": "<artifact sha256>"
    }
  ]
}
```

## Required Evidence Types

- `target_identity`: host, OS, runtime, deployment user, and network identity.
- `published_image_pull_run`: target pulled and ran the published image digest.
- `target_health_auth_logs`: target health, configured login, default-login
  rejection, logout, and revoked-token rejection evidence.
- `target_rollback`: rollback executed on the target host or orchestrator.
- `secret_rotation`: secrets rotated on target and old credentials rejected.
- `shared_revocation_store`: every API worker/container uses the same JWT
  revocation store and revoked-token rejection works across workers.
- `host_network_policy`: host firewall, exposed ports, CORS/origin, TLS/proxy,
  and network boundary evidence.
- `service_orchestrator_hardening`: service manager or orchestrator restart,
  health, resource, privilege, persistence, and read-only configuration
  hardening evidence.
- `platform_backend_execution`: real OS VPN/firewall backend apply/rollback or
  an explicit narrowed production claim that removes the unsupported backend.

## Acceptance Rule

The target deployment is not accepted unless
`verify_target_deployment_evidence.py` exits with status `0` for the target
manifest and the manifest artifacts match their recorded SHA-256 digests.

## Bundle Collector

Use the collector on the target host to create `target-evidence.json` and the
artifact files in one folder:

```powershell
python scripts\collect_target_deployment_evidence.py `
  --output-dir evidence\target-deployment `
  --target-host prod-host-1 `
  --image ghcr.io/iamsothirsty/thirstys-waterfall:1.0.3 `
  --image-digest sha256:<published digest> `
  --evidence published_image_pull_run=artifacts\published-image-pull-run.log `
  --evidence target_health_auth_logs=artifacts\target-health-auth-logs.log `
  --evidence target_rollback=artifacts\target-rollback.log `
  --evidence secret_rotation=artifacts\secret-rotation.log `
  --evidence shared_revocation_store=artifacts\shared-revocation-store.log `
  --evidence host_network_policy=artifacts\host-network-policy.log `
  --evidence service_orchestrator_hardening=artifacts\service-orchestrator-hardening.log `
  --evidence platform_backend_execution=artifacts\platform-backend-execution.log `
  --require-complete
```

The collector captures `target_identity` directly from the host. Any evidence
type not supplied as an artifact is written with `status: pending`, which keeps
the verifier fail-closed until the real artifact is attached.

## Evidence Package/Audit

After the target manifest validates, package the bundle for retention or review:

```powershell
python scripts\package_target_deployment_evidence.py `
  evidence\target-deployment\target-evidence.json `
  --output-dir evidence\packages `
  --package-name prod-host-1-20260713 `
  --zip
```

The packager runs the same fail-closed target evidence validator before copying
anything. It copies `target-evidence.json`, every manifest-declared artifact,
writes `package-manifest.json` with artifact hashes and sizes, and can create a
zip archive. It exits non-zero if the manifest is incomplete, an artifact is
outside the evidence folder, a recorded SHA-256 digest does not match, the
package name is not a single directory name, or the output already exists. Use
`--overwrite` only when intentionally replacing an existing local evidence
package.

## Published Image Pull/Run Probe

Run the published-image probe on the target host to prove the exact published
image digest can be pulled and started in production mode. Prefer environment
variables for secret values:

```powershell
$env:THIRSTYS_TARGET_USERNAME = "operator"
$env:THIRSTYS_TARGET_PASSWORD = "<target password>"
$env:THIRSTYS_TARGET_ADMIN_PASSWORD_HASH = "<werkzeug password hash>"
$env:SECRET_KEY = "<target secret key>"
$env:JWT_SECRET_KEY = "<target jwt secret key>"
python scripts\probe_target_image_evidence.py `
  --image ghcr.io/iamsothirsty/thirstys-waterfall:1.0.3 `
  --image-digest sha256:<published digest> `
  --output artifacts\published-image-pull-run.json
```

The probe writes a redacted JSON artifact and exits non-zero unless Docker or
Podman can pull the pinned digest, inspect the pulled image, start a container
with production auth configuration, pass health/auth/default-login rejection
checks, and capture container logs. Supply the resulting artifact to the bundle
collector as `published_image_pull_run`.

## Host Network Policy Probe

Run the host network policy probe on the target host or proxy host to prove the
exposed port, host firewall policy, CORS origin, and TLS boundary:

```powershell
python scripts\probe_host_network_policy_evidence.py `
  --base-url https://prod-host-1.example `
  --expected-origin https://operator-console.example `
  --expected-public-port 443 `
  --output artifacts\host-network-policy.json
```

The probe writes a bounded JSON artifact and exits non-zero unless it captures
listening-port output, host firewall policy command output, verified TLS
certificate evidence for HTTPS targets, and a non-wildcard CORS preflight match
for the expected origin. Supply the resulting artifact to the bundle collector
as `host_network_policy`.

For the repository's Caddy production proxy configuration, first validate the
deployable proxy shape locally:

```powershell
python scripts\verify_production_proxy_config.py `
  --compose-file docker-compose.production.yml `
  --caddyfile deploy\caddy\Caddyfile
```

That command does not replace target TLS evidence. After deploying
`docker-compose.production.yml` with a real public host, capture the live
boundary with `probe_host_network_policy_evidence.py` against the HTTPS URL.

## Service/Orchestrator Hardening Probe

Run the service/orchestrator hardening probe against the deployment
configuration used by the target. For Docker Compose deployments, the probe
uses Docker Compose's normalized JSON config output and supplies only redacted
placeholder values for required secret interpolation:

```powershell
python scripts\probe_service_orchestrator_evidence.py `
  --compose-file docker-compose.yml `
  --dockerfile Dockerfile `
  --service thirstys-waterfall `
  --output artifacts\service-orchestrator-hardening.json
```

The probe exits non-zero unless it captures a defined service, production-mode
environment, required secret interpolation, non-root Dockerfile user,
`no-new-privileges`, non-privileged container mode, explicit Linux
capabilities, an orchestrator healthcheck, restart policy, resource limits and
reservations, persistent JWT revocation storage, and a read-only configuration
mount. Supply the resulting artifact to the bundle collector as
`service_orchestrator_hardening`.

## Rollback Probe

Run the rollback probe on the target host or deployment orchestrator after
installing a known rollback candidate. Commands are JSON arrays and run with
shell execution disabled:

```powershell
python scripts\probe_target_rollback_evidence.py `
  --rollback-command '["docker","compose","up","-d","previous"]' `
  --validation-command '["docker","compose","ps"]' `
  --base-url https://prod-host-1.example `
  --output artifacts\target-rollback.json
```

The probe exits non-zero unless rollback commands pass and either a validation
command passes or the target health endpoint returns `200`. Supply the artifact
as `target_rollback`.

## Secret Rotation Probe

Run the secret rotation probe after rotating the target administrator secret.
Prefer environment variables for credential values:

```powershell
$env:THIRSTYS_TARGET_USERNAME = "operator"
$env:THIRSTYS_TARGET_OLD_PASSWORD = "<old password>"
$env:THIRSTYS_TARGET_NEW_PASSWORD = "<new password>"
python scripts\probe_secret_rotation_evidence.py `
  --base-url https://prod-host-1.example `
  --rotation-command '["deployctl","rotate-secrets"]' `
  --require-pre-rotation-old-login `
  --output artifacts\secret-rotation.json
```

The `--require-pre-rotation-old-login` option makes the probe prove the old
credential worked before rotation commands run, then prove the old credential is
rejected and the new credential receives an access token afterward.
Token-bearing response fields are redacted from the artifact. Supply the
artifact as `secret_rotation`.

Generated local target bundles under `evidence/` are ignored by git by default.
Package or copy a bundle deliberately when it must be retained outside the local
machine.

## Platform Backend Probe

Run the platform backend probe for production VPN/firewall claims that require
real OS backend execution:

```powershell
python scripts\probe_platform_backend_evidence.py `
  --backend windows-firewall `
  --apply-command '["netsh","advfirewall","set","allprofiles","state","on"]' `
  --verify-command '["netsh","advfirewall","show","allprofiles"]' `
  --rollback-command '["netsh","advfirewall","reset"]' `
  --output artifacts\platform-backend-execution.json
```

If a backend claim is intentionally narrowed out of production scope, attach the
claim document instead:

```powershell
python scripts\probe_platform_backend_evidence.py `
  --backend vpn `
  --narrowed-claim-file docs\operations\PLATFORM_CAPABILITIES.md `
  --output artifacts\platform-backend-execution.json
```

The probe exits non-zero unless apply and rollback commands pass, or a non-empty
narrowed production claim file is attached. Supply the artifact as
`platform_backend_execution`.

## Live Auth Probe

Use the live probe against the deployed target to create the
`target_health_auth_logs` artifact. Prefer environment variables for the target
password so it is not recorded in shell history:

```powershell
$env:THIRSTYS_TARGET_USERNAME = "operator"
$env:THIRSTYS_TARGET_PASSWORD = "<target password>"
python scripts\probe_target_auth_evidence.py `
  --base-url https://prod-host-1.example `
  --peer-base-url https://prod-host-1-worker-2.example `
  --output artifacts\target-health-auth-logs.json
```

The probe writes a redacted JSON artifact and exits non-zero unless the target
proves health, configured login, default-login rejection, logout, revoked-token
rejection, and, when peer URLs are supplied, cross-worker revoked-token
rejection. The same artifact may be supplied for `shared_revocation_store` when
the peer checks pass:

```powershell
python scripts\collect_target_deployment_evidence.py `
  --output-dir evidence\target-deployment `
  --target-host prod-host-1 `
  --image ghcr.io/iamsothirsty/thirstys-waterfall:1.0.3 `
  --image-digest sha256:<published digest> `
  --evidence target_health_auth_logs=artifacts\target-health-auth-logs.json `
  --evidence shared_revocation_store=artifacts\target-health-auth-logs.json `
  --require-complete
```
