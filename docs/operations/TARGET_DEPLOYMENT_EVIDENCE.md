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
    "image": "ghcr.io/iamsothirsty/thirstys-waterfall:1.0.2",
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
  --image ghcr.io/iamsothirsty/thirstys-waterfall:1.0.2 `
  --image-digest sha256:<published digest> `
  --evidence published_image_pull_run=artifacts\published-image-pull-run.log `
  --evidence target_health_auth_logs=artifacts\target-health-auth-logs.log `
  --evidence target_rollback=artifacts\target-rollback.log `
  --evidence secret_rotation=artifacts\secret-rotation.log `
  --evidence shared_revocation_store=artifacts\shared-revocation-store.log `
  --evidence host_network_policy=artifacts\host-network-policy.log `
  --evidence platform_backend_execution=artifacts\platform-backend-execution.log `
  --require-complete
```

The collector captures `target_identity` directly from the host. Any evidence
type not supplied as an artifact is written with `status: pending`, which keeps
the verifier fail-closed until the real artifact is attached.

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
  --image ghcr.io/iamsothirsty/thirstys-waterfall:1.0.2 `
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
  --image ghcr.io/iamsothirsty/thirstys-waterfall:1.0.2 `
  --image-digest sha256:<published digest> `
  --evidence target_health_auth_logs=artifacts\target-health-auth-logs.json `
  --evidence shared_revocation_store=artifacts\target-health-auth-logs.json `
  --require-complete
```
