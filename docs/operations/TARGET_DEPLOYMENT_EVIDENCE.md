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
- `host_network_policy`: host firewall, exposed ports, CORS/origin, TLS/proxy,
  and network boundary evidence.
- `platform_backend_execution`: real OS VPN/firewall backend apply/rollback or
  an explicit narrowed production claim that removes the unsupported backend.

## Acceptance Rule

The target deployment is not accepted unless
`verify_target_deployment_evidence.py` exits with status `0` for the target
manifest and the manifest artifacts match their recorded SHA-256 digests.
