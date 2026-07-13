# Thirstys Waterfall Showcase

This page describes the current product direction and the evidence already collected for Thirstys Waterfall. It is not a production-readiness certificate. Under Thirsty's Standard v3, a capability is accepted only when implementation, tests, documentation, and operational evidence agree.

For the active acceptance matrix, see `docs/operations/README_CLAIM_ACCEPTANCE.md`.

## Current Evidence

- Local Standard v3 verifier passes with the enhanced Thirsty-Lang path.
- Hosted CI passes on Linux, Windows, and macOS for Python 3.10 and 3.11.
- CodeQL, Bandit, and locked dependency vulnerability checks pass in the recorded evidence.
- Release workflow has published GitHub release and GHCR image evidence for `v1.0.3`.
- Local published-image pull, health/auth smoke, log capture, and rollback smoke evidence exist.
- A local Docker target evidence manifest passes the strict target-evidence gate.
- The web UI no longer auto-logs in with demo credentials or displays fake active VPN/encryption state for rendered tabs.

## Capability Snapshot

| Area | Current Standard v3 status | What exists now | What remains before acceptance |
| --- | --- | --- | --- |
| Built-in VPN | Partial | Backend modules, command-path availability checks, web endpoints that fail closed when unavailable | Real OS execution evidence, privilege documentation, rollback behavior, and platform capability boundaries |
| Firewalls | Partial | Eight firewall categories represented in code and backend tests; web status no longer reports static active firewalls on backend failure | Real rule apply/rollback evidence per supported OS or narrowed claims for unsupported modes |
| Native browser engine | Partial | Native document/parser/fetcher layer with compatibility tests | Layout/rendering/navigation/session acceptance tests and a clear definition of native-engine scope |
| Encryption and private storage | Not accepted | Crypto and encrypted storage helpers exist | End-to-end evidence for stored state, browser data, logs, downloads, and transport paths |
| Web API production auth | Partial | Default hardcoded login removed; password-hash auth, process-local token revocation, session-policy reporting, and production fail-closed checks exist | Target secret-rotation evidence and shared revocation-store evidence |
| Docker and release | Partial | Local verifier, release workflow, GHCR image, published-image smoke, local rollback smoke, and local Docker target manifest evidence exist | External target host/proxy, TLS, service/orchestrator hardening, and real OS backend evidence |

## Demonstrable Workflows

These workflows are currently supported as evidence-producing local checks:

```bash
python scripts/verify_production_deployment.py --skip-docker --thirsty-lang-path "T:\00-Active\thirsty_lang_exploration_0754"
python -m pytest -q
python -m pytest tests\test_native_web_engine.py tests\test_web_app_import.py -q
```

The verifier is the strongest local gate in this repository, but it does not replace target-host production evidence.

## Product Direction

Thirstys Waterfall is being built as a local-first privacy system with:

- A native web engine direction rather than an embedded external browser engine.
- Optional enhanced Thirsty-Lang startup/governance binding.
- Built-in VPN and firewall orchestration paths that must fail closed when unavailable.
- Evidence-first release and deployment documentation.

## Current Limits

The following areas are still completion work, not accepted production claims:

- External/public target production host deployment has not been verified.
- External target host/proxy logs and TLS boundary evidence are missing.
- Local Docker target rollback, secret-rotation, shared-revocation, and host-network evidence exists; non-local orchestrator/service evidence is still missing.
- Real OS VPN/firewall backend execution evidence is missing.
- Backend-dependent capabilities still require configured provider or target-host evidence tracked in the acceptance matrix.

## Install and Inspect

```bash
git clone https://github.com/IAmSoThirsty/Thirstys-waterfall.git
cd Thirstys-waterfall
pip install -e .[test,web]
python -m pytest -q
```

Use `docs/operations/README_CLAIM_ACCEPTANCE.md` as the source of truth for what is accepted, partial, or not accepted under Standard v3.
