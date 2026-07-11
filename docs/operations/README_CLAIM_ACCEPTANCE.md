# README Claim Acceptance Matrix

This matrix is the active Standard v3 plan for making the repository satisfy the minimum accepted requirements implied by its README. A claim is accepted only when implementation, tests, docs, and operational evidence agree.

## Acceptance Summary

Status: `in progress`

Current conclusion: the repository now passes the reproducible local Standard v3 deployment verifier, hosted CI, CodeQL, release workflow, GHCR publishing, published-image pull, and local published-image rollback/log-capture smoke. It is still not accepted for full target-host deployment under Standard v3 because target-host rollback/log evidence, production secret rotation evidence, host network policy evidence, and real platform backend evidence remain missing.

## Claim Matrix

| README claim | Current status | Evidence now present | Remaining acceptance work |
| --- | --- | --- | --- |
| Complete deployment-accepted ecosystem | Partial | `python scripts\verify_production_deployment.py --thirsty-lang-path "T:\00-Active\thirsty_lang_exploration_0754"` passes; CodeQL run `29138681694` passed for commit `8261b212e1c2d8ecb3ca8adccbb535f2ce30710a`; release workflow run `29138685612` passed; release `v1.0.2` published; GHCR image `ghcr.io/iamsothirsty/thirstys-waterfall:1.0.2` has digest `sha256:4095d4d28f4d39aa9859783d2a9f170be919aba0435061f3d6ee9b3af95db059`; published image pull and local rollback/log smoke pass; orchestrator status now reports `deployment_accepted: False` until evidence is complete | Target production logs, target rollback execution evidence, secrets rotation execution evidence, host network policy evidence, and real platform backend evidence |
| Built-in VPN | Partial | VPN backend modules and tests exist; subprocess execution paths are shell-free and command-resolved; web VPN connect/disconnect endpoints no longer return fabricated success payloads; `VPNManager` now connects through backend instances and fails closed instead of returning synthetic endpoints | Prove real OS integration on supported platforms, document privilege requirements, and separate mocked/backend-availability tests from real integration tests |
| 8 firewall types | Partial | Firewall modules and backend factory tests exist; backend command paths are shell-free and command-resolved; web firewall list no longer reports static active firewalls when backend status is unavailable | Prove each firewall backend applies and rolls back real rules on its supported OS, or clearly mark unsupported modes |
| Privacy-first incognito browser | Partial | Added native document/parser/fetcher engine layer and compatibility tests; web UI no longer auto-logs in with demo credentials or displays fake rendered-page VPN/encryption claims; browser status now separates encrypted helper activity from accepted end-to-end browser encryption/native-engine claims; encrypted search no longer returns placeholder results when no backend is configured | Add layout/rendering/navigation/session behavior acceptance tests; define what "native web engine" includes and excludes; add or document a real encrypted search backend |
| Total encryption of all data | Not accepted | Crypto modules and encrypted storage helpers exist; orchestrator and browser status no longer report `everything_encrypted: True` or accepted encryption tier by default | End-to-end proof for stored state, browser data, logs, telemetry, downloads, and transport paths |
| No stubs, placeholders, or TODOs | Not accepted | New continuity map identifies current simulated and placeholder paths; web static demo-login/fake-active status paths are covered by regression tests; encrypted search placeholder results were replaced with an encrypted fail-closed unavailable response; local inference no longer returns a simulated AI response without a configured backend; remote browser no longer reports simulated server/session command success without a transport backend; media downloader no longer reports completed downloads without a download backend | Replace or explicitly reclassify each remaining simulated, placeholder, simplified, and production-substitute path |
| Real backends | Partial | Backend factories exist; some tests exercise backend availability; local Docker web backend starts and serves health/auth; IKEv2 availability now requires a concrete OS command path instead of platform name alone; VPN manager startup now fails closed when configured backends are unavailable or fail to connect | Add real VPN/firewall backend execution evidence and fail-closed handling when required OS tools are absent |
| Comprehensive testing | Partial | Latest full local verifier ran `python -m pytest -q`: 326 tests passed with no pytest warning summary; hosted PR and release workflows passed Linux, Windows, and macOS on Python 3.10-3.11 | Keep separating availability/unit coverage from real OS backend execution tests |
| CI/CD pipeline | Partial | CI test install path now includes `.[test,web]`; flake8 syntax gate is hard; Bandit/Safety no longer swallow failures; Python matrix is now 3.10-3.11 to match the patched web dependency stack; CodeQL run `29138681694` passed; release Docker smoke tests the loaded release image tag without rebuilding; release workflow run `29138685612` passed; PyPI publish is skipped for workflow-dispatch releases | Add target deployment workflow evidence |
| Security audits | Partial | Full-repo Bandit passes with 0 findings; deployment lock vulnerability check passes with 0 vulnerabilities and 0 ignored vulnerabilities; CodeQL run `29138681694` passed on main | Continue scheduled CodeQL monitoring and triage any future findings |
| Public README/marketing/comparison claims | Partial | README high-risk feature, architecture, platform, security, and comparison language now points to current evidence and remaining Standard v3 gaps; `docs/SHOWCASE.md` and `docs/COMPETITION_COMPARISON.md` now describe current evidence instead of claiming accepted production superiority | Keep README and public docs aligned as implementation evidence changes |
| Web API production authentication | Partial | Default hardcoded `admin/admin` login removed; password-hash auth added; fail-closed tests added; production import rejects missing secrets, wildcard CORS, and demo login; local and container production-mode login smoke pass with explicit secrets | Add operator setup docs, token revocation/session policy, and target secret rotation execution evidence |
| Thirsty-Lang / sovereign startup integration | Partial | Optional bridge loads local enhanced `utf.tarl` from `T:\00-Active\thirsty_lang_exploration_0754`; local and container health smoke report backend `thirsty-lang` when mounted | Define full governance contract, policy source, denial handling, proof persistence, and CI-safe integration strategy |
| Docker deployment | Partial | Verifier builds `thirstys-waterfall:codex-verify`; release workflow run `29138685612` loads, smoke-tests, and pushes `ghcr.io/iamsothirsty/thirstys-waterfall:1.0.2`; published digest is `sha256:4095d4d28f4d39aa9859783d2a9f170be919aba0435061f3d6ee9b3af95db059`; local pull plus health/auth/log and rollback smoke passed with enhanced Thirsty-Lang mounted read-only | Target rollback, non-local secret injection, target logs, production host/network policy, and orchestrator/service hardening evidence |
| Cross-platform support | Not accepted | CI matrix declares Linux, Windows, and macOS on Python 3.10-3.11 | Prove platform-specific install/runtime behavior and document platform capability differences |

## Immediate Completion Plan

1. Convert remaining simulated implementation paths into real backends or adjust the README claim language.
2. Execute rollback and secret rotation procedure against the target deployment and capture target logs.
3. Attach target-host deployment, rollback, secret-rotation, and log evidence to this matrix.
4. Prove real OS VPN/firewall backend execution or narrow the related README claims further.

## Evidence Required Before Marking Complete

- Clean full local test run.
- Clean package build and install from wheel.
- Clean import/startup path without local-only dependencies.
- Explicit Thirsty-Lang optional-binding behavior with and without local checkout.
- Clean full-repo Bandit scan.
- Clean locked dependency vulnerability scan.
- Docker build and container smoke evidence.
- Reproducible verifier evidence from `scripts/verify_production_deployment.py`.
- CI run showing hard test/security/syntax gates.
- Release run showing artifact build, Docker smoke, GHCR push, and GitHub release creation.
- Published image pull and smoke evidence.
- Rollback procedure, including local rollback smoke and target-host rollback evidence.
- Secrets review confirming no hardcoded production credentials and production startup rejection for missing/unsafe secrets.
- Continuity map updated with final status.
