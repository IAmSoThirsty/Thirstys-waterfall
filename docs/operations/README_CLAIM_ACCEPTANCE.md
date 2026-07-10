# README Claim Acceptance Matrix

This matrix is the active Standard v3 plan for making the repository satisfy the minimum accepted requirements implied by its README. A claim is accepted only when implementation, tests, docs, and operational evidence agree.

## Acceptance Summary

Status: `in progress`

Current conclusion: the repository now passes the reproducible local Standard v3 deployment verifier, including local Docker rollback and log-capture smoke. It is still not accepted for full deployment under Standard v3 because external CI/release/registry evidence, target-host rollback/log evidence, and real platform backend evidence remain missing.

## Claim Matrix

| README claim | Current status | Evidence now present | Remaining acceptance work |
| --- | --- | --- | --- |
| Complete deployment-accepted ecosystem | Not accepted | `python scripts\verify_production_deployment.py --thirsty-lang-path "T:\00-Active\thirsty_lang_exploration_0754"` passes; README now points to Standard v3 status instead of final deployment readiness; local Docker rollback/log smoke passes | Published image evidence, target production logs, target rollback execution evidence, secrets rotation execution evidence, CI/CodeQL run evidence, and real platform backend evidence |
| Built-in VPN | Partial | VPN backend modules and tests exist; subprocess execution paths are shell-free and command-resolved | Prove real OS integration on supported platforms, document privilege requirements, and separate mocked/backend-availability tests from real integration tests |
| 8 firewall types | Partial | Firewall modules and backend factory tests exist; backend command paths are shell-free and command-resolved | Prove each firewall backend applies and rolls back real rules on its supported OS, or clearly mark unsupported modes |
| Privacy-first incognito browser | Partial | Added native document/parser/fetcher engine layer and compatibility tests | Add layout/rendering/navigation/session behavior acceptance tests; define what "native web engine" includes and excludes |
| Total encryption of all data | Not accepted | Crypto modules and encrypted storage helpers exist | End-to-end proof for stored state, browser data, logs, telemetry, downloads, and transport paths |
| No stubs, placeholders, or TODOs | Not accepted | New continuity map identifies current simulated and placeholder paths | Replace or explicitly reclassify each simulated, placeholder, simplified, and production-substitute path |
| Real backends | Partial | Backend factories exist; some tests exercise backend availability; local Docker web backend starts and serves health/auth | Add real VPN/firewall backend execution evidence and fail-closed handling when required OS tools are absent |
| Comprehensive testing | Partial | Latest full local verifier ran `python -m pytest -q`: 326 tests passed with no pytest warning summary; `python -m pytest tests\test_mfa_auth.py -q -W error::cryptography.utils.CryptographyDeprecationWarning` also passes | Validate the same suite in CI on Linux, Windows, and macOS |
| CI/CD pipeline | Partial | CI test install path now includes `.[test,web]`; flake8 syntax gate is hard; Bandit/Safety no longer swallow failures; Python matrix is now 3.9-3.11; release Docker smoke now tests the loaded release image tag without rebuilding; PyPI publish no longer uses `continue-on-error` | Validate GitHub Actions on all claimed OS/Python combinations and collect release-run evidence |
| Security audits | Partial | Full-repo Bandit passes with 0 findings; deployment lock vulnerability check passes with 0 vulnerabilities and 0 ignored vulnerabilities | Collect GitHub-hosted CodeQL/security workflow evidence and review release workflow gates |
| Web API production authentication | Partial | Default hardcoded `admin/admin` login removed; password-hash auth added; fail-closed tests added; production import rejects missing secrets, wildcard CORS, and demo login; local and container production-mode login smoke pass with explicit secrets | Add operator setup docs, token revocation/session policy, and target secret rotation execution evidence |
| Thirsty-Lang / sovereign startup integration | Partial | Optional bridge loads local enhanced `utf.tarl` from `T:\00-Active\thirsty_lang_exploration_0754`; local and container health smoke report backend `thirsty-lang` when mounted | Define full governance contract, policy source, denial handling, proof persistence, and CI-safe integration strategy |
| Docker deployment | Partial | Verifier builds `thirstys-waterfall:codex-verify`, runs container health/auth/log smoke locally with redacted secret command logging, tags `thirstys-waterfall:codex-verify-rollback-good`, and runs local rollback health/auth/log smoke; release workflow now loads, smoke-tests, and pushes the verified image tag to GHCR; latest locally verified image is `sha256:5d3596d064337f9ebc9c972bb4d4facfecac4c25d5197ea5535671c14e4ed032` | Run release workflow, verify published image digest, registry pull, target rollback, non-local secret injection, target logs, and production host/network policy |
| Cross-platform support | Not accepted | CI matrix declares Linux, Windows, and macOS on Python 3.9-3.11 | Prove platform-specific install/runtime behavior and document platform capability differences |

## Immediate Completion Plan

1. Replace web static demo/placeholder behavior or mark the web UI as development-only until complete.
2. Convert simulated implementation paths into real backends or adjust the README claim language.
3. Execute rollback and secret rotation procedure against the target deployment and capture target logs.
4. Run the hardened release workflow and attach the release-run evidence.
5. Run GitHub Actions and attach CI, CodeQL, and release evidence to this matrix.

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
- Rollback procedure, including local rollback smoke and target-host rollback evidence.
- Secrets review confirming no hardcoded production credentials and production startup rejection for missing/unsafe secrets.
- Continuity map updated with final status.
