# Thirstys Waterfall Continuity Map

Standard: Thirsty's Standard v3

Repo: `C:\Users\Quencher\Documents\Codex\2026-07-09\iamsothirsty-thirstys-waterfall-https-github-com\work\tw-src`

Remote: `https://github.com/IAmSoThirsty/Thirstys-waterfall.git`

Branch: `main`

Baseline HEAD: `0158ec8a114c137cc14d30c6e3a777a95bf2d15f`

Local enhanced Thirsty-Lang source: `T:\00-Active\thirsty_lang_exploration_0754`

Review date: 2026-07-10 America/Denver

## Current Mode

This is a repair and completion pass, not a report-only pass. The target is to make the repository satisfy the minimum accepted requirements implied by the README claims under Standard v3.

## Standard v3 Operating Rules Applied

- Do not claim production readiness without passing evidence.
- Current problems are current problems, even when they existed at baseline.
- README claims must map to implemented code, tests, CI, docs, and operational proof.
- Keep continuity state inside the repo for multi-step work.
- Optional local dependencies must fail explicitly and must not crash imports.
- Production deployment mode requires source, tests, docs, config, continuity, deployment assets, production checks, and rollback path.
- Runtime behavior, command output, logs, and test results override intent-only documentation.

## Work Completed In This Pass

- Added a first native web-engine layer under `thirstys_waterfall/browser/engine/` with document nodes, HTML parsing, URL fetching, and browser-engine integration.
- Added tests for native engine behavior and browser compatibility.
- Replaced the old local governance import path with `thirstys_waterfall.sovereign_binding`.
- Removed the old fallback from `sovereign_binding`; only enhanced `utf.tarl` is supported now.
- Added support for the enhanced local Thirsty-Lang checkout through `THIRSTY_LANG_PATH` / `THIRSTY_LANG_REPO`.
- Verified the local `utf.tarl` backend can load from `T:\00-Active\thirsty_lang_exploration_0754` and allow `INIT_PROTOCOL` with proof output.
- Fixed console entrypoint exposure by adding `thirstys_waterfall.cli:main`.
- Added web app import and health smoke tests.
- Added a `web` optional dependency extra matching the web application runtime.
- Updated vulnerable web dependency pins to patched version ranges.
- Replaced the web API's default `admin/admin` login with fail-closed password-hash authentication.
- Hardened CI syntax/test/security gates so scanners are not silently ignored.
- Aligned Python package metadata and CI matrix to Python 3.10+ because the patched Flask-Limiter web stack requires Python 3.10 or newer.
- Cleared full-repo Bandit findings by removing shell execution paths, resolving OS command paths, replacing non-cryptographic random use in anonymity/security-adjacent modules, and documenting bounded subprocess use.
- Added `requirements-deploy.lock` as the exact dependency set used for deployment verification.
- Tightened the `cryptography` dependency floor to `>=46.0.7,<50.0.0` after Safety reported vulnerable versions allowed by the old range.
- Hardened Docker deployment: locked dependency install, fail-closed package install, normalized Linux shell script line endings, removed production source bind mounts, and switched Compose health checks to `/health`.
- Verified local web startup and Docker container startup with enhanced Thirsty-Lang mounted read-only.
- Added `scripts/verify_production_deployment.py` as the reproducible Standard v3 local deployment verification gate.
- Added `docs/operations/PRODUCTION_DEPLOYMENT_VERIFICATION.md` with verification, rollback, secret rotation, and remaining external evidence requirements.
- Reconciled README and public deployment/showcase docs so they no longer claim final production readiness beyond the accepted evidence.
- Added this continuity map and the README claim acceptance matrix.
- Removed MFA certificate datetime deprecation warnings by using timezone-aware certificate validity properties when available.

## Verification Evidence Collected

- `python -m pytest tests/test_native_web_engine.py tests/test_browser.py -q` passed earlier in this pass: 39 tests passed.
- `python -m pytest -q` passed earlier in this pass before the web-auth additions: 315 tests passed.
- `python -m compileall -q thirstys_waterfall tests` passed earlier in this pass.
- `python -m pip wheel . --no-deps -w ..\wheelhouse` passed earlier in this pass and included the new engine package files.
- `python -m pip install -e ".[dev,web]" rich==14.3.3 python-dotenv==1.2.2` succeeded after dependency correction.
- `python -m pip check` passed after installing the final web/dev dependency set.
- `python -m pytest tests/test_web_app_import.py tests/test_entrypoints.py -q` passed earlier: 8 tests passed.
- `python -m pytest -q` passed inside the latest full deployment verifier run: 326 tests passed with no pytest warning summary after the MFA datetime fix and production web import coverage.
- `python -m pytest tests\test_mfa_auth.py -q -W error::cryptography.utils.CryptographyDeprecationWarning` passed after the MFA datetime fix: 28 tests passed with cryptography deprecations treated as errors.
- `python -m compileall -q thirstys_waterfall tests web` passed after the latest edits.
- `python -m pip wheel . --no-deps -w ..\wheelhouse` passed after the latest edits; latest wheel hash reported by pip build was `686739c702a906335beac62e12520269d993ae9b57608e55eaf30e2f1fb02864`.
- `flake8 thirstys_waterfall/ web/ tests/ --count --select=E9,F63,F7,F82 --show-source --statistics` passed with `0`.
- `bandit -r thirstys_waterfall/ -q -f json -o ..\bandit-current-cleancheck.json` passed with 0 findings.
- `safety check -r requirements-deploy.lock --json` passed with 12 packages scanned, 0 vulnerabilities, and 0 ignored vulnerabilities. `safety scan` was tested but was not a drop-in replacement in this environment: it rejects a file target and prompts interactively for project scans.
- `bandit -r thirstys_waterfall/browser/engine -q` passed for the new native engine package.
- With `THIRSTY_LANG_PATH=T:\00-Active\thirsty_lang_exploration_0754`, `get_sovereign_binding_status()` reported backend `thirsty-lang` and `execute_sovereign_protocol({}, "INIT_PROTOCOL")` returned verdict `ALLOW`.
- Local web smoke passed on `127.0.0.1:18081` with `THIRSTY_LANG_PATH=T:\00-Active\thirsty_lang_exploration_0754`: `/health` returned `healthy`, sovereign binding was available with backend `thirsty-lang`, configured admin login succeeded, and default `admin/admin` was rejected.
- `docker compose config` passed after making `.env` optional and removing the obsolete Compose `version` field.
- `docker build -t thirstys-waterfall:codex-verify .` passed after Dockerfile hardening.
- Docker container smoke passed for image `thirstys-waterfall:codex-verify` with the enhanced Thirsty-Lang path mounted read-only: `/health` returned `healthy`, sovereign binding was available with backend `thirsty-lang`, configured admin login succeeded, and default `admin/admin` was rejected.
- `python scripts\verify_production_deployment.py --thirsty-lang-path "T:\00-Active\thirsty_lang_exploration_0754"` passed after the MFA datetime fix. It covered retired-identifier scan, compileall, flake8 syntax/undefined gate, full-repo Bandit, locked dependency vulnerability check, full pytest suite, wheel build, local web smoke, Compose config, Docker build, and Docker container smoke.
- Earlier locally verified Docker image after the MFA datetime fix: `thirstys-waterfall:codex-verify` image ID `sha256:e36a0ec20a1bfab6f6baa0d78775f6015d3d838d3b9176354ff4ab9e9deb3965`, size `158593547` bytes.
- `python scripts\verify_production_deployment.py --skip-docker --skip-tests --thirsty-lang-path "T:\00-Active\thirsty_lang_exploration_0754"` passed after renaming the verifier's retired-identifier scan messages.
- `python scripts\verify_production_deployment.py --skip-tests --thirsty-lang-path "T:\00-Active\thirsty_lang_exploration_0754"` passed after adding Docker log capture and local rollback smoke. It verified current image health/auth/log capture, tagged `thirstys-waterfall:codex-verify-rollback-good`, and verified rollback image health/auth/log capture.
- Full verifier rerun after the local rollback/log documentation update passed: `python scripts\verify_production_deployment.py --thirsty-lang-path "T:\00-Active\thirsty_lang_exploration_0754"`.
- Earlier locally verified Docker image after the full rollback/log verifier run: `thirstys-waterfall:codex-verify` and `thirstys-waterfall:codex-verify-rollback-good` both point to `sha256:72b2b5afca5a821377f5a54a34cbe3734e4664d3340bcc5ef574c2663ff59007`, size `158597599` bytes.
- Added production startup validation in `web/app.py`: production mode now requires explicit runtime signing/authentication/CORS settings, and demo login is rejected in production.
- `python -m pytest tests\test_web_app_import.py -q` passed after adding production secret/CORS/demo-login import tests: 7 tests passed.
- `python scripts\verify_production_deployment.py --skip-docker --skip-tests --thirsty-lang-path "T:\00-Active\thirsty_lang_exploration_0754"` passed after the verifier switched local web smoke to production mode with explicit secrets.
- `python scripts\verify_production_deployment.py --skip-tests --thirsty-lang-path "T:\00-Active\thirsty_lang_exploration_0754"` passed after Docker command logging redacted sensitive runtime environment values; Compose config validation also ran with required production interpolation supplied.
- `python scripts\verify_production_deployment.py --thirsty-lang-path "T:\00-Active\thirsty_lang_exploration_0754"` passed after the redaction and Compose secret-interpolation updates. It covered retired-identifier scan, compileall, flake8 syntax/undefined gate, full-repo Bandit, locked dependency vulnerability check, 326-test pytest suite, wheel build, local production web smoke, Compose config, Docker build, Docker health/auth/log smoke, and local Docker rollback health/auth/log smoke.
- Latest locally verified Docker image after the full post-redaction verifier run: `thirstys-waterfall:codex-verify` and `thirstys-waterfall:codex-verify-rollback-good` both point to `sha256:5d3596d064337f9ebc9c972bb4d4facfecac4c25d5197ea5535671c14e4ed032`, size `158602367` bytes.
- Added `--skip-docker-build` to the Standard v3 verifier so release CI can smoke-test the loaded release image tag instead of rebuilding a separate image.
- Hardened `.github/workflows/release.yml`: Docker Buildx now loads the built release image into the runner before smoke testing, the verifier tests `thirstys-waterfall:${{ steps.version.outputs.version }}` with `--skip-docker-build`, the verified image is pushed to GHCR with version and `latest` tags, and PyPI publish no longer uses `continue-on-error`.
- Rewrote `docs/SHOWCASE.md` and `docs/COMPETITION_COMPARISON.md` as evidence-gated Standard v3 documents instead of broad marketing superiority claims.
- Rewrote high-risk README feature, architecture, platform, security, and comparison language so accepted-looking claims point back to the Standard v3 matrix.

## Known Current Problems

- README and public deployment/showcase/comparison docs now point to Standard v3 evidence instead of claiming final production readiness; remaining target-state capability language is explicitly gated by the matrix.
- Several implementation paths still state they are simulated, simplified, placeholders, or production substitutes.
- CI integration jobs still announce platform integration without installing all real OS-level VPN/firewall dependencies.
- Full-repo Bandit is clean locally and in hosted CI; CodeQL run `29138681694` passed on main for commit `8261b212e1c2d8ecb3ca8adccbb535f2ce30710a`.
- The deploy lock checks clean locally, but transitive dependency locking is limited to the current deployment requirements surface rather than a generated hash-locked lockfile.
- Release workflow run `29138685612` passed for `v1.0.2` and commit `8261b212e1c2d8ecb3ca8adccbb535f2ce30710a`.
- The web UI no longer auto-logs in with `admin/admin`, increments fake privacy counters, or displays fake active VPN/encryption claims for rendered tabs; full native rendering remains incomplete.
- Docker build, container health/auth/log smoke, local rollback smoke, production-mode secret/CORS startup checks, GHCR push, published image pull, and published-image local rollback smoke now pass, but target rollback execution, production secrets rotation, target host network policy, and target environment logs have not been verified.

## Safe Continuation Points

1. Replace or downgrade remaining simulated implementation paths until the README claim matrix is green.
2. Add target rollback, production secrets rotation, target host network policy, and real environment log evidence.
3. Prove real OS VPN/firewall backend execution on supported platforms or narrow the README claims.
4. Continue replacing simulated implementation paths or narrow related claims as each path is inspected.
