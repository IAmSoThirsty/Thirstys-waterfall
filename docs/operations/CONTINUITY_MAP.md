# Thirstys Waterfall Continuity Map

Standard: Thirsty's Standard v3

Repo: `C:\Users\Quencher\Documents\Codex\2026-07-09\iamsothirsty-thirstys-waterfall-https-github-com\work\tw-src`

Remote: `https://github.com/IAmSoThirsty/Thirstys-waterfall.git`

Branch: `main` integration target; current work branch `harden/production-lint-gate`

Baseline HEAD: `176398bfce893abd8607ba578c744eade703c3da`

Local enhanced Thirsty-Lang source: `T:\01-Projects\thirsty_lang_exploration_0754`

Review date: 2026-07-13 America/Denver

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
- Replaced `VPNManager` synthetic protocol endpoints with backend-factory connection attempts; VPN startup now fails closed when no configured backend is available or when backend connection fails.
- Changed orchestrator startup/status reporting so runtime output no longer claims full operation, total encryption, accepted encryption tier, or deployment acceptance without Standard v3 evidence.
- Changed browser startup/status reporting so it no longer claims accepted total browser encryption or native-engine acceptance while helper-only evidence remains partial.
- Replaced encrypted-search placeholder results with an encrypted fail-closed unavailable response when no search backend is configured.
- `python -m pytest tests\test_browser.py -q` passed after the encrypted-search unavailable-response change: 35 tests passed.
- `python -m pytest tests\test_browser.py tests\test_native_web_engine.py tests\test_web_app_import.py -q` passed after the encrypted-search unavailable-response change: 51 tests passed.
- `python -m pytest -q` passed after the encrypted-search unavailable-response change: 339 tests passed.
- `python scripts\verify_production_deployment.py --skip-docker --skip-tests --thirsty-lang-path "T:\00-Active\thirsty_lang_exploration_0754"` passed after restoring the sparse-hidden verifier script with `git checkout --ignore-skip-worktree-bits HEAD -- scripts/verify_production_deployment.py`.
- Replaced `LocalInferenceEngine` simulated model loading and response generation with a fail-closed backend-injection contract.
- `python -m pytest tests\test_local_inference.py -q` passed after the local-inference backend-gating change: 3 tests passed.
- `flake8 thirstys_waterfall\ai_assistant\local_inference.py tests\test_local_inference.py --count --select=E9,F63,F7,F82 --show-source --statistics` passed after the local-inference backend-gating change: 0 findings.
- `python -m pytest -q` passed after the local-inference backend-gating change: 342 tests passed.
- `python scripts\verify_production_deployment.py --skip-docker --skip-tests --thirsty-lang-path "T:\00-Active\thirsty_lang_exploration_0754"` passed after the local-inference backend-gating change and the same sparse-hidden verifier script restore.
- Replaced `RemoteBrowser` simulated server startup and command success with a fail-closed transport-backend contract.
- `python -m pytest tests\test_remote_browser.py -q` passed after the remote-browser backend-gating change: 3 tests passed.
- `flake8 thirstys_waterfall\remote_access\remote_browser.py tests\test_remote_browser.py --count --select=E9,F63,F7,F82 --show-source --statistics` passed after the remote-browser backend-gating change: 0 findings.
- `python -m pytest -q` passed after the remote-browser backend-gating change: 345 tests passed.
- `python scripts\verify_production_deployment.py --skip-docker --skip-tests --thirsty-lang-path "T:\00-Active\thirsty_lang_exploration_0754"` passed after the remote-browser backend-gating change and the same sparse-hidden verifier script restore.
- Replaced `MediaDownloader` simulated completed-download paths with a fail-closed download-backend contract.
- `python -m pytest tests\test_media_downloader.py -q` passed after the media-downloader backend-gating change: 3 tests passed.
- `flake8 thirstys_waterfall\media_downloader\media_engine.py tests\test_media_downloader.py --count --select=E9,F63,F7,F82 --show-source --statistics` passed after the media-downloader backend-gating change: 0 findings.
- `python -m pytest -q` passed after the media-downloader backend-gating change: 348 tests passed.
- `python scripts\verify_production_deployment.py --skip-docker --skip-tests --thirsty-lang-path "T:\00-Active\thirsty_lang_exploration_0754"` passed after the media-downloader backend-gating change and the same sparse-hidden verifier script restore.
- Replaced `RemoteDesktop` simulated connection success with a fail-closed desktop-backend contract.
- `python -m pytest tests\test_remote_desktop.py -q` passed after the remote-desktop backend-gating change: 3 tests passed.
- `flake8 thirstys_waterfall\remote_access\remote_desktop.py tests\test_remote_desktop.py --count --select=E9,F63,F7,F82 --show-source --statistics` passed after the remote-desktop backend-gating change: 0 findings.
- `python -m pytest -q` passed after the remote-desktop backend-gating change: 351 tests passed.
- `python scripts\verify_production_deployment.py --skip-docker --skip-tests --thirsty-lang-path "T:\00-Active\thirsty_lang_exploration_0754"` passed after the remote-desktop backend-gating change and the same sparse-hidden verifier script restore.
- Replaced `FormatConverter` simulated completed-conversion paths with a fail-closed conversion-backend contract.
- `python -m pytest tests\test_format_converter.py -q` passed after the format-converter backend-gating change: 3 tests passed.
- `flake8 thirstys_waterfall\media_downloader\format_converter.py tests\test_format_converter.py --count --select=E9,F63,F7,F82 --show-source --statistics` passed after the format-converter backend-gating change: 0 findings.
- `python -m pytest -q` passed after the format-converter backend-gating change: 354 tests passed.
- `python scripts\verify_production_deployment.py --skip-docker --skip-tests --thirsty-lang-path "T:\00-Active\thirsty_lang_exploration_0754"` passed after the format-converter backend-gating change and the same sparse-hidden verifier script restore.
- Replaced `IncognitoBrowser.download_file()` silent production-substitute behavior with a fail-closed browser-download-backend contract.
- `python -m pytest tests\test_browser.py -q` passed after the browser-download backend-gating change: 38 tests passed.
- `flake8 thirstys_waterfall\browser\browser_engine.py tests\test_browser.py --count --select=E9,F63,F7,F82 --show-source --statistics` passed after the browser-download backend-gating change: 0 findings.
- `python -m pytest -q` passed after the browser-download backend-gating change: 357 tests passed.
- `python scripts\verify_production_deployment.py --skip-docker --skip-tests --thirsty-lang-path "T:\00-Active\thirsty_lang_exploration_0754"` passed after the browser-download backend-gating change and the same sparse-hidden verifier script restore.
- Replaced `SecureTunnel` unconditional tunnel-establishment success with a fail-closed VPN-plus-tunnel-backend contract.
- `python -m pytest tests\test_secure_tunnel.py -q` passed after the secure-tunnel backend-gating change: 5 tests passed.
- `flake8 thirstys_waterfall\remote_access\secure_tunnel.py tests\test_secure_tunnel.py --count --select=E9,F63,F7,F82 --show-source --statistics` passed after the secure-tunnel backend-gating change: 0 findings.
- `python -m pytest -q` passed after the secure-tunnel backend-gating change: 362 tests passed.
- `python scripts\verify_production_deployment.py --skip-docker --skip-tests --thirsty-lang-path "T:\00-Active\thirsty_lang_exploration_0754"` passed after the secure-tunnel backend-gating change and the same sparse-hidden verifier script restore.
- Replaced `GlobalKillSwitch` no-op production-substitute traffic blocking with an evidence-reporting traffic-blocker-backend contract.
- `python -m pytest tests\test_global_kill_switch.py -q` passed after the global-kill-switch backend-gating change: 4 tests passed.
- `flake8 thirstys_waterfall\kill_switch.py tests\test_global_kill_switch.py --count --select=E9,F63,F7,F82 --show-source --statistics` passed after the global-kill-switch backend-gating change: 0 findings.
- `python -m pytest -q` passed after the global-kill-switch backend-gating change: 366 tests passed.
- `python scripts\verify_production_deployment.py --skip-docker --skip-tests --thirsty-lang-path "T:\00-Active\thirsty_lang_exploration_0754"` passed after the global-kill-switch backend-gating change and the same sparse-hidden verifier script restore.
- Replaced VPN `KillSwitch` no-op production-substitute traffic blocking/restoring with evidence-reporting traffic-blocker-backend contracts.
- `python -m pytest tests\test_vpn_kill_switch.py -q` passed after the VPN-kill-switch backend-gating change: 5 tests passed.
- `flake8 thirstys_waterfall\vpn\kill_switch.py tests\test_vpn_kill_switch.py --count --select=E9,F63,F7,F82 --show-source --statistics` passed after the VPN-kill-switch backend-gating change: 0 findings.
- `python -m pytest -q` passed after the VPN-kill-switch backend-gating change: 371 tests passed.
- `python scripts\verify_production_deployment.py --skip-docker --skip-tests --thirsty-lang-path "T:\00-Active\thirsty_lang_exploration_0754"` passed after the VPN-kill-switch backend-gating change and the same sparse-hidden verifier script restore.
- Replaced browser sandbox no-op policy application and placeholder zero resource usage with evidence-reporting policy/resource backend contracts.
- `python -m pytest tests\test_browser.py -q` passed after the browser-sandbox backend-gating change: 43 tests passed.
- `flake8 thirstys_waterfall\browser\sandbox.py tests\test_browser.py --count --select=E9,F63,F7,F82 --show-source --statistics` passed after the browser-sandbox backend-gating change: 0 findings.
- `python -m pytest -q` passed after the browser-sandbox backend-gating change: 376 tests passed.
- `python scripts\verify_production_deployment.py --skip-docker --skip-tests --thirsty-lang-path "T:\00-Active\thirsty_lang_exploration_0754"` passed after the browser-sandbox backend-gating change.
- Replaced VPN DNS/IPv6 leak-protection production substitutes with evidence-reporting DNS backend and leak-detector contracts.
- `python -m pytest tests\test_vpn_dns_protection.py tests\test_vpn_manager.py -q` passed after the VPN-DNS backend-gating change: 11 tests passed.
- `flake8 thirstys_waterfall\vpn\dns_protection.py tests\test_vpn_dns_protection.py --count --select=E9,F63,F7,F82 --show-source --statistics` passed after the VPN-DNS backend-gating change: 0 findings.
- `python -m pytest -q` passed after the VPN-DNS backend-gating change: 383 tests passed.
- `python scripts\verify_production_deployment.py --skip-docker --skip-tests --thirsty-lang-path "T:\00-Active\thirsty_lang_exploration_0754"` passed after the VPN-DNS backend-gating change.
- Replaced advanced-stealth synthetic transport, onion-node, and domain-fronting paths with evidence-reporting backend/provider contracts.
- `python -m pytest tests\test_advanced_stealth.py -q` passed after the advanced-stealth backend-gating change: 4 tests passed.
- `flake8 thirstys_waterfall\network\advanced_stealth.py tests\test_advanced_stealth.py --count --select=E9,F63,F7,F82 --show-source --statistics` passed after the advanced-stealth backend-gating change: 0 findings.
- `python -m pytest -q` passed after the advanced-stealth backend-gating change: 387 tests passed.
- `python scripts\verify_production_deployment.py --skip-docker --skip-tests --thirsty-lang-path "T:\00-Active\thirsty_lang_exploration_0754"` passed after the advanced-stealth backend-gating change.
- Replaced privacy-auditor DNS/IPv6/WebRTC leak-check production substitutes with an evidence-reporting leak-audit-backend contract.
- `python -m pytest tests\test_privacy_auditor.py -q` passed after the privacy-auditor backend-gating change: 4 tests passed.
- `flake8 thirstys_waterfall\privacy\privacy_auditor.py tests\test_privacy_auditor.py --count --select=E9,F63,F7,F82 --show-source --statistics` passed after the privacy-auditor backend-gating change: 0 findings.
- `python -m pytest -q` passed after the privacy-auditor backend-gating change: 391 tests passed.
- `python scripts\verify_production_deployment.py --skip-docker --skip-tests --thirsty-lang-path "T:\00-Active\thirsty_lang_exploration_0754"` passed after the privacy-auditor backend-gating change.
- Replaced hardware-firewall simulated initialization and hardware inspection with an evidence-reporting hardware-backend contract.
- Replaced cloud-firewall simulated cloud nodes, DDoS checks, and static threat-intelligence list with an evidence-reporting cloud-backend contract.
- `python -m pytest tests\test_firewall_hardware_cloud_evidence.py -q` passed after the hardware/cloud firewall backend-gating change: 7 tests passed.
- `flake8 thirstys_waterfall\firewalls\hardware.py thirstys_waterfall\firewalls\cloud.py tests\test_firewall_hardware_cloud_evidence.py --count --select=E9,F63,F7,F82 --show-source --statistics` passed after the hardware/cloud firewall backend-gating change: 0 findings.
- `python -m pytest -q` passed after the hardware/cloud firewall backend-gating change: 398 tests passed.
- `python scripts\verify_production_deployment.py --skip-docker --skip-tests --thirsty-lang-path "T:\00-Active\thirsty_lang_exploration_0754"` passed after the hardware/cloud firewall backend-gating change.
- Replaced encrypted-navigation history search production substitute with a fail-closed encrypted-search-backend contract.
- `python -m pytest tests\test_browser.py -q` passed after the encrypted-navigation search backend-gating change: 46 tests passed.
- `flake8 thirstys_waterfall\browser\encrypted_navigation.py tests\test_browser.py --count --select=E9,F63,F7,F82 --show-source --statistics` passed after the encrypted-navigation search backend-gating change: 0 findings.
- `python -m pytest -q` passed after the encrypted-navigation search backend-gating change: 401 tests passed.
- `python scripts\verify_production_deployment.py --skip-docker --skip-tests --thirsty-lang-path "T:\00-Active\thirsty_lang_exploration_0754"` passed after the encrypted-navigation search backend-gating change.
- Replaced packet-filtering simplified IP matching with standard-library IPv4/IPv6 exact and CIDR matching.
- `python -m pytest tests\test_packet_filtering.py tests\test_basic.py -q` passed after the packet-filter IP matching change: 14 tests passed.
- `flake8 thirstys_waterfall\firewalls\packet_filtering.py tests\test_packet_filtering.py --count --select=E9,F63,F7,F82 --show-source --statistics` passed after the packet-filter IP matching change: 0 findings.
- `python -m pytest -q` passed after the packet-filter IP matching change: 407 tests passed.
- `python scripts\verify_production_deployment.py --skip-docker --skip-tests --thirsty-lang-path "T:\00-Active\thirsty_lang_exploration_0754"` passed after the packet-filter IP matching change.
- Replaced nftables local-only rule removal with comment-tagged rule creation, handle lookup, and OS rule deletion.
- `python -m pytest tests\test_firewall_backends.py -q` passed after the nftables handle-removal change: 37 tests passed.
- `flake8 thirstys_waterfall\firewalls\backends.py tests\test_firewall_backends.py --count --select=E9,F63,F7,F82 --show-source --statistics` passed after the nftables handle-removal change: 0 findings.
- `python -m pytest -q` passed after the nftables handle-removal change: 409 tests passed.
- `python scripts\verify_production_deployment.py --skip-docker --skip-tests --thirsty-lang-path "T:\00-Active\thirsty_lang_exploration_0754"` passed after the nftables handle-removal change.
- Replaced encrypted-network Python stringification and unused extra-layer claim with deterministic JSON payload encryption and explicit payload-only status evidence.
- `python -m pytest tests\test_encrypted_network.py -q` passed after the encrypted-network parsing/scope change: 5 tests passed.
- `flake8 thirstys_waterfall\utils\encrypted_network.py tests\test_encrypted_network.py --count --select=E9,F63,F7,F82 --show-source --statistics` passed after the encrypted-network parsing/scope change: 0 findings.
- `python -m pytest -q` passed after the encrypted-network parsing/scope change: 414 tests passed.
- `python scripts\verify_production_deployment.py --skip-docker --skip-tests --thirsty-lang-path "T:\00-Active\thirsty_lang_exploration_0754"` passed after the encrypted-network parsing/scope change.
- Replaced post-quantum encryption substitute behavior with a fail-closed post-quantum-backend contract and downgraded helper cryptography status to classical unless backend evidence exists.
- `python -m pytest tests\test_god_tier_encryption.py -q` passed after the post-quantum backend-gating change: 3 tests passed.
- `flake8 thirstys_waterfall\utils\god_tier_encryption.py tests\test_god_tier_encryption.py --count --select=E9,F63,F7,F82 --show-source --statistics` passed after the post-quantum backend-gating change: 0 findings.
- `python -m pytest tests\test_god_tier_encryption.py tests\test_orchestrator_status.py tests\test_remote_browser.py tests\test_remote_desktop.py tests\test_secure_tunnel.py tests\test_media_downloader.py tests\test_format_converter.py -q` passed after the post-quantum backend-gating change: 22 tests passed.
- `python -m pytest -q` passed after the post-quantum backend-gating change: 417 tests passed.
- `python scripts\verify_production_deployment.py --skip-docker --skip-tests --thirsty-lang-path "T:\00-Active\thirsty_lang_exploration_0754"` passed after the post-quantum backend-gating change.
- Replaced browser sandbox script execution placeholder behavior with a fail-closed script-executor backend contract and explicit execution status evidence.
- `python -m pytest tests\test_browser.py -q` passed after the browser-sandbox script-executor change: 50 tests passed.
- `flake8 thirstys_waterfall\browser\sandbox.py tests\test_browser.py --count --select=E9,F63,F7,F82 --show-source --statistics` passed after the browser-sandbox script-executor change: 0 findings.
- `python -m pytest -q` passed after the browser-sandbox script-executor change: 421 tests passed.
- `python scripts\verify_production_deployment.py --skip-docker --skip-tests --thirsty-lang-path "T:\00-Active\thirsty_lang_exploration_0754"` passed after the browser-sandbox script-executor change.
- Replaced privacy-risk ML and hardening production-substitute comments with explicit heuristic/model-backend and hardening-backend evidence contracts.
- Fixed privacy-risk threat handling to use a reentrant lock so threat handling can run from locked report/anomaly paths without deadlock.
- `python -m pytest tests\test_privacy_risk_engine.py -q` passed after the privacy-risk backend-evidence change: 6 tests passed.
- `flake8 thirstys_waterfall\security\privacy_risk_engine.py tests\test_privacy_risk_engine.py --count --select=E9,F63,F7,F82 --show-source --statistics` passed after the privacy-risk backend-evidence change: 0 findings.
- `python -m pytest -q` passed after the privacy-risk backend-evidence change: 427 tests passed.
- `python scripts\verify_production_deployment.py --skip-docker --skip-tests --thirsty-lang-path "T:\00-Active\thirsty_lang_exploration_0754"` passed after the privacy-risk backend-evidence change.
- Replaced WiFi deauth monitoring, evil-twin detection, and 802.11r fast-roaming substitute paths with explicit WiFi security backend evidence contracts.
- `python -m pytest tests\test_wifi_security.py -q` passed after the WiFi security backend-evidence change: 6 tests passed.
- `flake8 thirstys_waterfall\wifi_network\wifi_security.py tests\test_wifi_security.py --count --select=E9,F63,F7,F82 --show-source --statistics` passed after the WiFi security backend-evidence change: 0 findings.
- `python -m pytest -q` passed after the WiFi security backend-evidence change: 433 tests passed.
- `python scripts\verify_production_deployment.py --skip-docker --skip-tests --thirsty-lang-path "T:\00-Active\thirsty_lang_exploration_0754"` passed after the WiFi security backend-evidence change. The verifier script had to be restored first with `git checkout --ignore-skip-worktree-bits HEAD -- scripts/verify_production_deployment.py` because sparse checkout hid it locally.
- Replaced WiFi controller empty scan parsers with deterministic Linux `iw`, Windows `netsh`, and macOS `airport` output parsing.
- Replaced WiFi controller connect/disconnect/channel-optimization substitute paths with an explicit WiFi backend evidence contract.
- `python -m pytest tests\test_wifi_controller.py -q` passed after the WiFi controller parser/backend-evidence change: 6 tests passed.
- `flake8 thirstys_waterfall\wifi_network\wifi_controller.py tests\test_wifi_controller.py --count --select=E9,F63,F7,F82 --show-source --statistics` passed after the WiFi controller parser/backend-evidence change: 0 findings.
- `python -m pytest -q` passed after the WiFi controller parser/backend-evidence change: 439 tests passed.
- `python scripts\verify_production_deployment.py --skip-docker --skip-tests --thirsty-lang-path "T:\00-Active\thirsty_lang_exploration_0754"` passed after the WiFi controller parser/backend-evidence change. The verifier script had to be restored first with `git checkout --ignore-skip-worktree-bits HEAD -- scripts/verify_production_deployment.py` because sparse checkout hid it locally.
- Replaced mesh networking interface creation and peer-discovery substitutes with an explicit mesh backend evidence contract.
- Replaced mesh routing and topology optimization placeholders with deterministic route calculation and bottleneck detection over known mesh nodes.
- `python -m pytest tests\test_mesh_networking.py -q` passed after the mesh networking backend/routing change: 5 tests passed.
- `flake8 thirstys_waterfall\wifi_network\mesh_networking.py tests\test_mesh_networking.py --count --select=E9,F63,F7,F82 --show-source --statistics` passed after the mesh networking backend/routing change: 0 findings.
- `python -m pytest -q` passed after the mesh networking backend/routing change: 444 tests passed.
- `python scripts\verify_production_deployment.py --skip-docker --skip-tests --thirsty-lang-path "T:\00-Active\thirsty_lang_exploration_0754"` passed after the mesh networking backend/routing change. The verifier script had to be restored first with `git checkout --ignore-skip-worktree-bits HEAD -- scripts/verify_production_deployment.py` because sparse checkout hid it locally.
- Reworded MFA FIDO2 signature verification to state the built-in verifier's DER-encoded RSA/ECDSA scope instead of implying full WebAuthn/COSE coverage.
- Replaced biometric similarity substitute behavior with an exact-hash fallback plus optional biometric matcher backend evidence.
- Reworded the TOTP provisioning helper so it reports a base64 provisioning URI payload, not generated QR image data.
- `python -m pytest tests\test_mfa_auth.py -q` passed after the MFA evidence-language change: 31 tests passed.
- `flake8 thirstys_waterfall\security\mfa_auth.py tests\test_mfa_auth.py --count --select=E9,F63,F7,F82 --show-source --statistics` passed after the MFA evidence-language change: 0 findings.
- `python -m pytest -q` passed after the MFA evidence-language change: 447 tests passed.
- `python scripts\verify_production_deployment.py --skip-docker --skip-tests --thirsty-lang-path "T:\00-Active\thirsty_lang_exploration_0754"` passed after the MFA evidence-language change. The verifier script had to be restored first with `git checkout --ignore-skip-worktree-bits HEAD -- scripts/verify_production_deployment.py` because sparse checkout hid it locally.
- Replaced microVM default boot-asset assumptions with explicit kernel/rootfs validation evidence before launch.
- Replaced microVM non-isolated TAP/network setup and cleanup substitute paths with a platform-backend evidence contract.
- Replaced microVM pause/resume local state flips with platform-backend control evidence requirements.
- Replaced microVM simulated health metrics with either backend-collected metrics or explicit process-liveness-only evidence.
- `python -m pytest tests\test_microvm_isolation.py -q` passed after the microVM evidence-contract change: 42 tests passed.
- `flake8 thirstys_waterfall\security\microvm_isolation.py tests\test_microvm_isolation.py --count --select=E9,F63,F7,F82 --show-source --statistics` passed after the microVM evidence-contract change: 0 findings.
- `python -m pytest -q` passed after the microVM evidence-contract change: 454 tests passed.
- `python scripts\verify_production_deployment.py --skip-docker --skip-tests --thirsty-lang-path "T:\00-Active\thirsty_lang_exploration_0754"` passed after the microVM evidence-contract change. The verifier script had to be restored first with `git checkout --ignore-skip-worktree-bits HEAD -- scripts/verify_production_deployment.py` because sparse checkout hid it locally.
- Replaced hardware-root TPM, Secure Enclave, and HSM accepted-looking substitute initialization with backend-evidence requirements; default local operation now reports explicit `software_fallback`.
- Added operation evidence for hardware-root key storage, retrieval, deletion, attestation, sealing, and unsealing paths, separating hardware-backed backend results from software-emulated fallback results.
- Tightened TPM software seal/unseal behavior so the fallback records and rechecks the local PCR policy before returning sealed data.
- `python -m pytest tests\test_hardware_root_of_trust.py -q` passed after the hardware-root evidence-contract change: 27 tests passed.
- `flake8 thirstys_waterfall\security\hardware_root_of_trust.py tests\test_hardware_root_of_trust.py --count --select=E9,F63,F7,F82 --show-source --statistics` passed after the hardware-root evidence-contract change: 0 findings.
- `python -m pytest -q` passed after the hardware-root evidence-contract change: 459 tests passed.
- `python scripts\verify_production_deployment.py --skip-docker --skip-tests --thirsty-lang-path "T:\00-Active\thirsty_lang_exploration_0754"` passed after the hardware-root evidence-contract change. The verifier script had to be restored first with `git checkout --ignore-skip-worktree-bits HEAD -- scripts/verify_production_deployment.py` because sparse checkout hid it locally.
- Reworded the DOS trap module from production-grade to evidence-gated.
- Replaced Windows syscall-table fake SSDT hashing with explicit unavailable evidence unless a Windows kernel backend is configured.
- Replaced HSM key-destruction substitute success with enumerable-backend/key-list requirements and destruction evidence.
- `python -m pytest tests\test_dos_trap.py -q` passed after the DOS trap evidence-contract change: 35 tests passed.
- `flake8 thirstys_waterfall\security\dos_trap.py tests\test_dos_trap.py --count --select=E9,F63,F7,F82 --show-source --statistics` passed after the DOS trap evidence-contract change: 0 findings.
- `python -m pytest -q` passed after the DOS trap evidence-contract change: 462 tests passed.
- `python scripts\verify_production_deployment.py --skip-docker --skip-tests --thirsty-lang-path "T:\00-Active\thirsty_lang_exploration_0754"` passed after the DOS trap evidence-contract change. The verifier script had to be restored first with `git checkout --ignore-skip-worktree-bits HEAD -- scripts/verify_production_deployment.py` because sparse checkout hid it locally.
- Core source marker scan passed across `thirstys_waterfall\firewalls`, `thirstys_waterfall\wifi_network`, `thirstys_waterfall\security`, `thirstys_waterfall\browser`, and `thirstys_waterfall\utils`: `rg -n "Would|would|simulate|simulated|simplified|placeholder|TODO|production|quantum-resistant" thirstys_waterfall\firewalls thirstys_waterfall\wifi_network thirstys_waterfall\security thirstys_waterfall\browser thirstys_waterfall\utils -g "*.py"` returned no matches.
- Replaced the web browser-tabs API placeholder state path with active browser runtime/tab-manager evidence; inactive or unavailable browser runtime now returns `503` with explicit unavailable evidence.
- The browser-tabs API now serializes only non-sensitive tab metadata and does not expose tab storage, cookies, or history.
- `python -m pytest tests\test_web_app_import.py -q` passed after the web browser-tabs evidence-contract change: 12 tests passed.
- `flake8 web\app.py tests\test_web_app_import.py --count --select=E9,F63,F7,F82 --show-source --statistics` passed after the web browser-tabs evidence-contract change: 0 findings.
- `python -m pytest -q` passed after the web browser-tabs evidence-contract change: 464 tests passed.
- `python scripts\verify_production_deployment.py --skip-docker --skip-tests --thirsty-lang-path "T:\00-Active\thirsty_lang_exploration_0754"` passed after the web browser-tabs evidence-contract change; wheel sha256 was `f7fadf8561bc09872523f34bccf976e581a979e0a08e85679a13c0c6da05ddaa`, and local web smoke reported `backend=thirsty-lang`.
- Touched-file marker scan passed after the web browser-tabs evidence-contract change: `rg -n "placeholder|simulated|simplified|production-grade|Would|would" web\app.py tests\test_web_app_import.py` returned no matches.
- Reworded DOS trap, MFA, network-stealth, privacy-ledger, and example/demo docs from final/production/simulation language to evidence-gated or example-only language.
- `rg -n "production-grade|simulated|simplified|placeholder|Would|would" docs\DOS_TRAP_MODE.md docs\mfa_authentication.md docs\network_stealth.md docs\SHOWCASE.md examples\privacy_ledger_examples.py examples\dos_trap_demo.py examples\mfa_authentication_example.py` returned no matches after the docs/examples claim-hygiene change.
- `python -m compileall -q examples` passed after the docs/examples claim-hygiene change.
- `python -m pytest tests\test_public_claim_hygiene.py -q` passed after the docs/examples claim-hygiene change: 2 tests passed.
- `python scripts\verify_production_deployment.py --skip-docker --skip-tests --thirsty-lang-path "T:\00-Active\thirsty_lang_exploration_0754"` passed after the docs/examples claim-hygiene change; wheel sha256 was `64491b22c320e1b00dd59464f5de06452ef5999ace1b99cd42734a7d082451c4`, and local web smoke reported `backend=thirsty-lang`.
- Fixed integrated-spec unsafe capability exception expiration so `duration` is applied as seconds instead of being ignored.
- Replaced remaining Python source claim-marker comments/status fields in local AI, anti-fingerprint, anti-phishing, and VPN kill-switch surfaces with evidence-gated wording or status.
- Local AI responses/status now report local helper encryption and `encryption_accepted: False` instead of accepted-looking encryption-tier claims.
- Anti-fingerprint status now reports spoofing/canvas/WebGL protections as active only when the engine is active.
- `rg -n "production-grade|simulated|simplified|placeholder|quantum-resistant|god_tier_encrypted|encryption_layers\": 7|Would|would" . -g "*.py" --glob "!htmlcov/**" --glob "!*.egg-info/**" --glob "!dist/**" --glob "!build/**" --glob "!node_modules/**" --glob "!__pycache__/**"` returned no matches after the Python marker-hygiene change.
- `python -m pytest tests\test_python_marker_hygiene.py tests\test_vpn_kill_switch.py tests\test_browser.py::TestIncognitoBrowser::test_fingerprint_protection_status -q` passed after the Python marker-hygiene change: 9 tests passed.
- `python -m pytest -q` passed after the Python marker-hygiene change: 467 tests passed.
- `python scripts\verify_production_deployment.py --skip-docker --skip-tests --thirsty-lang-path "T:\00-Active\thirsty_lang_exploration_0754"` passed after the Python marker-hygiene change; wheel sha256 was `2d5c5a57e42a64a4e9c645f50e6bab8ada1774a8158a04f61333a024ccc04e53`, and local web smoke reported `backend=thirsty-lang`.
- Added a deployment-verifier claim-marker gate covering current source, tests, examples, selected docs, README, and web/static surfaces.
- Replaced remaining settings, media downloader, remote-access, consigliere, README, and integrated-spec accepted-looking claim markers caught by that gate with evidence-gated status fields and wording.
- `python scripts\verify_production_deployment.py --skip-docker --skip-tests --thirsty-lang-path "T:\00-Active\thirsty_lang_exploration_0754"` passed after adding the claim-marker verifier gate; local web smoke reported `backend=thirsty-lang`.
- `python -m pytest tests\test_browser.py::TestEncryptedSearchEngine::test_search_without_backend_returns_encrypted_unavailable_payload tests\test_privacy_ledger.py tests\test_python_marker_hygiene.py -q` passed after the claim-marker verifier gate: 29 tests passed.
- `python -m pytest tests\test_media_downloader.py tests\test_format_converter.py tests\test_remote_browser.py tests\test_remote_desktop.py tests\test_secure_tunnel.py tests\test_consigliere.py -q` passed after the claim-marker verifier gate: 51 tests passed.
- Added deterministic native-engine layout snapshots and ephemeral tab session snapshots for browser acceptance evidence.
- `python -m pytest tests\test_native_web_engine.py tests\test_browser.py -q` passed after the native layout/session change: 58 tests passed.
- `python scripts\verify_production_deployment.py --skip-docker --skip-tests --thirsty-lang-path "T:\00-Active\thirsty_lang_exploration_0754"` passed after the native layout/session change; local web smoke reported `backend=thirsty-lang`.
- Added deterministic local HTTP navigation coverage for the native web engine with network mode enabled.
- Changed the local deployment verifier wheel build to use the prepared verifier environment without build isolation after isolated `pip wheel` repeatedly timed out while direct setuptools wheel creation passed.
- Reclassified package metadata from stable to beta and removed stale package setup wording.
- `python -m pytest tests\test_native_web_engine.py -q` passed after the local network-navigation change: 9 tests passed.
- `python scripts\verify_production_deployment.py --skip-docker --skip-tests --thirsty-lang-path "T:\00-Active\thirsty_lang_exploration_0754"` passed after the local network-navigation and verifier wheel-build change; wheel sha256 was `57d6e4c64295be6589acef06a1a250e9ed97fc521339b20bb42febe4ea5e7274`, and local web smoke reported `backend=thirsty-lang`.
- `python -m pytest -q` passed after the local network-navigation and verifier wheel-build change: 470 tests passed.
- Added settings export/import encryption evidence tests and narrowed stale local-helper encryption wording in code and docs.
- `python -m pytest tests\test_settings_manager.py tests\test_god_tier_encryption.py tests\test_web_app_import.py tests\test_python_marker_hygiene.py -q` passed after the settings/local-helper encryption evidence change: 22 tests passed.
- `python scripts\verify_production_deployment.py --skip-docker --skip-tests --thirsty-lang-path "T:\00-Active\thirsty_lang_exploration_0754"` passed after expanding the claim-marker verifier gate to local-helper encryption wording; wheel sha256 was `fbfbcefb0b43f7e47e4fbeec4ee68b6030657954c40f94104ee8f02c9c5d6cfd`, and local web smoke reported `backend=thirsty-lang`.
- `python -m pytest -q` passed after the settings/local-helper encryption evidence change: 474 tests passed.
- `python -m pytest -q` passed after adding platform capability reporting: 486 tests passed.
- `python scripts\verify_production_deployment.py --skip-docker --skip-tests --thirsty-lang-path "T:\00-Active\thirsty_lang_exploration_0754"` passed after adding platform capability reporting; local web smoke reported `backend=thirsty-lang`.
- Encryption data-surface coverage is now mapped through `thirstys_waterfall.get_encryption_evidence_report()` and `docs/operations/ENCRYPTION_EVIDENCE_MAP.md`; full encryption acceptance remains false until all accepted stored-state, browser-data, telemetry, download, transport, target-log, and post-quantum surfaces have end-to-end proof.
- Target deployment evidence now has a fail-closed manifest validator in `scripts/verify_target_deployment_evidence.py`; full production acceptance still requires executing the target deployment and attaching artifacts for every required evidence type.
- The main production verifier now accepts `--target-evidence-manifest` and `--require-target-evidence`, so target-host acceptance can fail closed when the required evidence bundle is missing.
- Target deployment evidence now has a bundle collector in `scripts/collect_target_deployment_evidence.py`; missing artifact types remain `pending` in the generated manifest until target proof is attached, including shared JWT revocation-store proof.
- Target deployment evidence now has a package/audit command in `scripts/package_target_deployment_evidence.py`; it validates the manifest before copying declared artifacts and writing a package manifest.
- Added a configured local browser download backend that stores downloaded bytes as Fernet ciphertext while keeping network downloads disabled by default unless explicitly enabled.
- Privacy auditor local event storage now keeps encrypted audit records internally and decrypts them only for caller access.
- Web API token revocation now supports a configured SQLite revocation store through `JWT_REVOCATION_DB_PATH`, while target acceptance still requires evidence that every worker/container uses the same store.

## Known Current Problems

- README and public deployment/showcase/comparison docs now point to Standard v3 evidence instead of claiming final production readiness; remaining target-state capability language is explicitly gated by the matrix.
- The deployment verifier now gates claim-marker regressions across current source, tests, examples, selected docs, README, and web/static surfaces; newly added surfaces still need to be added to the gate when they become part of accepted claims.
- Platform capability differences are now documented through `thirstys_waterfall.get_platform_capabilities()` and `docs/operations/PLATFORM_CAPABILITIES.md`, but the report intentionally returns `production_accepted: false` until real OS-level VPN/firewall apply/rollback, privilege, service, and target-log evidence exists.
- CI integration jobs still announce platform integration without installing all real OS-level VPN/firewall dependencies.
- Full-repo Bandit is clean locally and in hosted CI; CodeQL run `29226577880` passed on main for commit `a83c9dc940d40409a5c9531864b07521d735b13b`.
- The deploy lock checks clean locally, but transitive dependency locking is limited to the current deployment requirements surface rather than a generated hash-locked lockfile.
- Release workflow run `29226584539` passed for `v1.0.3` and commit `a83c9dc940d40409a5c9531864b07521d735b13b`.
- The web UI no longer auto-logs in with `admin/admin`, increments fake privacy counters, or displays fake active VPN/encryption claims for rendered tabs; full native rendering remains incomplete.
- The web browser-tabs API no longer fabricates tabs from local `system_state`, but it still requires an active configured browser runtime for tab listing and creation.
- `VPNManager` no longer reports synthetic protocol endpoints as connected, but real VPN backend execution on supported operating systems still needs target evidence.
- Global kill switch no longer implies all traffic was blocked without a backend, but no real global traffic blocker backend is bundled or configured.
- VPN kill switch no longer implies traffic block/restore without a backend, but no real VPN traffic blocker backend is bundled or configured.
- Browser sandbox no longer reports policy enforcement or zero/within-limit resource usage without configured backends, but no real browser sandbox policy backend or resource monitor is bundled or configured.
- Browser sandbox no longer reports script execution without a configured script-executor backend, but no real sandboxed JavaScript execution backend is bundled or configured.
- Privacy risk engine now reports heuristic analysis unless a real model backend is configured, and hardening actions report unavailable unless a hardening backend is configured.
- WiFi security no longer reports deauth monitoring, evil-twin detection, or 802.11r fast-roaming configuration success without a configured WiFi security backend. PMF-only deauth protection is reported separately from active monitoring evidence.
- WiFi controller now parses platform scan output into network records, but actual connect/disconnect/channel optimization still require a configured WiFi backend.
- Mesh networking now calculates local routes and bottlenecks from known topology, but actual mesh interface creation and peer discovery still require a configured mesh backend.
- MFA FIDO2 verification is limited to DER-encoded RSA/ECDSA public keys in the built-in verifier; full WebAuthn COSE attestation/verification, native biometric matching, and image QR generation still require configured or future backends.
- MicroVM isolation now fails closed when boot assets are missing and no longer reports non-isolated networking, pause/resume control, or health metrics beyond process liveness without a configured platform backend.
- Hardware root-of-trust now reports `software_fallback` unless a configured TPM, Secure Enclave, or HSM backend provides concrete hardware evidence; no real TPM, Secure Enclave, HSM, PKCS#11, or CloudHSM backend is bundled or configured.
- DOS trap Windows syscall-table hashing now reports unavailable unless a configured Windows kernel backend provides evidence; HSM key destruction now requires enumerable HSM backend/key-list evidence before reporting destruction success.
- VPN DNS/IPv6 leak protection no longer reports DNS changes or leak-free verification without configured DNS and leak-detector backends, but no real DNS protection backend or leak detector is bundled or configured.
- Advanced stealth no longer activates synthetic transports, fabricated onion nodes, or fabricated domain fronts without configured backends/providers, but no real advanced-stealth transport backend, node provider, or domain-fronting backend is bundled or configured.
- Privacy auditor no longer reports DNS/IPv6/WebRTC leak checks as passed without a configured leak-audit backend, but no real privacy leak-audit backend is bundled or configured.
- Hardware and cloud firewalls no longer report hardware/cloud packet protection without configured backends, but no real hardware firewall backend or cloud firewall backend is bundled or configured.
- Encrypted navigation no longer reports empty history-search results from a production substitute when no encrypted-search backend is configured, but no real encrypted-navigation search backend is bundled or configured.
- Packet-filtering firewall now uses standard-library IPv4/IPv6 exact and CIDR matching instead of simplified string matching.
- Nftables rule removal now looks up and deletes concrete OS rule handles instead of only updating local tracking state.
- Encrypted-network helper now parses structured JSON payloads and reports payload-only scope instead of claiming unused extra encryption layers or host-wide interception.
- Post-quantum encryption no longer uses classical AES/Scrypt as a substitute implementation; no real post-quantum backend is bundled or configured.
- Orchestrator status is now evidence-gated, but downstream docs and examples may still need continued narrowing as simulated modules are replaced.
- Browser status is now evidence-gated, and native layout, local network navigation, plus ephemeral session snapshots are covered by tests; broader rendering and supported-site acceptance evidence remain incomplete.
- Total-encryption evidence is now mapped by data surface, but telemetry outside the privacy auditor, target download lifecycle behavior, target production logs, persisted state inspection, transport coverage, and post-quantum backend proof remain incomplete.
- Browser downloads now have a configured local encrypted backend when `download_storage_path` is supplied, but target-host storage lifecycle, cleanup, and retention evidence remain incomplete.
- Encrypted search no longer fabricates placeholder results, but a real encrypted search backend is still not implemented.
- Local inference no longer fabricates AI responses without a backend, but no real local inference backend is bundled or configured.
- Remote browser no longer fabricates remote server/session command success without a backend, but no real remote-browser transport backend is bundled or configured.
- Remote desktop no longer fabricates connection success without a backend, but no real remote-desktop backend is bundled or configured.
- Secure tunnel no longer fabricates tunnel establishment without connected VPN evidence and a backend, but no real secure-tunnel backend is bundled or configured.
- Media downloader no longer fabricates completed downloads without a backend, but no real media download backend is bundled or configured.
- Format converter no longer fabricates completed conversions without a backend, but no real media conversion backend is bundled or configured.
- Docker build, container health/auth/log smoke, local rollback smoke, production-mode secret/CORS startup checks, GHCR push, published image pull, and published-image local rollback smoke now pass for `v1.0.3`; production TLS reverse-proxy config validation passes; a local Docker target manifest now validates published image pull/run, health/auth/logs, target rollback, secret rotation, shared revocation store, host network policy, service/orchestrator hardening, and narrowed platform-backend evidence; the local evidence bundle can be packaged with package-level hashes. External/public target logs, live TLS/proxy boundary, external service/orchestrator hardening, and real OS VPN/firewall backend execution still have not been captured.

## Safe Continuation Points

1. Replace or downgrade remaining simulated implementation paths until the README claim matrix is green.
2. Add external/public target logs, live TLS/proxy boundary evidence, external service/orchestrator hardening, and real OS backend evidence or narrowed production claims.
3. Prove end-to-end encryption for stored state, browser data, telemetry, downloads, transport paths, target logs, and any accepted post-quantum backend.
4. Prove real OS VPN/firewall backend execution, privilege behavior, service setup, and rollback on Linux, Windows, and macOS, or narrow the README claims.

## 2026-07-13 Production Lint And Typed Tooling Update

### Current State

- Full Flake8 validation is now a hard CI and production-verifier gate; the
  former advisory `--exit-zero` command was removed.
- The 19 non-complexity findings exposed by that gate were fixed. Complexity
  notices remain outside the configured lint contract and are not represented
  as passing complexity analysis.
- Mypy now checks all 13 modules under `scripts/` with untyped function bodies
  checked. It is pinned to `>=1.11,<2.0` for CI reproducibility.
- Timeout evidence paths now normalize partial `bytes` or `str` output before
  constructing string-only command results.
- User-facing Q/A text no longer promises guaranteed kill-switch or universal
  ad-blocking outcomes without backend evidence.

### Files Modified

- `.github/workflows/ci.yml`
- `pyproject.toml`
- `scripts/*.py` production deployment and target-evidence tooling
- `tests/test_consigliere.py`
- `tests/test_probe_target_image_evidence.py`
- `tests/test_production_proxy_config.py`
- `tests/test_settings_manager.py`
- `tests/test_target_evidence_probes.py`
- Narrow lint corrections in `thirstys_waterfall/` and `web/app.py`
- This continuity map and deployment acceptance documentation

### Commands And Verification

- `flake8 scripts/ thirstys_waterfall/ web/ tests/ --count --max-line-length=127 --statistics`: passed with `0` findings.
- `python -m mypy`: passed, 13 script modules checked.
- `uvx --from mypy==1.19.1 mypy`: passed, 13 script modules checked under the pinned CI-compatible version.
- `python -m pytest tests\test_target_evidence_probes.py tests\test_production_proxy_config.py tests\test_probe_target_image_evidence.py -q`: 21 passed.
- Split validation after the original 120-second combined timeout: 59 evidence/Wi-Fi/consigliere tests passed, 31 MFA tests passed, and 16 web import/auth tests passed.
- `python scripts\verify_production_deployment.py --thirsty-lang-path "T:\00-Active\thirsty_lang_exploration_0754"`: passed in 395.8 seconds after the timeout repair; 541 tests passed, wheel build passed, local web smoke passed, Docker build/health/auth/log smoke passed, and Docker rollback smoke passed.
- `python scripts\verify_production_deployment.py --skip-tests --skip-docker-build --image thirstys-waterfall:codex-verify --thirsty-lang-path "T:\00-Active\thirsty_lang_exploration_0754"`: passed after UTF-8 subprocess decoding was added; no reader-thread exception occurred.
- `python scripts\verify_production_proxy_config.py --compose-file docker-compose.production.yml --caddyfile deploy\caddy\Caddyfile`: passed 15/15 checks.
- `python scripts\verify_production_deployment.py --skip-docker --skip-tests --require-target-evidence --target-evidence-manifest evidence\target-deployment\local-docker-v1.0.3-20260713T070000Z\target-evidence.json --thirsty-lang-path "T:\00-Active\thirsty_lang_exploration_0754"`: passed when rerun sequentially.

### Known Failures And Risks

- The first combined targeted pytest command timed out after 124 seconds with
  no test failure output. Splitting the same surfaces completed successfully.
- The first full verifier run on this branch reached the former 240-second
  pytest subprocess limit before Docker. The verifier now defaults that bounded
  full-suite limit to 480 seconds and accepts an explicit positive
  `--test-timeout` override.
- The next full verifier run passed 541 tests, package build, local web smoke,
  Docker build/health/auth/log smoke, and rollback in 395.8 seconds, then a
  Windows subprocess reader emitted a CP1252 `UnicodeDecodeError`. Text-mode
  verifier subprocesses now decode as UTF-8 with replacement so undecodable
  tool output cannot raise a background reader exception.
- Two verifier instances run in parallel collided in the shared setuptools
  `build/` directory and one wheel build failed. The strict target-evidence
  verifier passed when rerun alone. Concurrent verifier execution remains
  unsupported and is not represented as verified.
- Whole-runtime mypy validation is not yet accepted. The local mypy 2.1 build
  raised an internal error while scanning `thirstys_waterfall` and `web`; the
  hard gate currently covers production deployment/evidence tooling only.
- External/public deployment evidence remains missing as documented above.

### Pending Work

- Extend type checking to the application runtime in staged, explicit surfaces.
- Obtain an external host/DNS/secrets boundary and capture the required public
  target evidence bundle.

### Safe To Continue

Yes. The current work is reversible and does not alter external deployment
state or production credentials.

## 2026-07-13 Core Runtime Type-Check Foundation

### Current State

- The hard mypy gate now checks 22 explicitly enrolled files: all 13
  deployment/evidence scripts plus nine core runtime files covering platform
  capability reporting, enhanced Thirsty-Lang binding, the native browser
  engine, and the configuration registry.
- The enrolled runtime contracts now type optional fetch policies, HTTP status
  values, HTML attributes, and encryption salts accurately.
- Imported runtime modules are not implicitly accepted. `follow_imports =
  "skip"` keeps the gate scoped to the explicit file manifest under both mypy
  1.19 and 2.1; remaining modules must be enrolled in later increments.

### Commands And Verification

- `python -m mypy --no-incremental`: passed, 22 files checked with mypy 2.1.
- `uvx --from mypy==1.19.1 mypy --no-incremental`: passed, 22 files checked
  under the pinned CI-compatible version.
- `python -m pytest tests\test_native_web_engine.py tests\test_platform_capabilities.py tests\test_entrypoints.py -q`: 19 passed.
- Touched-file Flake8 and `git diff --check`: passed.

### Known Failures And Risks

- A first pinned-mypy run with implicit package-import traversal exposed 32
  errors across 20 unenrolled VPN, firewall, privacy, and browser modules. Those
  modules are not represented as type-accepted and remain current follow-up
  work.
- Full external/public target evidence and real OS VPN/firewall apply/rollback
  evidence remain missing.

### Safe To Continue

Yes. Continue by enrolling and fixing another explicit runtime slice, starting
with the VPN/firewall backend contracts exposed by the pinned analyzer.

## 2026-07-13 VPN Runtime Type-Check Increment

### Current State

- The hard mypy gate now checks 28 explicit files, adding all six VPN package
  files to the 22-file production-tooling and core-runtime foundation.
- OpenVPN process state, backend factory constructors, VPN manager connection
  state, route records, and DNS server collections now have concrete contracts.
- `VPNManager.get_current_ip()` fails closed for absent or non-string backend
  endpoint values.

### Commands And Verification

- `python -m mypy --no-incremental`: passed, 28 files checked with mypy 2.1.
- `uvx --from mypy==1.19.1 mypy --no-incremental`: passed, 28 files checked
  under the pinned CI-compatible version.
- `python -m pytest tests\test_vpn_backends.py tests\test_vpn_manager.py tests\test_vpn_dns_protection.py tests\test_vpn_kill_switch.py -q`: 47 passed.

### Known Failures And Risks

- Type acceptance does not prove privileged OS VPN execution. Real connect,
  disconnect, service, privilege, and rollback evidence is still required on
  each claimed platform.
- The firewall package and remaining application runtime are not yet enrolled
  in the hard mypy gate.

### Safe To Continue

Yes. Continue with the firewall package as the next explicit type-check slice.

## 2026-07-13 Firewall Runtime Type-Check Increment

### Current State

- The hard mypy gate now checks 41 explicit files, adding all 13 firewall
  package modules to the 28-file production-tooling, core-runtime, and VPN
  foundation.
- Firewall rule, session, cache, backend, and evidence collections now have
  concrete contracts.
- Byte-oriented nftables and PF subprocess diagnostics are decoded as UTF-8
  with replacement before logging.
- Packet filtering now explicitly fails closed when a packet IP is absent or
  not a string.

### Commands And Verification

- `python -m mypy --no-incremental`: passed, 41 files checked with mypy 2.1.
- `uvx --from mypy==1.19.1 mypy --no-incremental`: passed, 41 files checked
  under the pinned CI-compatible version.
- `python -m pytest tests\test_firewall_backends.py tests\test_firewall_hardware_cloud_evidence.py tests\test_packet_filtering.py -q`: 51 passed.
- Full-repository Flake8: passed with zero findings.

### Known Failures And Risks

- Type acceptance does not prove privileged OS firewall execution. Real apply,
  enforcement, service, privilege, and rollback evidence is still required on
  each claimed platform.
- The remaining browser, privacy, storage, security, web, and orchestration
  runtime modules are not yet fully enrolled in the hard mypy gate.

### Safe To Continue

Yes. Measure and enroll the next bounded runtime slice without broadening type
acceptance beyond files that pass both supported mypy versions.

## 2026-07-15 Privacy Runtime Type-Check Increment

### Current State

- The hard mypy gate now checks 48 explicit files, adding all seven privacy
  package modules to the 41-file production-tooling and runtime foundation.
- Privacy engine collection state now has explicit list and mapping contracts.
- Anti-malware file scans explicitly accept an absent byte payload, matching
  the existing public default and fail-closed scanning path.
- Suspicious byte signatures are decoded to readable text before logging.

### Commands And Verification

- `python -m mypy --no-incremental`: passed, 48 files checked with mypy 2.1.
- `uvx --from mypy==1.19.1 mypy --no-incremental`: passed, 48 files checked
  under the pinned CI-compatible version.
- `python -m pytest tests\test_privacy_engines.py tests\test_privacy_auditor.py tests\test_python_marker_hygiene.py -q`:
  11 passed.
- Full-repository Flake8: passed with zero findings.
- Standard v3 aggregate smoke passed the marker scans, compile step, mypy,
  Bandit, locked-dependency Safety scan, wheel build, local web startup,
  Docker health/auth/log smoke, and Docker rollback smoke.

### Known Failures And Risks

- Type acceptance does not prove live anti-phishing, anti-malware, onion-routing,
  fingerprint-protection, or leak-audit backend enforcement on target hosts.
- The remaining browser, storage, security, web, and orchestration runtime
  modules are not yet fully enrolled in the hard mypy gate.

### Safe To Continue

Yes. Continue with another bounded runtime slice or external deployment evidence.

## 2026-07-15 Storage And Utilities Type-Check Increment

### Current State

- The hard mypy gate now checks 56 explicit files, adding all three storage
  modules and all five utility modules to the 48-file foundation.
- The enrolled modules passed the type checker without runtime code changes.
- Direct tests now cover encrypted vault round-trip and wipe behavior,
  deterministic ephemeral expiry, and DoH fail-closed behavior.

### Commands And Verification

- `python -m mypy --no-incremental`: passed, 56 files checked with mypy 2.1.
- `uvx --from mypy==1.19.1 mypy --no-incremental`: passed, 56 files checked
  under the pinned CI-compatible version.
- `python -m pytest tests\test_storage_runtime.py tests\test_encrypted_logging.py tests\test_encrypted_network.py tests\test_god_tier_encryption.py -q`:
  13 passed.
- Full-repository Flake8: passed with zero findings.
- Standard v3 aggregate smoke passed the marker scans, compile step, mypy,
  Bandit, locked-dependency Safety scan, wheel build, local web startup,
  Docker health/auth/log smoke, and Docker rollback smoke.

### Known Failures And Risks

- Type and unit-test acceptance do not prove a network-backed DoH resolver or
  durable external vault integration; the current resolver remains fail-closed.
- The remaining browser, security, web, and orchestration runtime modules are
  not yet fully enrolled in the hard mypy gate.

### Safe To Continue

Yes. Continue with the remaining browser package as the next bounded slice.

## 2026-07-15 Main Branch Governance

### Current State

- An active repository ruleset requires changes to use a pull request with
  zero approvals, resolved review conversations, and no bypass actors.
- GitHub `main` branch protection independently requires strict up-to-date
  status checks and is enforced for administrators; force pushes and branch
  deletion are disabled by both policy layers.
- Eleven quality, security, Standard v3, package-build, CodeQL, integration,
  and Python 3.11 platform checks are required before future merges.
- PR #92 exposed the missing protection by merging while checks were pending;
  protection was enabled immediately afterward and applies to future changes.

### Commands And Verification

- GitHub's effective-rules API confirms the active PR-only, deletion, and
  non-fast-forward rules from ruleset `18974290`.
- GitHub's branch-protection API confirms strict checks, administrator
  enforcement, conversation resolution, disabled force pushes, disabled
  deletion, and the 11 required check contexts.

### Known Failures And Risks

- PR #92's protection evidence is post-merge because the rule did not exist at
  merge time. Its hosted checks must still finish cleanly.

## 2026-07-15 Browser Runtime Type-Check Increment

### Current State

- The hard mypy gate now checks 64 explicit files, adding all eight remaining
  browser modules to the 56-file foundation and covering the complete browser
  package.
- Browser document, session, and encrypted-search history state now has
  explicit contracts.
- Optional browser configuration parameters are represented explicitly.
- Browser tab exhaustion now raises a deterministic runtime error instead of
  passing an absent tab identifier into privacy-policy setup.

### Commands And Verification

- `python -m mypy --no-incremental`: passed, 64 files checked with mypy 2.1.
- `uvx --from mypy==1.19.1 mypy --no-incremental`: passed, 64 files checked
  under the pinned CI-compatible version.
- `python -m pytest tests\test_browser.py tests\test_native_web_engine.py tests\test_browser_downloads.py -q`:
  67 passed.
- Full-repository Flake8: passed with zero findings.
- Standard v3 aggregate smoke passed the marker scans, compile step, mypy,
  Bandit, locked-dependency Safety scan, wheel build, local web startup,
  Docker health/auth/log smoke, and Docker rollback smoke.

### Known Failures And Risks

- Type and unit-test acceptance do not prove broad supported-site rendering,
  script execution, real sandbox enforcement, or external browser backends.
- Security, web, orchestration, and other application runtime modules remain
  outside the hard mypy gate.

### Safe To Continue

Yes. Publish through the protected `main` workflow, then continue with another
bounded runtime slice or external deployment evidence.

## 2026-07-15 Remote Access And Media Runtime Type-Check Increment

### Current State

- The hard mypy gate now checks 72 explicit files, adding all four remote-access
  and all four media-downloader modules to the 64-file foundation.
- Both packages passed the type checker without runtime code changes.
- Existing direct tests cover fail-closed backend absence, encrypted backend
  inputs, invalid backend results, lifecycle cleanup, and delegated operations.

### Commands And Verification

- `python -m mypy --no-incremental`: passed, 72 files checked with mypy 2.1.
- `uvx --from mypy==1.19.1 mypy --no-incremental`: passed, 72 files checked
  under the pinned CI-compatible version.
- `python -m pytest tests\test_remote_browser.py tests\test_remote_desktop.py tests\test_secure_tunnel.py tests\test_format_converter.py tests\test_media_downloader.py -q`:
  17 passed.
- Standard v3 aggregate smoke passed the marker scans, compile step, mypy,
  Bandit, locked-dependency Safety scan, wheel build, local web startup,
  Docker health/auth/log smoke, and Docker rollback smoke.
- A read-only remainder scan passed all seven unenrolled root/configuration
  modules, completing their classification for a later bounded increment.
- PR #93's hosted Standard v3 verifier passed 551 tests on the protected
  browser-runtime foundation before this increment.

### Known Failures And Risks

- Type and unit-test acceptance do not prove external remote-access transports,
  a real secure-tunnel backend, or target-host media download/conversion.
- Forty-eight application runtime files remain outside the hard mypy gate: 24
  are currently clean and 24 are in packages with known type findings.

### Safe To Continue

Yes. Publish through the protected `main` workflow, then continue with the next
clean runtime package group.

## 2026-07-15 Clean Runtime Type-Check Increment

### Current State

- The hard mypy gate now checks 96 explicit files, adding 24 clean runtime
  files to the 72-file foundation.
- The new enrollment covers the remaining clean root/configuration modules, all
  ad-annihilator modules, all AI-assistant modules, all setup modules, and all
  theme modules.
- Configuration IP address validation now uses the standard library IP parser
  so invalid IPv4 octets are rejected and compressed IPv6 addresses are
  accepted.

### Commands And Verification

- `python -m mypy --no-incremental`: passed, 96 files checked with mypy 2.1.
- `uvx --from mypy==1.19.1 mypy --no-incremental`: passed, 96 files checked
  under the pinned CI-compatible version.
- `python -m pytest tests\test_ai_setup_themes.py tests\test_ad_annihilator.py tests\test_local_inference.py tests\test_entrypoints.py tests\test_encryption_evidence.py tests\test_global_kill_switch.py tests\test_orchestrator_status.py -q`:
  52 passed, 1 skipped.
- `python scripts\verify_production_deployment.py --skip-docker --skip-tests --thirsty-lang-path "T:\01-Projects\thirsty_lang_exploration_0754"`:
  passed after Docker was found unavailable locally; wheel sha256 was
  `d539e7f49651258efb6b106c698983508a1387300d3a1ec0d76cca9c3547ad4e`,
  and local web smoke reported `backend=thirsty-lang`.

### Known Failures And Risks

- Type and unit-test acceptance do not prove real ad-blocking effectiveness,
  local inference backend availability, target setup acceptance, or UI theme
  behavior on all supported hosts.
- Docker Desktop's Linux engine was not running locally for this increment:
  `docker ps` failed to connect to `npipe:////./pipe/dockerDesktopLinuxEngine`.
  Container proof must come from a later local Docker run or hosted checks.
- The first hosted Code Quality and Standard v3 jobs failed because Linux mypy
  saw the Windows-only `winreg` import without registry attributes. The theme
  detector now uses a typed dynamic import for that Windows-only path.
- Twenty-four application runtime files remain outside the hard mypy gate in
  packages with known type findings: consigliere, Wi-Fi, network, settings,
  and security.

### Safe To Continue

Yes. Publish through the protected `main` workflow, then continue with the
remaining defect-bearing runtime packages.

## 2026-07-15 Consigliere And Wi-Fi Type-Check Increment

### Current State

- The hard mypy gate now checks 106 explicit files, adding all five Consigliere
  modules and all five Wi-Fi modules to the 96-file foundation.
- Permission-request audit records and minimized assistant context now have
  explicit heterogeneous value contracts.
- Wi-Fi channel optimization narrows validated backend results to its declared
  integer-or-null return contract before returning them.

### Commands And Verification

- `python -m mypy --no-incremental thirstys_waterfall\consigliere thirstys_waterfall\wifi_network`:
  passed, 10 files checked.
- `python -m mypy --no-incremental`: passed, 106 files checked with mypy 2.1.
- `uvx --from mypy==1.19.1 mypy --no-incremental`: passed, 106 files
  checked under the pinned CI-compatible version.
- `python -m pytest tests\test_consigliere.py tests\test_wifi_controller.py tests\test_wifi_security.py -q --no-cov`:
  48 passed.
- `python scripts\verify_production_deployment.py --skip-docker --thirsty-lang-path "T:\01-Projects\thirsty_lang_exploration_0754"`:
  passed the marker scans, compilation, Flake8, mypy, Bandit, locked Safety
  scan, all 562 tests, wheel build, and local web smoke. The wheel sha256 was
  `1a907cb3239463c5a7f34ce920bbad90379120c11692213119a31f4d98cfd58c`,
  and local web smoke reported `backend=thirsty-lang`.
- Parent PR #95 passed every hosted quality, Standard v3, security, package,
  integration, CodeQL, and Python 3.10-3.11 platform check.

### Known Failures And Risks

- Type and unit-test acceptance do not prove a configured local inference
  backend or privileged Wi-Fi connect, disconnect, and channel-control behavior
  on supported operating systems.
- Fourteen runtime files remain outside the hard mypy gate in the network,
  settings, and security packages.

### Safe To Continue

Yes. Run the full Standard v3 local gate, publish through the protected `main`
workflow, then continue with the remaining runtime packages.

## 2026-07-15 Network Type-Check Increment

### Current State

- The hard mypy gate now checks 108 explicit files, adding both network modules
  to the 106-file foundation.
- Obfuscation metrics, active domain fronts, provider usage, and request-queue
  state now have explicit element contracts.
- The obfs4 handshake debug path now distinguishes the textual session ID from
  mixed bytes and integer handshake material without logging key bytes.

### Commands And Verification

- `python -m mypy --no-incremental thirstys_waterfall\network`: passed, 2 files
  checked.
- `python -m mypy --no-incremental`: passed, 108 files checked with mypy 2.1.
- `uvx --from mypy==1.19.1 mypy --no-incremental`: passed, 108 files checked
  under the pinned CI-compatible version.
- `python -m pytest tests\test_advanced_stealth.py -q --no-cov`: 4 passed.
- `python scripts\verify_production_deployment.py --skip-docker --skip-tests --thirsty-lang-path "T:\01-Projects\thirsty_lang_exploration_0754"`:
  passed the marker scans, compilation, Flake8, mypy, Bandit, locked Safety
  scan, wheel build, and local web smoke. The wheel sha256 was
  `e7356d5fb0f48d4aec87131f93a9577d4d05108dd327dfa9db8500086ef0fba9`,
  and local web smoke reported `backend=thirsty-lang`.

### Known Failures And Risks

- Type and unit-test acceptance do not prove configured stealth transports,
  onion nodes, or domain-fronting behavior on a target network.
- Twelve runtime files remain outside the hard mypy gate in the settings and
  security packages.

### Safe To Continue

Yes. Run the aggregate local gate, publish through the protected `main`
workflow, then continue with settings and security.

## 2026-07-15 Settings Type-Check Increment

### Current State

- The hard mypy gate now checks 113 explicit files, adding all five settings
  modules to the 108-file foundation.
- Settings and defaults now use isolated deep snapshots, so reset operations
  restore original nested values and returned snapshots cannot mutate manager
  state.
- Imported settings are shape-validated completely and applied atomically, so
  a malformed later category cannot leave earlier categories partially changed.

### Commands And Verification

- `python -m mypy --no-incremental thirstys_waterfall\settings`: passed, 5 files
  checked.
- `python -m mypy --no-incremental`: passed, 113 files checked with mypy 2.1.
- `uvx --from mypy==1.19.1 mypy --no-incremental`: passed, 113 files checked
  under the pinned CI-compatible version.
- `python -m pytest tests\test_settings_manager.py -q --no-cov`: 8 passed.
- Full-repository Flake8 passed with zero findings.
- `python scripts\verify_production_deployment.py --skip-docker --skip-tests --thirsty-lang-path "T:\01-Projects\thirsty_lang_exploration_0754"`:
  passed the marker scans, compilation, Flake8, mypy, Bandit, locked Safety
  scan, wheel build, and local web smoke. The wheel sha256 was
  `d26b50d13497d7b79f08b808c048f5ea40f4d5cc81ac541b11ac0b19af1026e5`,
  and local web smoke reported `backend=thirsty-lang`.

### Known Failures And Risks

- Type and unit-test acceptance do not prove target-host persistence,
  operator-facing settings UI behavior, or external support delivery.
- Seven runtime files remain outside the hard mypy gate in the security package.

### Safe To Continue

Yes. Run the aggregate local gate, publish through the protected `main`
workflow, then finish the security package.
