# Thirstys Waterfall Capability Comparison

This document is a Standard v3 comparison guide. It compares intended product scope and current evidence without claiming accepted production superiority before the repository has target-host proof.

The acceptance source of truth is `docs/operations/README_CLAIM_ACCEPTANCE.md`.

## Comparison Rules

- Claims about Thirstys Waterfall must match implemented code, tests, documentation, and operational evidence.
- Competitor descriptions are broad category references, not audited product certifications.
- A capability marked `partial` is not accepted as a finished production claim.
- A capability marked `not accepted` must not be used as marketing proof.

## Current Status by Area

| Area | Thirstys Waterfall status | Current evidence | Remaining evidence |
| --- | --- | --- | --- |
| Local-first architecture | Partial | Python package, local verifier, Docker build/smoke, GHCR release image | Target-host deployment and service hardening evidence |
| Native browser direction | Partial | Native document/parser/fetcher layer and tests | Rendering, layout, navigation, session, and compatibility acceptance tests |
| Built-in VPN direction | Partial | Backend factory, command resolution, tests, fail-closed web API behavior | Real OS connection/disconnection evidence and privilege documentation |
| Firewall orchestration | Partial | Eight categories represented in code and backend tests; fail-closed web status behavior | Real rule apply/rollback evidence per supported platform |
| Encryption and storage | Not accepted | Crypto helpers and encrypted storage components | End-to-end data-path evidence for storage, browser state, logs, downloads, and transport |
| Web API production auth | Partial | Default demo login removed; configured password-hash auth and production startup guards exist | Operator setup, token/session policy, and target secret-rotation evidence |
| Release and image pipeline | Partial | Release `v1.0.2`, GHCR image digest, hosted CI, security scans, local published-image smoke | Target deployment, target logs, rollback, and network policy evidence |

## Category Comparison

| Category | Typical external VPN service | Typical privacy browser | Typical firewall product | Thirstys Waterfall direction |
| --- | --- | --- | --- | --- |
| Primary scope | VPN transport | Browser privacy controls | Network filtering | Combined local privacy browser, VPN, firewall, and evidence workflow |
| External service dependency | Usually required | Usually not for browsing; may rely on sync/services | Varies | Intended to be local-first; remaining host evidence required |
| Browser engine | Not applicable | Existing browser engine | Not applicable | Native engine direction with partial implementation |
| VPN implementation | Provider managed | Usually absent or separate | Usually absent | Built-in orchestration direction; real OS backend evidence still required |
| Firewall control | Usually absent | Usually absent | Primary feature | Multiple firewall categories represented; real platform proof still required |
| Production proof in this repo | Not applicable | Not applicable | Not applicable | In progress under Standard v3 |

## What Is Already Stronger Than Before

- Public release and image evidence now exist for `v1.0.2`.
- The release pipeline runs hard checks instead of silently swallowing security or syntax failures.
- The web API no longer returns fabricated VPN success responses when the service reports failure.
- The web UI no longer embeds the default `admin/admin` login flow.
- The firewall status endpoint no longer reports all firewalls active when backend status is unavailable.

## What Cannot Be Claimed Yet

Until the acceptance matrix is green, the repository should not claim:

- Full production readiness.
- Target-host deployment verification.
- Real OS VPN/firewall execution across supported platforms.
- Total encryption of all browser, network, log, download, and storage data paths.
- Complete native browser rendering acceptance.
- Comparative market superiority scores.

## Evidence Commands

Use these local commands to reproduce the strongest current evidence:

```bash
python scripts/verify_production_deployment.py --skip-docker --thirsty-lang-path "T:\00-Active\thirsty_lang_exploration_0754"
python -m pytest -q
```

These checks are necessary evidence, not sufficient evidence for final target-host production acceptance.
