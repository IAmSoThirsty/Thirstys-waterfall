# Encryption Evidence Map

Status: Standard v3 evidence surface, not full encryption acceptance.

`thirstys_waterfall.get_encryption_evidence_report()` describes the current
encryption evidence by data surface. The report returns
`standard_v3_accepted: false` and `all_surfaces_covered: false` until every
accepted data path has end-to-end proof.

## Partial Evidence

| Surface | Evidence now present | Remaining work |
| --- | --- | --- |
| Browser search queries | Search queries and local unavailable responses are encrypted bytes; local history does not retain plaintext query records | Prove configured search backend storage and transport encryption; define accepted external search scope |
| Browser navigation history | Navigation URLs and tab IDs are stored as encrypted bytes; local history search returns encrypted result records | Prove persisted browser state encryption beyond in-memory helpers; prove multi-session lifecycle and wipe behavior on target hosts |
| Browser downloads | Unavailable download results redact plaintext URLs; download backend contract reports isolation state; configured local browser download backend stores downloaded bytes as Fernet ciphertext | Prove configured download storage and cleanup behavior on target hosts; prove target lifecycle wipe behavior for encrypted download artifacts |
| Runtime logs | Package runtime logger routes through encrypted handlers; local encrypted log file round-trip test excludes plaintext probe | Prove target production logs are encrypted; prove operational log export and retention behavior |
| Explicit network payloads | Explicit request and packet payload helpers use JSON plus Fernet; status reports explicit-payload scope, not host-wide interception | Prove all accepted transport paths route through encryption; prove VPN/firewall target traffic behavior on supported OSes |
| Configuration and private storage | Configuration registry accepts an encryption key; privacy vault and encrypted storage helpers exist | Prove persisted config/state files contain no plaintext secrets; prove backup, restore, and rotation behavior |

## Not Covered

| Surface | Current evidence | Required acceptance work |
| --- | --- | --- |
| Telemetry and audit events | Privacy auditor stores local audit events as encrypted records and decrypts them only for caller access | Prove telemetry encryption or disable telemetry by accepted policy; prove audit/event log encryption for every emitted event path outside the privacy auditor; prove target retention and export behavior for encrypted audit records |
| Post-quantum backend | Facade fails closed without a configured backend | Configure and prove an accepted post-quantum backend |

## Acceptance Rule

The README claim for total encryption remains below full Standard v3 acceptance
until the repository has proof for:

- stored state,
- browser data,
- telemetry and audit events,
- downloads,
- all accepted transport paths,
- target production logs,
- any accepted post-quantum backend.
