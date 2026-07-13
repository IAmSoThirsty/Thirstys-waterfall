"""Evidence map for Standard v3 encryption acceptance."""

from dataclasses import asdict, dataclass
from typing import Dict, List


FULL_ENCRYPTION_ACCEPTANCE_GAPS = [
    "end-to-end stored-state plaintext inspection",
    "browser data path proof beyond local helper records",
    "download content encryption and persistence proof",
    "telemetry and audit-log encryption proof",
    "target production log encryption proof",
    "accepted post-quantum backend proof",
]


@dataclass(frozen=True)
class DataSurfaceEvidence:
    """Encryption evidence for one data surface."""

    name: str
    coverage_status: str
    evidence: List[str]
    remaining_work: List[str]

    def as_dict(self) -> Dict[str, object]:
        """Return a JSON-serializable surface record."""
        return asdict(self)


@dataclass(frozen=True)
class EncryptionEvidenceReport:
    """Standard v3 encryption evidence summary."""

    standard_v3_accepted: bool
    all_surfaces_covered: bool
    surfaces: List[DataSurfaceEvidence]
    acceptance_gaps: List[str]

    def as_dict(self) -> Dict[str, object]:
        """Return a JSON-serializable report."""
        return asdict(self)


def get_encryption_evidence_report() -> EncryptionEvidenceReport:
    """Return the current encryption evidence map."""
    surfaces = [
        DataSurfaceEvidence(
            name="browser_search_queries",
            coverage_status="partial",
            evidence=[
                "search queries and local unavailable responses are encrypted bytes",
                "search history does not retain plaintext query records",
            ],
            remaining_work=[
                "prove configured search backend storage and transport encryption",
                "define accepted external search scope",
            ],
        ),
        DataSurfaceEvidence(
            name="browser_navigation_history",
            coverage_status="partial",
            evidence=[
                "navigation URLs and tab IDs are stored as encrypted bytes",
                "local history search returns encrypted result records",
            ],
            remaining_work=[
                "prove persisted browser state encryption beyond in-memory helpers",
                "prove multi-session lifecycle and wipe behavior on target hosts",
            ],
        ),
        DataSurfaceEvidence(
            name="browser_downloads",
            coverage_status="partial",
            evidence=[
                "unavailable download results redact plaintext URLs",
                "download backend contract reports isolation state",
                "configured local browser download backend stores downloaded bytes as Fernet ciphertext",
            ],
            remaining_work=[
                "prove configured download storage and cleanup behavior on target hosts",
                "prove target lifecycle wipe behavior for encrypted download artifacts",
            ],
        ),
        DataSurfaceEvidence(
            name="runtime_logs",
            coverage_status="partial",
            evidence=[
                "package runtime logger routes through encrypted handlers",
                "local encrypted log file round-trip test excludes plaintext probe",
            ],
            remaining_work=[
                "prove target production logs are encrypted",
                "prove operational log export and retention behavior",
            ],
        ),
        DataSurfaceEvidence(
            name="explicit_network_payloads",
            coverage_status="partial",
            evidence=[
                "explicit request and packet payload helpers use JSON plus Fernet",
                "status reports explicit-payload scope, not host-wide interception",
            ],
            remaining_work=[
                "prove all accepted transport paths route through encryption",
                "prove VPN/firewall target traffic behavior on supported OSes",
            ],
        ),
        DataSurfaceEvidence(
            name="configuration_and_private_storage",
            coverage_status="partial",
            evidence=[
                "configuration registry accepts an encryption key",
                "privacy vault and encrypted storage helpers exist",
            ],
            remaining_work=[
                "prove persisted config/state files contain no plaintext secrets",
                "prove backup, restore, and rotation behavior",
            ],
        ),
        DataSurfaceEvidence(
            name="telemetry_and_audit_events",
            coverage_status="partial",
            evidence=[
                "privacy auditor stores local audit events as encrypted records",
                "public audit access decrypts records on demand without retaining a plaintext event log",
            ],
            remaining_work=[
                "prove telemetry encryption or disable telemetry by accepted policy",
                "prove audit/event log encryption for every emitted event path outside the privacy auditor",
                "prove target retention and export behavior for encrypted audit records",
            ],
        ),
        DataSurfaceEvidence(
            name="post_quantum_backend",
            coverage_status="not_covered",
            evidence=[
                "post-quantum facade fails closed without a configured backend",
            ],
            remaining_work=[
                "configure and prove an accepted post-quantum backend",
            ],
        ),
    ]

    return EncryptionEvidenceReport(
        standard_v3_accepted=False,
        all_surfaces_covered=False,
        surfaces=surfaces,
        acceptance_gaps=list(FULL_ENCRYPTION_ACCEPTANCE_GAPS),
    )
