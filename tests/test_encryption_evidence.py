"""Tests for Standard v3 encryption evidence mapping."""

from thirstys_waterfall import get_encryption_evidence_report
from thirstys_waterfall.encryption_evidence import (
    DataSurfaceEvidence,
    EncryptionEvidenceReport,
)


def _surface(report, name):
    return next(surface for surface in report.surfaces if surface.name == name)


def test_encryption_report_fails_full_acceptance_closed():
    report = get_encryption_evidence_report()

    assert isinstance(report, EncryptionEvidenceReport)
    assert report.standard_v3_accepted is False
    assert report.all_surfaces_covered is False
    assert "target production log encryption proof" in report.acceptance_gaps


def test_browser_navigation_and_search_are_partial_not_accepted():
    report = get_encryption_evidence_report()

    search = _surface(report, "browser_search_queries")
    navigation = _surface(report, "browser_navigation_history")

    assert isinstance(search, DataSurfaceEvidence)
    assert search.coverage_status == "partial"
    assert navigation.coverage_status == "partial"
    assert any("encrypted bytes" in item for item in search.evidence)
    assert any("persisted browser state" in item for item in navigation.remaining_work)


def test_download_logs_and_network_surfaces_retain_remaining_work():
    report = get_encryption_evidence_report()

    downloads = _surface(report, "browser_downloads")
    logs = _surface(report, "runtime_logs")
    network = _surface(report, "explicit_network_payloads")

    assert downloads.coverage_status == "partial"
    assert logs.coverage_status == "partial"
    assert network.coverage_status == "partial"
    assert any("target lifecycle wipe" in item for item in downloads.remaining_work)
    assert any("Fernet ciphertext" in item for item in downloads.evidence)
    assert any("target production logs" in item for item in logs.remaining_work)
    assert any("accepted transport paths" in item for item in network.remaining_work)


def test_uncovered_surfaces_are_explicit():
    report = get_encryption_evidence_report()

    telemetry = _surface(report, "telemetry_and_audit_events")
    post_quantum = _surface(report, "post_quantum_backend")

    assert telemetry.coverage_status == "partial"
    assert any("privacy auditor" in item for item in telemetry.evidence)
    assert any("outside the privacy auditor" in item for item in telemetry.remaining_work)
    assert post_quantum.coverage_status == "not_covered"
    assert post_quantum.evidence == [
        "post-quantum facade fails closed without a configured backend"
    ]


def test_report_is_serializable():
    report = get_encryption_evidence_report()
    serialized = report.as_dict()

    assert serialized["standard_v3_accepted"] is False
    assert serialized["surfaces"][0]["name"] == "browser_search_queries"
