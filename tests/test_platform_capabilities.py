"""Tests for Standard v3 platform capability reporting."""

from thirstys_waterfall import get_platform_capabilities
from thirstys_waterfall.platform_capabilities import PlatformCapabilityReport


def test_linux_capabilities_are_supported_but_not_production_accepted():
    report = get_platform_capabilities("Linux")

    assert report.platform == "Linux"
    assert report.supported is True
    assert "wireguard" in report.vpn_backends
    assert "nftables" in report.firewall_backends
    assert report.service_model == "systemd"
    assert report.production_accepted is False
    assert "real VPN connect/disconnect evidence on each supported OS" in (
        report.acceptance_gaps
    )


def test_windows_capabilities_document_native_backends_and_gaps():
    report = get_platform_capabilities("Windows")

    assert report.supported is True
    assert "native_ikev2_rasdial" in report.vpn_backends
    assert "windows_firewall_netsh" in report.firewall_backends
    assert report.service_model == "Windows Service"
    assert report.production_accepted is False
    assert any("netsh" in item for item in report.privileged_operations)


def test_macos_capabilities_document_pf_and_launchd():
    report = get_platform_capabilities("Darwin")

    assert report.supported is True
    assert "native_ikev2_scutil" in report.vpn_backends
    assert "pf" in report.firewall_backends
    assert report.service_model == "launchd"
    assert report.production_accepted is False


def test_unsupported_platform_fails_closed():
    report = get_platform_capabilities("Plan9")

    assert report.supported is False
    assert report.vpn_backends == []
    assert report.firewall_backends == []
    assert report.production_accepted is False
    assert "unsupported OS" in report.acceptance_gaps[0]


def test_report_is_serializable():
    report = get_platform_capabilities("Linux")

    assert isinstance(report, PlatformCapabilityReport)
    assert report.as_dict()["platform"] == "Linux"
    assert report.as_dict()["production_accepted"] is False
