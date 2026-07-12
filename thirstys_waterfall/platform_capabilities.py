"""Platform capability reporting for Standard v3 acceptance gates."""

from dataclasses import asdict, dataclass
import platform as runtime_platform
from typing import Dict, List, Optional


STANDARD_V3_ACCEPTANCE_GAPS = [
    "real VPN connect/disconnect evidence on each supported OS",
    "real firewall rule apply/rollback evidence on each supported OS",
    "documented privilege and service-install requirements per OS",
    "target-host runtime logs for each supported OS",
]


@dataclass(frozen=True)
class PlatformCapabilityReport:
    """Evidence-aware platform capability report."""

    platform: str
    supported: bool
    vpn_backends: List[str]
    firewall_backends: List[str]
    service_model: Optional[str]
    privileged_operations: List[str]
    production_accepted: bool
    acceptance_gaps: List[str]

    def as_dict(self) -> Dict[str, object]:
        """Return a JSON-serializable report."""
        return asdict(self)


PLATFORM_CAPABILITIES = {
    "Linux": {
        "vpn_backends": ["wireguard", "openvpn", "ikev2_strongswan"],
        "firewall_backends": ["nftables"],
        "service_model": "systemd",
        "privileged_operations": [
            "sudo wg-quick up/down",
            "sudo openvpn",
            "sudo ipsec up/down",
            "sudo nft rule/table changes",
        ],
    },
    "Windows": {
        "vpn_backends": ["wireguard_service", "openvpn", "native_ikev2_rasdial"],
        "firewall_backends": ["windows_firewall_netsh"],
        "service_model": "Windows Service",
        "privileged_operations": [
            "WireGuard tunnel service install/uninstall",
            "OpenVPN process execution",
            "rasdial native VPN connect/disconnect",
            "netsh advfirewall rule/profile changes",
        ],
    },
    "Darwin": {
        "vpn_backends": ["wireguard", "openvpn", "native_ikev2_scutil"],
        "firewall_backends": ["pf"],
        "service_model": "launchd",
        "privileged_operations": [
            "sudo wg-quick up/down",
            "sudo openvpn",
            "scutil network connection control",
            "sudo pfctl anchor/rule changes",
        ],
    },
}


def get_platform_capabilities(
    system: Optional[str] = None,
) -> PlatformCapabilityReport:
    """Return the Standard v3 capability report for an OS name."""
    platform_name = system or runtime_platform.system()
    capability = PLATFORM_CAPABILITIES.get(platform_name)

    if capability is None:
        return PlatformCapabilityReport(
            platform=platform_name,
            supported=False,
            vpn_backends=[],
            firewall_backends=[],
            service_model=None,
            privileged_operations=[],
            production_accepted=False,
            acceptance_gaps=[
                "unsupported OS has no verified VPN/firewall/service capability map"
            ],
        )

    return PlatformCapabilityReport(
        platform=platform_name,
        supported=True,
        vpn_backends=list(capability["vpn_backends"]),
        firewall_backends=list(capability["firewall_backends"]),
        service_model=capability["service_model"],
        privileged_operations=list(capability["privileged_operations"]),
        production_accepted=False,
        acceptance_gaps=list(STANDARD_V3_ACCEPTANCE_GAPS),
    )
