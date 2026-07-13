"""DNS and IPv6 leak protection"""

import logging
from typing import Any, Dict, List, Optional


class DNSProtection:
    """
    Protects against DNS and IPv6 leaks.
    Ensures all DNS queries go through VPN tunnel.
    """

    def __init__(
        self,
        dns_protection: bool = True,
        ipv6_protection: bool = True,
        dns_backend: Optional[Any] = None,
        leak_detector: Optional[Any] = None,
    ):
        self.dns_protection = dns_protection
        self.ipv6_protection = ipv6_protection
        self.dns_backend = dns_backend
        self.leak_detector = leak_detector
        self.logger = logging.getLogger(__name__)
        self._active = False
        self._dns_servers: List[str] = []
        self._original_dns: List[str] = []
        self._start_result: Optional[Dict[str, Any]] = None
        self._stop_result: Optional[Dict[str, Any]] = None
        self._dns_leak_result: Optional[Dict[str, Any]] = None
        self._ipv6_leak_result: Optional[Dict[str, Any]] = None

    def start(self):
        """Start DNS leak protection"""
        if not self.dns_protection:
            self._active = False
            self._start_result = {
                "status": "disabled",
                "dns_protected": False,
                "ipv6_protected": False,
            }
            return self._start_result

        self.logger.info("Starting DNS leak protection")

        if self.dns_backend is None:
            self._active = False
            self._start_result = {
                "status": "unavailable",
                "error": "VPN DNS protection backend is not configured",
                "dns_protected": False,
                "ipv6_protected": False,
            }
            self.logger.error(self._start_result["error"])
            return self._start_result

        self._original_dns = self._get_system_dns()
        self._dns_servers = ["10.200.200.1", "10.200.200.2"]  # VPN DNS 1  # VPN DNS 2
        dns_result = self._set_dns_servers(self._dns_servers)

        ipv6_result = {"status": "disabled", "ipv6_blocked": False}
        if self.ipv6_protection:
            ipv6_result = self._block_ipv6()

        dns_protected = bool(dns_result.get("dns_servers_set"))
        ipv6_protected = (not self.ipv6_protection) or bool(
            ipv6_result.get("ipv6_blocked")
        )
        self._active = dns_protected and ipv6_protected
        self._start_result = {
            "status": "protected" if self._active else "unprotected",
            "dns_protected": dns_protected,
            "ipv6_protected": ipv6_protected,
            "original_dns": list(self._original_dns),
            "vpn_dns": list(self._dns_servers),
            "dns_result": dns_result,
            "ipv6_result": ipv6_result,
            "backend": type(self.dns_backend).__name__,
        }
        return self._start_result

    def stop(self):
        """Stop DNS leak protection"""
        if not self._active:
            self._stop_result = {
                "status": "inactive",
                "dns_restored": False,
                "ipv6_restored": False,
                "backend_configured": self.dns_backend is not None,
            }
            return self._stop_result

        self.logger.info("Stopping DNS leak protection")

        dns_result = {"status": "not_attempted", "dns_restored": False}
        if self._original_dns:
            dns_result = self._set_dns_servers(self._original_dns, restore=True)

        ipv6_result = {"status": "disabled", "ipv6_restored": False}
        if self.ipv6_protection:
            ipv6_result = self._restore_ipv6()

        self._active = False
        self._stop_result = {
            "status": "stopped",
            "dns_restored": bool(dns_result.get("dns_servers_set")),
            "ipv6_restored": (
                (not self.ipv6_protection) or bool(ipv6_result.get("ipv6_restored"))
            ),
            "dns_result": dns_result,
            "ipv6_result": ipv6_result,
            "backend": type(self.dns_backend).__name__,
        }
        return self._stop_result

    def _get_system_dns(self) -> List[str]:
        """Get current system DNS servers"""
        get_system_dns = getattr(self.dns_backend, "get_system_dns", None)
        if not callable(get_system_dns):
            raise RuntimeError("VPN DNS backend does not implement get_system_dns")

        result = get_system_dns()
        if not isinstance(result, list) or not all(
            isinstance(server, str) for server in result
        ):
            raise RuntimeError("VPN DNS backend returned invalid DNS server list")
        return result

    def _set_dns_servers(self, servers: List[str], restore: bool = False):
        """Set system DNS servers"""
        self.logger.debug(f"Setting DNS servers: {servers}")
        set_dns_servers = getattr(self.dns_backend, "set_dns_servers", None)
        if not callable(set_dns_servers):
            raise RuntimeError("VPN DNS backend does not implement set_dns_servers")

        result = set_dns_servers(servers=servers, restore=restore)
        if not isinstance(result, dict):
            raise RuntimeError("VPN DNS backend returned invalid set-DNS result")

        result.setdefault("status", "unknown")
        result.setdefault("dns_servers_set", result["status"] in {"set", "restored"})
        result.setdefault("servers", list(servers))
        result.setdefault("backend", type(self.dns_backend).__name__)
        return result

    def _block_ipv6(self):
        """Block IPv6 to prevent leaks"""
        self.logger.info("Blocking IPv6 traffic")
        block_ipv6 = getattr(self.dns_backend, "block_ipv6", None)
        if not callable(block_ipv6):
            raise RuntimeError("VPN DNS backend does not implement block_ipv6")

        result = block_ipv6()
        if not isinstance(result, dict):
            raise RuntimeError("VPN DNS backend returned invalid IPv6 block result")

        result.setdefault("status", "unknown")
        result.setdefault("ipv6_blocked", result["status"] == "blocked")
        result.setdefault("backend", type(self.dns_backend).__name__)
        return result

    def _restore_ipv6(self):
        """Restore IPv6 functionality"""
        self.logger.info("Restoring IPv6 traffic")
        restore_ipv6 = getattr(self.dns_backend, "restore_ipv6", None)
        if not callable(restore_ipv6):
            raise RuntimeError("VPN DNS backend does not implement restore_ipv6")

        result = restore_ipv6()
        if not isinstance(result, dict):
            raise RuntimeError("VPN DNS backend returned invalid IPv6 restore result")

        result.setdefault("status", "unknown")
        result.setdefault("ipv6_restored", result["status"] == "restored")
        result.setdefault("backend", type(self.dns_backend).__name__)
        return result

    def verify_dns_leak(self) -> bool:
        """
        Verify no DNS leaks are occurring.

        Returns:
            True if protected (no leaks), False if leaking
        """
        status = self.get_dns_leak_status()
        return bool(status.get("protected"))

    def verify_ipv6_leak(self) -> bool:
        """
        Verify no IPv6 leaks are occurring.

        Returns:
            True if protected (no leaks), False if leaking
        """
        status = self.get_ipv6_leak_status()
        return bool(status.get("protected"))

    def is_active(self) -> bool:
        """Check if DNS protection is active"""
        return self._active

    def get_status(self) -> Dict[str, Any]:
        """Return DNS protection state and latest backend evidence."""
        return {
            "active": self._active,
            "dns_protection_enabled": self.dns_protection,
            "ipv6_protection_enabled": self.ipv6_protection,
            "backend_configured": self.dns_backend is not None,
            "leak_detector_configured": self.leak_detector is not None,
            "start_result": self._start_result,
            "stop_result": self._stop_result,
            "dns_leak_result": self._dns_leak_result,
            "ipv6_leak_result": self._ipv6_leak_result,
        }

    def get_dns_leak_status(self) -> Dict[str, Any]:
        """Verify DNS leak protection with a configured detector backend."""
        if self.leak_detector is None:
            self._dns_leak_result = {
                "status": "unavailable",
                "error": "VPN DNS leak detector is not configured",
                "protected": False,
            }
            return self._dns_leak_result

        verify_dns_leak = getattr(self.leak_detector, "verify_dns_leak", None)
        if not callable(verify_dns_leak):
            raise RuntimeError("VPN DNS leak detector does not implement verify_dns_leak")

        result = verify_dns_leak(dns_servers=list(self._dns_servers))
        if not isinstance(result, dict):
            raise RuntimeError("VPN DNS leak detector returned invalid result")

        result.setdefault("status", "verified")
        if "protected" not in result:
            result["protected"] = not bool(result.get("leak_detected", True))
        result.setdefault("backend", type(self.leak_detector).__name__)
        self._dns_leak_result = result
        return result

    def get_ipv6_leak_status(self) -> Dict[str, Any]:
        """Verify IPv6 leak protection with a configured detector backend."""
        if self.leak_detector is None:
            self._ipv6_leak_result = {
                "status": "unavailable",
                "error": "VPN IPv6 leak detector is not configured",
                "protected": False,
            }
            return self._ipv6_leak_result

        verify_ipv6_leak = getattr(self.leak_detector, "verify_ipv6_leak", None)
        if not callable(verify_ipv6_leak):
            raise RuntimeError(
                "VPN IPv6 leak detector does not implement verify_ipv6_leak"
            )

        result = verify_ipv6_leak()
        if not isinstance(result, dict):
            raise RuntimeError("VPN IPv6 leak detector returned invalid result")

        result.setdefault("status", "verified")
        if "protected" not in result:
            result["protected"] = not bool(result.get("leak_detected", True))
        result.setdefault("backend", type(self.leak_detector).__name__)
        self._ipv6_leak_result = result
        return result
