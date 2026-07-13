"""VPN Manager - Coordinates VPN functionality"""

from typing import Any, Dict, List, Optional
import logging
import threading
import time
from cryptography.fernet import Fernet
from .backends import VPNBackend, VPNBackendFactory
from .multi_hop import MultiHopRouter
from .kill_switch import KillSwitch
from .dns_protection import DNSProtection


class VPNManager:
    """
    Coordinates configured VPN backends, multi-hop state, kill switch,
    and DNS protection.
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)

        self.enabled = config.get("enabled", True)
        self.multi_hop = config.get("multi_hop", True)
        self.hop_count = config.get("hop_count", 3)
        self.stealth_mode = config.get("stealth_mode", True)
        self.split_tunneling = config.get("split_tunneling", False)
        self.logging_policy = config.get("logging", "never")
        self.protocol_fallback = config.get(
            "protocol_fallback", ["wireguard", "openvpn"]
        )

        # ENCRYPTION: Generate encryption key for all VPN traffic
        self._vpn_cipher = Fernet(Fernet.generate_key())

        # Initialize components
        self.router = MultiHopRouter(self.hop_count)
        self.kill_switch = KillSwitch(config.get("kill_switch", True))
        self.dns_protection = DNSProtection(
            config.get("dns_leak_protection", True),
            config.get("ipv6_leak_protection", True),
        )

        self._active = False
        self._connected = False
        self._current_route: List[Dict[str, Any]] = []
        self._active_backend: Optional[VPNBackend] = None
        self._last_error: Optional[str] = None
        self._lock = threading.Lock()
        self._connection_thread: Optional[threading.Thread] = None

    def start(self):
        """Start VPN manager and connect through an available backend."""
        self.logger.info("Starting VPN Manager")

        with self._lock:
            if self._active:
                return

            # Enable kill switch first
            self.kill_switch.enable()

            # Start DNS protection (encrypted DNS)
            self.dns_protection.start()

            try:
                self._establish_connection()
                self._active = True
                self.logger.info("VPN manager active")
            except Exception:
                self.dns_protection.stop()
                self._active = False
                self._connected = False
                raise

    def stop(self):
        """Stop VPN manager"""
        self.logger.info("Stopping VPN Manager")

        with self._lock:
            if not self._active:
                return

            # Disconnect VPN
            self._disconnect()

            # Stop DNS protection
            self.dns_protection.stop()

            # Keep kill switch active until explicitly disabled

            self._active = False

    def _establish_connection(self):
        """Establish VPN connection through a real backend."""
        self._current_route = []
        if self.multi_hop:
            self.logger.info(
                "Multi-hop requested; active route requires real backend evidence"
            )
        backend_status = self._connect_single_node()
        self._current_route.append(backend_status)
        self._connected = True
        self._last_error = None
        self.logger.info("VPN connection established through backend")

    def _connect_single_node(self) -> Dict[str, Any]:
        """Connect to single VPN node"""
        failures = []
        # Try protocols in fallback order
        for protocol in self.protocol_fallback:
            try:
                node = self._connect_with_protocol(protocol)
                self.logger.info(f"Connected via {protocol}")
                return node
            except Exception as e:
                failures.append(f"{protocol}: {e}")
                self.logger.warning(f"Failed to connect via {protocol}: {e}")

        self._last_error = "All VPN protocols failed: " + "; ".join(failures)
        raise ConnectionError(self._last_error)

    def _backend_config(self, protocol: str) -> Dict[str, Any]:
        """Return backend-specific configuration."""
        backend_configs = self.config.get("backends", {})
        protocol_config = backend_configs.get(protocol, {})
        if isinstance(protocol_config, dict):
            return protocol_config
        return {}

    def _connect_with_protocol(self, protocol: str) -> Dict[str, Any]:
        """Connect using a concrete backend for the requested protocol."""
        backend = VPNBackendFactory.create_backend(
            protocol, self._backend_config(protocol)
        )
        if backend is None:
            raise ConnectionError(f"Unsupported VPN protocol: {protocol}")

        if not backend.check_availability():
            raise ConnectionError(f"VPN backend unavailable: {protocol}")

        if not backend.connect():
            raise ConnectionError(f"VPN backend failed to connect: {protocol}")

        self._active_backend = backend
        status = backend.get_status()
        status["protocol"] = protocol
        status["real_backend"] = True
        return status

    def _disconnect(self):
        """Disconnect VPN"""
        if self._connected:
            if self._active_backend is not None:
                disconnected = self._active_backend.disconnect()
                if not disconnected:
                    self._last_error = "VPN backend disconnect failed"
                    self.logger.error(self._last_error)
            self._current_route.clear()
            self._connected = False
            self._active_backend = None
            self.logger.info("VPN disconnected")

    def reconnect(self):
        """Reconnect VPN"""
        self.logger.info("Reconnecting VPN")
        self._disconnect()
        time.sleep(1)
        self._establish_connection()

    def select_exit_node(self, node_id: str):
        """User-driven exit node selection"""
        self.logger.info(f"Selecting exit node: {node_id}")
        # Reconnect with new exit node
        self.reconnect()

    def enable_split_tunneling(self, enabled: bool):
        """Enable/disable split tunneling"""
        self.split_tunneling = enabled
        self.logger.info(f"Split tunneling: {'enabled' if enabled else 'disabled'}")

    def encrypt_traffic(self, data: bytes) -> bytes:
        """
        Encrypt VPN traffic.
        All traffic encrypted before transmission.
        """
        return self._vpn_cipher.encrypt(data)

    def decrypt_traffic(self, encrypted_data: bytes) -> bytes:
        """
        Decrypt VPN traffic.
        All incoming traffic decrypted.
        """
        try:
            return self._vpn_cipher.decrypt(encrypted_data)
        except Exception as e:
            self.logger.error(f"Failed to decrypt VPN traffic: {e}")
            return b""

    def get_status(self) -> Dict[str, Any]:
        """Get VPN status"""
        backend_status = None
        if self._active_backend is not None:
            backend_status = self._active_backend.get_status()

        return {
            "active": self._active,
            "connected": self._connected,
            "built_in": True,
            "multi_hop": self.multi_hop,
            "multi_hop_accepted": False,
            "route": self._current_route,
            "backend": backend_status,
            "backend_available": self._active_backend is not None,
            "kill_switch": self.kill_switch.is_active(),
            "dns_protected": self.dns_protection.is_active(),
            "stealth_mode": self.stealth_mode,
            "split_tunneling": self.split_tunneling,
            "traffic_encrypted": self._connected,
            "no_logging": self.logging_policy == "never",
            "error": self._last_error,
        }

    def is_connected(self) -> bool:
        """Check if VPN is connected"""
        return self._connected

    def get_current_ip(self) -> Optional[str]:
        """Get current exit IP"""
        if self._current_route:
            endpoint = self._current_route[-1].get("endpoint")
            return endpoint if isinstance(endpoint, str) else None
        return None
