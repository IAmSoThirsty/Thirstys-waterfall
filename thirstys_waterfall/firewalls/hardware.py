"""Hardware Firewall implementation"""

from typing import Dict, Any, Optional
from .base import FirewallBase


class HardwareFirewall(FirewallBase):
    """
    Hardware Firewall
    Requires a configured hardware backend for hardware-level packet filtering.
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.bypass_mode = config.get("bypass_mode", False)
        self.hardware_backend = config.get("hardware_backend")
        self._hardware_rules = []
        self._backend_status: Dict[str, Any] = {
            "status": "unavailable",
            "error": "Hardware firewall backend is not configured",
            "backend_configured": False,
        }
        self._last_backend_result: Optional[Dict[str, Any]] = None

    def start(self):
        """Start hardware firewall"""
        self.logger.info("Starting Hardware Firewall")
        self._active = True
        self._initialize_hardware()

    def stop(self):
        """Stop hardware firewall"""
        self.logger.info("Stopping Hardware Firewall")
        self._active = False

    def _initialize_hardware(self):
        """Initialize hardware-level filtering"""
        if self.hardware_backend is None:
            self._backend_status = {
                "status": "unavailable",
                "error": "Hardware firewall backend is not configured",
                "backend_configured": False,
            }
            self.logger.warning("Hardware firewall backend is not configured")
            return

        initialize = getattr(self.hardware_backend, "initialize", None)
        if callable(initialize):
            initialized = initialize()
            if initialized is False:
                raise RuntimeError("Hardware firewall backend initialization failed")

        self._backend_status = {
            "status": "ready",
            "backend": type(self.hardware_backend).__name__,
            "backend_configured": True,
        }
        self.logger.debug("Initialized hardware filtering backend")

    def add_rule(self, rule: Dict[str, Any]):
        """Add hardware firewall rule"""
        self._rules.append(rule)
        self._hardware_rules.append(rule)
        if self.hardware_backend is not None:
            add_rule = getattr(self.hardware_backend, "add_rule", None)
            if callable(add_rule):
                add_rule(rule)

    def remove_rule(self, rule_id: str):
        """Remove hardware firewall rule"""
        self._rules = [r for r in self._rules if r.get("id") != rule_id]
        self._hardware_rules = [
            r for r in self._hardware_rules if r.get("id") != rule_id
        ]
        if self.hardware_backend is not None:
            remove_rule = getattr(self.hardware_backend, "remove_rule", None)
            if callable(remove_rule):
                remove_rule(rule_id)

    def process_packet(self, packet: Dict[str, Any]) -> bool:
        """Process packet at hardware level"""
        if not self._active or self.bypass_mode:
            return True

        result = self._hardware_inspect(packet)
        if not result.get("allowed", False):
            self._update_statistics(False)
            return False

        self._update_statistics(True)
        return True

    def _hardware_inspect(self, packet: Dict[str, Any]) -> Dict[str, Any]:
        """Hardware-level packet inspection"""
        if self.hardware_backend is None:
            result = {
                "status": "unavailable",
                "error": "Hardware firewall backend is not configured",
                "allowed": False,
                "backend_configured": False,
            }
            self._last_backend_result = result
            self.logger.error(result["error"])
            return result

        inspect = getattr(self.hardware_backend, "inspect_packet", None)
        if not callable(inspect):
            raise RuntimeError(
                "Hardware firewall backend does not implement inspect_packet"
            )

        result = inspect(packet)
        if isinstance(result, bool):
            result = {"allowed": result}
        if not isinstance(result, dict) or "allowed" not in result:
            raise RuntimeError("Hardware firewall backend returned invalid result")

        result.setdefault("status", "verified")
        result.setdefault("backend", type(self.hardware_backend).__name__)
        result.setdefault("backend_configured", True)
        self._last_backend_result = result
        return result

    def set_bypass_mode(self, enabled: bool):
        """Enable/disable bypass mode"""
        self.bypass_mode = enabled
        self.logger.info(f"Bypass mode: {'enabled' if enabled else 'disabled'}")

    def get_hardware_status(self) -> Dict[str, Any]:
        """Get hardware firewall backend status."""
        status = self._backend_status.copy()
        status.update(
            {
                "active": self._active,
                "bypass_mode": self.bypass_mode,
                "rules": len(self._hardware_rules),
                "last_backend_result": self._last_backend_result,
            }
        )
        return status
