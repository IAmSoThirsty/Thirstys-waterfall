"""Kill Switch implementation"""

from typing import Callable, List, Optional, Any, Dict
import logging
import threading


class KillSwitch:
    """
    Kill Switch ensures no traffic leaks if VPN disconnects.
    Integrated with browser, VPN, and firewall layers.
    """

    def __init__(self, enabled: bool = True, traffic_blocker: Optional[Any] = None):
        self.enabled = enabled
        self.traffic_blocker = traffic_blocker
        self.logger = logging.getLogger(__name__)
        self._active = False
        self._callbacks: List[Callable] = []
        self._lock = threading.Lock()
        self._monitoring = False
        self._traffic_block_result: Optional[Dict[str, Any]] = None
        self._traffic_restore_result: Optional[Dict[str, Any]] = None

    def enable(self):
        """Enable kill switch"""
        with self._lock:
            self._active = True
            self.logger.info("Kill switch enabled")
            self._start_monitoring()

    def disable(self):
        """Disable kill switch"""
        with self._lock:
            self._active = False
            self._monitoring = False
            self.logger.info("Kill switch disabled")

    def _start_monitoring(self):
        """Start monitoring VPN connection"""
        if not self._monitoring:
            self._monitoring = True
            # In production, would monitor connection state

    def trigger(self, reason: str = "VPN disconnected"):
        """
        Trigger kill switch - block all traffic.

        Args:
            reason: Reason for triggering kill switch
        """
        if not self._active:
            return

        self.logger.critical(f"KILL SWITCH TRIGGERED: {reason}")

        # Block all network traffic
        self._block_all_traffic()

        # Notify all registered callbacks
        self._notify_callbacks(reason)

    def _block_all_traffic(self):
        """Block all network traffic"""
        self.logger.info("Blocking all network traffic")
        if self.traffic_blocker is None:
            self._traffic_block_result = {
                "status": "unavailable",
                "error": "VPN traffic blocker backend is not configured",
                "traffic_blocked": False,
            }
            self.logger.critical(self._traffic_block_result["error"])
            return self._traffic_block_result

        block_all = getattr(self.traffic_blocker, "block_all_traffic", None)
        if not callable(block_all):
            raise RuntimeError(
                "VPN traffic blocker backend does not implement block_all_traffic"
            )

        result = block_all()
        if not isinstance(result, dict):
            raise RuntimeError("VPN traffic blocker backend returned invalid result")

        result.setdefault("status", "unknown")
        result.setdefault("traffic_blocked", result["status"] == "blocked")
        result.setdefault("backend", type(self.traffic_blocker).__name__)
        self._traffic_block_result = result
        return result

    def register_callback(self, callback: Callable):
        """Register callback to be called when kill switch triggers"""
        self._callbacks.append(callback)

    def _notify_callbacks(self, reason: str):
        """Notify all registered callbacks"""
        for callback in self._callbacks:
            try:
                callback(reason)
            except Exception as e:
                self.logger.error(f"Callback error: {e}")

    def is_active(self) -> bool:
        """Check if kill switch is active"""
        return self._active

    def restore_traffic(self):
        """Restore traffic after kill switch trigger"""
        if self._active:
            self.logger.info("Restoring traffic after kill switch")
            if self.traffic_blocker is None:
                self._traffic_restore_result = {
                    "status": "unavailable",
                    "error": "VPN traffic blocker backend is not configured",
                    "traffic_restored": False,
                }
                self.logger.error(self._traffic_restore_result["error"])
                return self._traffic_restore_result

            restore = getattr(self.traffic_blocker, "restore_traffic", None)
            if not callable(restore):
                raise RuntimeError(
                    "VPN traffic blocker backend does not implement restore_traffic"
                )

            result = restore()
            if not isinstance(result, dict):
                raise RuntimeError(
                    "VPN traffic blocker backend returned invalid restore result"
                )

            result.setdefault("status", "unknown")
            result.setdefault("traffic_restored", result["status"] == "restored")
            result.setdefault("backend", type(self.traffic_blocker).__name__)
            self._traffic_restore_result = result
            return result

        return {
            "status": "inactive",
            "traffic_restored": False,
            "backend_configured": self.traffic_blocker is not None,
        }

    def get_traffic_block_status(self) -> Dict[str, Any]:
        """Return latest traffic blocking evidence."""
        if self._traffic_block_result is None:
            return {
                "status": "not_attempted",
                "traffic_blocked": False,
                "backend_configured": self.traffic_blocker is not None,
                "backend": (
                    type(self.traffic_blocker).__name__
                    if self.traffic_blocker is not None
                    else None
                ),
            }
        return {
            **self._traffic_block_result,
            "backend_configured": self.traffic_blocker is not None,
            "backend": (
                type(self.traffic_blocker).__name__
                if self.traffic_blocker is not None
                else None
            ),
        }

    def get_traffic_restore_status(self) -> Dict[str, Any]:
        """Return latest traffic restore evidence."""
        if self._traffic_restore_result is None:
            return {
                "status": "not_attempted",
                "traffic_restored": False,
                "backend_configured": self.traffic_blocker is not None,
                "backend": (
                    type(self.traffic_blocker).__name__
                    if self.traffic_blocker is not None
                    else None
                ),
            }
        return {
            **self._traffic_restore_result,
            "backend_configured": self.traffic_blocker is not None,
            "backend": (
                type(self.traffic_blocker).__name__
                if self.traffic_blocker is not None
                else None
            ),
        }
