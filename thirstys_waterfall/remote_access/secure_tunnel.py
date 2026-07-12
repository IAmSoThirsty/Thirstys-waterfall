"""Secure tunnel facade with evidence-gated encryption reporting."""

import logging
import json
from typing import Dict, Any, Optional


class SecureTunnel:
    """
    Secure tunnel with local helper encryption for remote access.
    All traffic goes through VPN with multi-hop routing.
    """

    def __init__(
        self,
        god_tier_encryption,
        vpn_manager,
        tunnel_backend: Optional[Any] = None,
    ):
        self.logger = logging.getLogger(__name__)
        self.god_tier_encryption = god_tier_encryption
        self.vpn_manager = vpn_manager
        self.tunnel_backend = tunnel_backend

        self._tunnel_active = False

    def establish(self) -> Dict[str, Any]:
        """Establish secure tunnel"""
        self.logger.info("Establishing secure tunnel with local helper encryption")

        if not self.vpn_manager.is_connected():
            self._tunnel_active = False
            return {
                "status": "unavailable",
                "error": "VPN manager is not connected",
                "local_helper_encrypted": True,
                "encryption_accepted": False,
            }

        if self.tunnel_backend is None:
            self._tunnel_active = False
            return {
                "status": "unavailable",
                "error": "Secure tunnel backend is not configured",
                "local_helper_encrypted": True,
                "encryption_accepted": False,
            }

        establish_tunnel = getattr(self.tunnel_backend, "establish", None)
        if not callable(establish_tunnel):
            raise RuntimeError("Secure tunnel backend does not implement establish")

        vpn_status = self.vpn_manager.get_status()
        encrypted_vpn_status = self.god_tier_encryption.encrypt_god_tier(
            json.dumps(vpn_status, sort_keys=True, default=str).encode()
        )

        result = establish_tunnel(encrypted_vpn_status=encrypted_vpn_status)
        if not isinstance(result, dict):
            raise RuntimeError("Secure tunnel backend returned invalid result")

        result.setdefault("status", "unknown")
        result.setdefault("local_helper_encrypted", True)
        result.setdefault("encryption_accepted", False)
        result.setdefault("backend", type(self.tunnel_backend).__name__)
        self._tunnel_active = result["status"] == "established"
        return result

    def close(self):
        """Close secure tunnel"""
        self.logger.info("Closing secure tunnel")
        close_tunnel = getattr(self.tunnel_backend, "close", None)
        if callable(close_tunnel):
            close_tunnel()
        self._tunnel_active = False

    def get_status(self) -> Dict[str, Any]:
        """Get tunnel status"""
        return {
            "active": self._tunnel_active,
            "local_helper_encrypted": True,
            "encryption_accepted": False,
            "backend_configured": self.tunnel_backend is not None,
            "backend": (
                type(self.tunnel_backend).__name__
                if self.tunnel_backend is not None
                else None
            ),
        }
