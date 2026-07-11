"""WiFi Security Manager - God Tier Security with WPA3, OWE, SAE, and PMF"""

import logging
from typing import Any, Dict, List, Optional
from enum import Enum
from dataclasses import dataclass


class WiFiSecurityProtocol(Enum):
    """WiFi security protocols ordered by security level"""

    WPA3_ENTERPRISE = "wpa3-enterprise"  # God Tier
    WPA3_PERSONAL = "wpa3-personal"  # God Tier
    WPA2_ENTERPRISE = "wpa2-enterprise"  # Good
    WPA2_PERSONAL = "wpa2-personal"  # Acceptable
    OWE = "owe"  # Good for open networks
    OPEN = "open"  # Avoid
    WPA = "wpa"  # DEPRECATED
    WEP = "wep"  # DEPRECATED


@dataclass
class WiFiSecurityConfig:
    """WiFi security configuration"""

    protocol: WiFiSecurityProtocol
    passphrase: Optional[str] = None
    enable_pmf: bool = True  # Protected Management Frames (802.11w)
    enable_sae: bool = True  # Simultaneous Authentication of Equals (WPA3)
    transition_mode: bool = False  # WPA2/WPA3 transition mode


class WiFiSecurityManager:
    """
    God Tier WiFi Security Manager

    Provides WPA3, OWE, SAE, PMF (802.11w), and Fast BSS Transition (802.11r).
    Enforces God Tier security standards and blocks deprecated protocols.
    """

    def __init__(self, security_backend: Optional[Any] = None):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.current_security: Optional[WiFiSecurityConfig] = None
        self.security_backend = security_backend

        # Security monitoring
        self.detected_threats: List[str] = []
        self.deauth_attack_count = 0
        self.evil_twin_detected = False
        self.fast_roaming_enabled = False
        self.last_security_checks: Dict[str, Dict[str, Any]] = {}

    def configure_security(self, config: WiFiSecurityConfig) -> bool:
        """
        Configure WiFi security

        Args:
            config: Security configuration

        Returns:
            True if configuration successful
        """
        try:
            # Validate configuration
            if not self._validate_security_config(config):
                return False

            # Check for deprecated protocols
            if config.protocol in [WiFiSecurityProtocol.WEP, WiFiSecurityProtocol.WPA]:
                self.logger.error(
                    f"{config.protocol.value} is deprecated and insecure - REFUSED"
                )
                return False

            # Warn about non-God-Tier configurations
            if config.protocol not in [
                WiFiSecurityProtocol.WPA3_PERSONAL,
                WiFiSecurityProtocol.WPA3_ENTERPRISE,
            ]:
                self.logger.warning(
                    f"{config.protocol.value} is not God Tier - consider WPA3"
                )

            # Enforce PMF (Protected Management Frames)
            if not config.enable_pmf:
                self.logger.warning(
                    "PMF disabled - FORCING ENABLE for God Tier security"
                )
                config.enable_pmf = True

            self.current_security = config
            self.logger.info(f"Security configured: {config.protocol.value} with PMF")

            return True

        except Exception as e:
            self.logger.error(f"Security configuration failed: {e}")
            return False

    def _validate_security_config(self, config: WiFiSecurityConfig) -> bool:
        """Validate security configuration"""
        # Check required passphrase for encrypted protocols
        if config.protocol in [
            WiFiSecurityProtocol.WPA2_PERSONAL,
            WiFiSecurityProtocol.WPA3_PERSONAL,
        ]:
            if not config.passphrase:
                self.logger.error("Passphrase required for Personal security")
                return False

            # Enforce strong passphrase
            if len(config.passphrase) < 12:
                self.logger.error(
                    "Passphrase must be at least 12 characters for God Tier security"
                )
                return False

        return True

    def get_recommended_config(
        self, network_type: str = "personal"
    ) -> WiFiSecurityConfig:
        """
        Get God Tier recommended security configuration

        Args:
            network_type: 'personal', 'enterprise', or 'open'

        Returns:
            Recommended security configuration
        """
        if network_type == "personal":
            return WiFiSecurityConfig(
                protocol=WiFiSecurityProtocol.WPA3_PERSONAL,
                enable_pmf=True,
                enable_sae=True,
                transition_mode=False,  # Pure WPA3
            )

        elif network_type == "enterprise":
            return WiFiSecurityConfig(
                protocol=WiFiSecurityProtocol.WPA3_ENTERPRISE,
                enable_pmf=True,
                enable_sae=True,
                transition_mode=False,
            )

        elif network_type == "open":
            # Use OWE for encryption on open networks
            return WiFiSecurityConfig(
                protocol=WiFiSecurityProtocol.OWE, enable_pmf=True, enable_sae=False
            )

        else:
            # Default to WPA3-Personal
            return self.get_recommended_config("personal")

    def detect_deauth_attack(self) -> bool:
        """
        Detect WiFi deauthentication attack

        Returns:
            True if attack detected
        """
        detector = getattr(self.security_backend, "detect_deauth_attack", None)

        if (
            self.current_security
            and self.current_security.enable_pmf
            and not callable(detector)
        ):
            self.logger.debug("PMF active - deauth attacks prevented")
            self._record_security_check(
                "deauth_attack",
                {
                    "status": "protected_by_pmf",
                    "attack_detected": False,
                    "backend": None,
                    "evidence": "Protected Management Frames are enabled",
                },
            )
            return False

        if not callable(detector):
            self.logger.warning(
                "PMF not active and no WiFi security backend is configured "
                "for deauth monitoring"
            )
            self._record_security_check(
                "deauth_attack",
                {
                    "status": "unavailable",
                    "attack_detected": None,
                    "backend": None,
                    "error": (
                        "WiFi security backend is not configured for "
                        "deauth monitoring"
                    ),
                },
            )
            return False

        result = detector(current_security=self.current_security)
        normalized = self._normalize_bool_or_dict_result(
            result, "attack_detected", "deauth monitoring"
        )
        normalized.setdefault("status", "checked")
        normalized["backend"] = self.security_backend.__class__.__name__
        self._record_security_check("deauth_attack", normalized)

        attack_detected = normalized["attack_detected"]
        if attack_detected:
            self.deauth_attack_count += 1
            self._add_detected_threat("deauth_attack")

        return attack_detected

    def detect_evil_twin(self, ssid: str, bssid: str) -> bool:
        """
        Detect evil twin access point

        Args:
            ssid: Network SSID
            bssid: Access point BSSID (MAC)

        Returns:
            True if evil twin suspected
        """
        detector = getattr(self.security_backend, "detect_evil_twin", None)
        if not callable(detector):
            self.logger.warning(
                "No WiFi security backend is configured for evil-twin checks"
            )
            self._record_security_check(
                "evil_twin",
                {
                    "status": "unavailable",
                    "evil_twin_detected": None,
                    "backend": None,
                    "error": (
                        "WiFi security backend is not configured for "
                        "evil-twin checks"
                    ),
                    "ssid": ssid,
                    "bssid": bssid,
                },
            )
            return False

        result = detector(
            ssid=ssid, bssid=bssid, current_security=self.current_security
        )
        normalized = self._normalize_bool_or_dict_result(
            result, "evil_twin_detected", "evil-twin detection"
        )
        normalized.setdefault("status", "checked")
        normalized["backend"] = self.security_backend.__class__.__name__
        normalized.setdefault("ssid", ssid)
        normalized.setdefault("bssid", bssid)
        self._record_security_check("evil_twin", normalized)

        evil_twin_detected = normalized["evil_twin_detected"]
        self.evil_twin_detected = evil_twin_detected
        if evil_twin_detected:
            self._add_detected_threat("evil_twin")

        return evil_twin_detected

    def enable_fast_roaming(self) -> bool:
        """
        Enable 802.11r Fast BSS Transition for seamless roaming

        Returns:
            True if enabled successfully
        """
        try:
            self.logger.info("Enabling 802.11r Fast BSS Transition")
            enabler = getattr(self.security_backend, "enable_fast_roaming", None)
            if not callable(enabler):
                self.logger.error(
                    "No WiFi security backend is configured for 802.11r"
                )
                self.fast_roaming_enabled = False
                self._record_security_check(
                    "fast_roaming",
                    {
                        "status": "unavailable",
                        "enabled": False,
                        "backend": None,
                        "error": (
                            "WiFi security backend is not configured for "
                            "802.11r Fast BSS Transition"
                        ),
                    },
                )
                return False

            result = enabler(current_security=self.current_security)
            normalized = self._normalize_bool_or_dict_result(
                result, "enabled", "fast roaming configuration"
            )
            normalized.setdefault("status", "configured")
            normalized["backend"] = self.security_backend.__class__.__name__
            self._record_security_check("fast_roaming", normalized)

            self.fast_roaming_enabled = normalized["enabled"]
            return self.fast_roaming_enabled

        except Exception as e:
            self.logger.error(f"Fast roaming enable failed: {e}")
            self.fast_roaming_enabled = False
            self._record_security_check(
                "fast_roaming",
                {"status": "error", "enabled": False, "error": str(e)},
            )
            return False

    def get_security_status(self) -> Dict:
        """Get current security status"""
        if not self.current_security:
            return {
                "configured": False,
                "security_level": "NONE",
                "backend_configured": self.security_backend is not None,
                "backend": self._backend_name(),
                "fast_roaming_enabled": self.fast_roaming_enabled,
                "last_security_checks": dict(self.last_security_checks),
            }

        # Determine security level
        if self.current_security.protocol in [WiFiSecurityProtocol.WPA3_ENTERPRISE]:
            level = "MAXIMUM (God Tier)"
        elif self.current_security.protocol == WiFiSecurityProtocol.WPA3_PERSONAL:
            level = "HIGH (God Tier)"
        elif self.current_security.protocol == WiFiSecurityProtocol.WPA2_ENTERPRISE:
            level = "MEDIUM"
        elif self.current_security.protocol == WiFiSecurityProtocol.WPA2_PERSONAL:
            level = "LOW"
        else:
            level = "AVOID"

        return {
            "configured": True,
            "protocol": self.current_security.protocol.value,
            "security_level": level,
            "pmf_enabled": self.current_security.enable_pmf,
            "sae_enabled": self.current_security.enable_sae,
            "transition_mode": self.current_security.transition_mode,
            "detected_threats": self.detected_threats,
            "deauth_attack_protected": self.current_security.enable_pmf,
            "backend_configured": self.security_backend is not None,
            "backend": self._backend_name(),
            "fast_roaming_enabled": self.fast_roaming_enabled,
            "last_security_checks": dict(self.last_security_checks),
        }

    def audit_security(self) -> Dict:
        """
        Perform security audit

        Returns:
            Audit results with recommendations
        """
        recommendations = []
        warnings = []

        if not self.current_security:
            warnings.append("No security configured - CRITICAL")
            recommendations.append(
                "Configure WPA3-Personal or WPA3-Enterprise immediately"
            )
            return {
                "security_level": "CRITICAL",
                "warnings": warnings,
                "recommendations": recommendations,
            }

        # Check protocol
        if self.current_security.protocol in [
            WiFiSecurityProtocol.WPA,
            WiFiSecurityProtocol.WEP,
        ]:
            warnings.append(
                f"{self.current_security.protocol.value} is DEPRECATED and INSECURE"
            )
            recommendations.append("IMMEDIATELY upgrade to WPA3")

        elif self.current_security.protocol == WiFiSecurityProtocol.WPA2_PERSONAL:
            warnings.append("WPA2-Personal is acceptable but not God Tier")
            recommendations.append("Upgrade to WPA3-Personal for God Tier security")

        # Check PMF
        if not self.current_security.enable_pmf:
            warnings.append(
                "PMF (Protected Management Frames) DISABLED - vulnerable to attacks"
            )
            recommendations.append("ENABLE PMF immediately")

        # Check SAE for WPA3
        if self.current_security.protocol in [
            WiFiSecurityProtocol.WPA3_PERSONAL,
            WiFiSecurityProtocol.WPA3_ENTERPRISE,
        ]:
            if not self.current_security.enable_sae:
                warnings.append("SAE disabled for WPA3 - not recommended")
                recommendations.append("Enable SAE for full WPA3 benefits")

        return {
            "security_level": self.get_security_status()["security_level"],
            "warnings": warnings,
            "recommendations": recommendations,
            "god_tier_compliant": self.current_security.protocol
            in [
                WiFiSecurityProtocol.WPA3_PERSONAL,
                WiFiSecurityProtocol.WPA3_ENTERPRISE,
            ]
            and self.current_security.enable_pmf,
            "backend_configured": self.security_backend is not None,
            "last_security_checks": dict(self.last_security_checks),
        }

    def _record_security_check(self, check_name: str, result: Dict[str, Any]) -> None:
        """Record latest evidence for a security check."""
        self.last_security_checks[check_name] = result

    def _normalize_bool_or_dict_result(
        self, result: Any, bool_field: str, operation: str
    ) -> Dict[str, Any]:
        """Normalize backend bool/dict result and fail loudly on invalid output."""
        if isinstance(result, bool):
            return {bool_field: result}

        if not isinstance(result, dict):
            raise TypeError(
                f"WiFi security backend {operation} must return bool or dict"
            )

        if bool_field not in result or not isinstance(result[bool_field], bool):
            raise ValueError(
                f"WiFi security backend {operation} result must include "
                f"boolean {bool_field!r}"
            )

        return dict(result)

    def _add_detected_threat(self, threat_name: str) -> None:
        if threat_name not in self.detected_threats:
            self.detected_threats.append(threat_name)

    def _backend_name(self) -> Optional[str]:
        if self.security_backend is None:
            return None
        return self.security_backend.__class__.__name__
