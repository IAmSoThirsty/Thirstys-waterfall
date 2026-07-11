"""
Thirstys Waterfall Orchestrator
Main integration layer coordinating all subsystems
Runtime status remains gated by the Standard v3 acceptance matrix.
"""

import logging
from typing import Dict, Any, Optional
import sys
from cryptography.fernet import Fernet

from .config import ConfigRegistry, ConfigValidator
from .firewalls import FirewallManager
from .vpn import VPNManager
from .browser import IncognitoBrowser
from .privacy import (
    AntiFingerprintEngine,
    AntiTrackerEngine,
    AntiPhishingEngine,
    AntiMalwareEngine,
    PrivacyAuditor,
    OnionRouter,
)
from .storage import PrivacyVault, EphemeralStorage
from .kill_switch import GlobalKillSwitch
from .utils.encrypted_logging import EncryptedLogger
from .utils.encrypted_network import EncryptedNetworkHandler
from .utils.god_tier_encryption import GodTierEncryption, QuantumResistantEncryption


class ThirstysWaterfall:
    """
    Main orchestrator for Thirstys Waterfall privacy-first system.

    Integrates:
    - 8 firewall types (Packet-Filtering, Circuit Level, Stateful Inspection,
      Proxy, Next Generation, Software, Hardware, Cloud)
    - BUILT-IN VPN with multi-hop routing and kill switch
    - Incognito browser with no pop-ups, redirects, history, cache, or cookies
    - Privacy vault and encrypted storage
    - Anti-fingerprinting, anti-tracking, anti-phishing, anti-malware
    - DNS-over-HTTPS and onion routing
    - Global kill switch coordinating all subsystems
    """

    def __init__(self, config_path: Optional[str] = None):
        # Setup logging
        self._setup_logging()

        self.logger = logging.getLogger(__name__)
        self.logger.info("=" * 70)
        self.logger.info("Initializing Thirstys Waterfall")
        self.logger.info("Standard v3 status: in progress")
        self.logger.info("=" * 70)

        # Encryption helpers are available, but acceptance is evidence-gated.
        self.god_tier_encryption = GodTierEncryption()
        self.quantum_encryption = QuantumResistantEncryption()

        # Log encryption details
        strength = self.god_tier_encryption.get_encryption_strength()
        self.logger.info(f"Encryption Tier: {strength['tier']}")
        self.logger.info(f"Encryption Layers: {strength['layers']}")
        self.logger.info(f"Quantum Resistant: {strength['quantum_resistant']}")
        self.logger.info(
            f"Perfect Forward Secrecy: {strength['perfect_forward_secrecy']}"
        )

        # Master encryption key for local helper components.
        self._master_cipher = Fernet(Fernet.generate_key())

        # Initialize encrypted logger.
        self.encrypted_logger = EncryptedLogger(self._master_cipher)
        self.encrypted_logger.start()

        # Initialize encrypted network handler.
        self.encrypted_network = EncryptedNetworkHandler(self._master_cipher)

        # Initialize configuration registry.
        self.config = ConfigRegistry()
        self.config.initialize(config_path, encryption_key=Fernet.generate_key())

        # Validate configuration
        valid, errors = ConfigValidator.validate(self.config.export_config())
        if not valid:
            self.logger.error(f"Configuration validation failed: {errors}")
            raise ValueError(f"Invalid configuration: {errors}")

        # Initialize global kill switch
        self.kill_switch = GlobalKillSwitch()

        # Initialize all subsystems
        self._initialize_subsystems()

        self._active = False

    def _setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            handlers=[logging.StreamHandler(sys.stdout)],
        )

    def _initialize_subsystems(self):
        """Initialize all subsystems"""
        # Firewall Manager (all 8 types)
        self.firewall = FirewallManager(self.config.get_section("firewalls"))

        # VPN Manager
        self.vpn = VPNManager(self.config.get_section("vpn"))

        # Incognito Browser
        self.browser = IncognitoBrowser(self.config.get_section("browser"))

        # Privacy engines
        privacy_config = self.config.get_section("privacy")
        self.anti_fingerprint = AntiFingerprintEngine(privacy_config)
        self.anti_tracker = AntiTrackerEngine(privacy_config)
        self.anti_phishing = AntiPhishingEngine(privacy_config)
        self.anti_malware = AntiMalwareEngine(privacy_config)
        self.privacy_auditor = PrivacyAuditor(privacy_config)
        self.onion_router = OnionRouter(privacy_config)

        # Storage
        storage_config = self.config.get_section("storage")
        self.privacy_vault = PrivacyVault(storage_config)
        self.ephemeral_storage = EphemeralStorage(storage_config)

        # Register components with kill switch
        self.kill_switch.register_vpn_kill_switch(self.vpn.kill_switch)
        self.kill_switch.register_browser_kill_switch(self.browser)
        self.kill_switch.register_firewall_kill_switch(self.firewall)

    def start(self):
        """Start all subsystems"""
        self.logger.info("=" * 70)
        self.logger.info("STARTING THIRSTYS WATERFALL")
        self.logger.info("Runtime claims remain Standard v3 evidence-gated")
        self.logger.info("=" * 70)

        try:
            # Start encrypted network handler
            self.encrypted_network.start()

            # Enable global kill switch first
            self.kill_switch.enable()

            # Start firewalls (all 8 types)
            self.logger.info("Starting firewalls...")
            self.firewall.start()

            # Start VPN backend orchestration.
            self.logger.info("Starting VPN backend orchestration...")
            self.vpn.start()

            # Start privacy engines
            self.logger.info("Starting privacy engines...")
            self.anti_fingerprint.start()
            self.anti_tracker.start()
            self.anti_phishing.start()
            self.anti_malware.start()
            self.privacy_auditor.start()
            self.onion_router.start()

            # Start encrypted storage helpers.
            self.logger.info("Starting encrypted storage helpers...")
            self.privacy_vault.start()
            self.ephemeral_storage.start()

            # Start browser last (requires VPN)
            self.logger.info("Starting incognito browser...")
            self.browser.start()

            self._active = True

            self.logger.info("=" * 70)
            self.logger.info("THIRSTYS WATERFALL RUNTIME STARTED")
            self.logger.info("=" * 70)
            self.logger.info("Standard v3 acceptance: in progress")
            self.logger.info("See docs/operations/README_CLAIM_ACCEPTANCE.md")
            self.logger.info("=" * 70)

        except Exception as e:
            self.logger.error(f"Failed to start: {e}")
            self.stop()
            raise

    def stop(self):
        """Stop all subsystems"""
        self.logger.info("Stopping Thirstys Waterfall")

        try:
            # Stop browser first
            if hasattr(self, "browser"):
                self.browser.stop()

            # Stop privacy engines
            if hasattr(self, "anti_fingerprint"):
                self.anti_fingerprint.stop()
            if hasattr(self, "anti_tracker"):
                self.anti_tracker.stop()
            if hasattr(self, "anti_phishing"):
                self.anti_phishing.stop()
            if hasattr(self, "anti_malware"):
                self.anti_malware.stop()
            if hasattr(self, "privacy_auditor"):
                self.privacy_auditor.stop()
            if hasattr(self, "onion_router"):
                self.onion_router.stop()

            # Stop VPN
            if hasattr(self, "vpn"):
                self.vpn.stop()

            # Stop firewalls
            if hasattr(self, "firewall"):
                self.firewall.stop()

            # Stop storage
            if hasattr(self, "privacy_vault"):
                self.privacy_vault.stop()
            if hasattr(self, "ephemeral_storage"):
                self.ephemeral_storage.stop()

            # Disable kill switch last
            if hasattr(self, "kill_switch"):
                self.kill_switch.disable()

            self._active = False
            self.logger.info("Thirstys Waterfall stopped")

        except Exception as e:
            self.logger.error(f"Error during shutdown: {e}")

    def get_status(self) -> Dict[str, Any]:
        """Get comprehensive system status"""
        vpn_status = self.vpn.get_status()
        vault_active = self.privacy_vault.is_active()
        ephemeral_stats = self.ephemeral_storage.get_statistics()
        encryption_strength = self.god_tier_encryption.get_encryption_strength()
        traffic_encrypted = bool(vpn_status.get("traffic_encrypted"))

        return {
            "active": self._active,
            "standard_v3_status": "in_progress",
            "deployment_accepted": False,
            "encryption_tier": "not_accepted",
            "encryption_layers": None,
            "everything_encrypted": False,
            "everything_encrypted_accepted": False,
            "built_in_vpn": bool(vpn_status.get("connected")),
            "built_in_vpn_accepted": False,
            "kill_switch": {
                "enabled": self.kill_switch.is_active(),
                "triggered": self.kill_switch.is_triggered(),
            },
            "firewall": self.firewall.get_statistics(),
            "vpn": vpn_status,
            "browser": self.browser.get_status(),
            "privacy": {
                "anti_fingerprint": self.anti_fingerprint.get_protection_status(),
                "anti_tracker": self.anti_tracker.get_statistics(),
                "anti_phishing": self.anti_phishing.get_statistics(),
                "anti_malware": self.anti_malware.get_statistics(),
            },
            "storage": {
                "vault_active": vault_active,
                "ephemeral_stats": ephemeral_stats,
                "all_encrypted": False,
                "all_encrypted_accepted": False,
                "encryption_tier": "not_accepted",
            },
            "encryption": {
                "tier": "not_accepted",
                "layers": None,
                "accepted": False,
                "searches_encrypted": False,
                "sites_encrypted": False,
                "traffic_encrypted": traffic_encrypted,
                "storage_encrypted": vault_active,
                "logs_encrypted": self.encrypted_logger.is_active(),
                "config_encrypted": True,
                "algorithms": [
                    "AES-256-GCM",
                    "RSA-4096",
                    "ChaCha20-Poly1305",
                    "ECC-521",
                    "Fernet",
                ],
                "helper_strength": encryption_strength,
                "quantum_resistant": False,
                "perfect_forward_secrecy": False,
                "zero_knowledge": False,
            },
        }

    def run_privacy_audit(self) -> Dict[str, Any]:
        """Run comprehensive privacy audit"""
        return self.privacy_auditor.run_full_audit()

    def is_active(self) -> bool:
        """Check if system is active"""
        return self._active
