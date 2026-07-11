import pytest

from thirstys_waterfall.wifi_network.wifi_security import (
    WiFiSecurityConfig,
    WiFiSecurityManager,
    WiFiSecurityProtocol,
)


class EvidenceBackend:
    def detect_deauth_attack(self, current_security=None):
        return {
            "status": "checked",
            "attack_detected": True,
            "frames_observed": 42,
            "window_seconds": 10,
        }

    def detect_evil_twin(self, ssid, bssid, current_security=None):
        return {
            "status": "checked",
            "evil_twin_detected": True,
            "ssid": ssid,
            "bssid": bssid,
            "matching_ssid_bssids": ["00:11:22:33:44:55", bssid],
        }

    def enable_fast_roaming(self, current_security=None):
        return {
            "status": "configured",
            "enabled": True,
            "adapter": "wlan0",
            "standard": "802.11r",
        }


def test_deauth_detection_without_backend_reports_unavailable():
    manager = WiFiSecurityManager()
    manager.current_security = WiFiSecurityConfig(
        protocol=WiFiSecurityProtocol.WPA2_PERSONAL,
        passphrase="long-enough-passphrase",
        enable_pmf=False,
    )

    assert manager.detect_deauth_attack() is False

    status = manager.get_security_status()
    check = status["last_security_checks"]["deauth_attack"]
    assert check["status"] == "unavailable"
    assert check["attack_detected"] is None
    assert status["backend_configured"] is False


def test_pmf_records_protection_without_claiming_monitoring_backend():
    manager = WiFiSecurityManager()
    manager.configure_security(
        WiFiSecurityConfig(
            protocol=WiFiSecurityProtocol.WPA3_PERSONAL,
            passphrase="long-enough-passphrase",
            enable_pmf=True,
        )
    )

    assert manager.detect_deauth_attack() is False

    check = manager.get_security_status()["last_security_checks"]["deauth_attack"]
    assert check["status"] == "protected_by_pmf"
    assert check["attack_detected"] is False
    assert check["backend"] is None


def test_wifi_security_backend_records_detection_evidence():
    manager = WiFiSecurityManager(security_backend=EvidenceBackend())
    manager.configure_security(
        WiFiSecurityConfig(
            protocol=WiFiSecurityProtocol.WPA2_PERSONAL,
            passphrase="long-enough-passphrase",
            enable_pmf=False,
        )
    )

    assert manager.detect_deauth_attack() is True
    assert manager.detect_evil_twin("ProjectAI", "aa:bb:cc:dd:ee:ff") is True

    status = manager.get_security_status()
    assert status["backend"] == "EvidenceBackend"
    assert status["last_security_checks"]["deauth_attack"]["frames_observed"] == 42
    assert status["last_security_checks"]["evil_twin"]["ssid"] == "ProjectAI"
    assert status["detected_threats"] == ["deauth_attack", "evil_twin"]


def test_fast_roaming_without_backend_fails_closed():
    manager = WiFiSecurityManager()

    assert manager.enable_fast_roaming() is False

    status = manager.get_security_status()
    check = status["last_security_checks"]["fast_roaming"]
    assert check["status"] == "unavailable"
    assert check["enabled"] is False
    assert status["fast_roaming_enabled"] is False


def test_fast_roaming_delegates_to_backend():
    manager = WiFiSecurityManager(security_backend=EvidenceBackend())

    assert manager.enable_fast_roaming() is True

    status = manager.get_security_status()
    check = status["last_security_checks"]["fast_roaming"]
    assert check["enabled"] is True
    assert check["standard"] == "802.11r"
    assert status["fast_roaming_enabled"] is True


def test_invalid_backend_result_fails_loudly():
    class InvalidBackend:
        def detect_deauth_attack(self, current_security=None):
            return {"status": "checked"}

    manager = WiFiSecurityManager(security_backend=InvalidBackend())
    manager.configure_security(
        WiFiSecurityConfig(
            protocol=WiFiSecurityProtocol.WPA2_PERSONAL,
            passphrase="long-enough-passphrase",
            enable_pmf=False,
        )
    )

    with pytest.raises(ValueError, match="attack_detected"):
        manager.detect_deauth_attack()
