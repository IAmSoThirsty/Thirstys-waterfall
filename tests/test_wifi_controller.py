import pytest

from thirstys_waterfall.wifi_network.wifi_controller import (
    WiFiBand,
    WiFiController,
    WiFiNetwork,
)


class WiFiBackend:
    def __init__(self):
        self.network = WiFiNetwork(
            ssid="ProjectAI",
            bssid="aa:bb:cc:dd:ee:ff",
            band=WiFiBand.BAND_5_GHZ,
            channel=36,
            frequency_mhz=5180,
            signal_strength_dbm=-45,
            security=["WPA3"],
            max_rate_mbps=1200,
            bandwidth_mhz=80,
            supports_wifi6=True,
            supports_wifi7=False,
        )

    def scan_networks(self, band=None):
        return [self.network]

    def connect(self, ssid, password=None, security=None):
        return {"connected": True, "network": self.network, "security": security}

    def disconnect(self, network=None):
        return {"disconnected": True, "interface": "wlan0"}

    def optimize_channel(self, band, networks=None):
        return {"channel": 149, "sample_count": len(networks or [])}

    def get_driver_windows(self, interface):
        return f"Driver for {interface}"


class IntegerChannelWiFiBackend(WiFiBackend):
    def optimize_channel(self, band, networks=None):
        return 44


class InvalidChannelWiFiBackend(WiFiBackend):
    def optimize_channel(self, band, networks=None):
        return {"channel": "44"}


def test_linux_iw_scan_parser_extracts_networks():
    output = """
BSS aa:bb:cc:dd:ee:ff(on wlan0)
        freq: 5180
        signal: -45.00 dBm
        SSID: ProjectAI
        DS Parameter set: channel 36
        RSN:     * Version: 1
                 * Authentication suites: SAE
        VHT capabilities:
        HE capabilities:
"""
    controller = WiFiController(config={"skip_discovery": True})

    networks = controller._parse_scan_results_linux(output, None)

    assert len(networks) == 1
    network = networks[0]
    assert network.ssid == "ProjectAI"
    assert network.bssid == "aa:bb:cc:dd:ee:ff"
    assert network.band == WiFiBand.BAND_5_GHZ
    assert network.security == ["WPA3", "WPA2"]
    assert network.supports_wifi6 is True


def test_windows_netsh_scan_parser_extracts_networks():
    output = """
SSID 1 : ProjectAI
    Network type            : Infrastructure
    Authentication          : WPA3-Personal
    Encryption              : CCMP
    BSSID 1                 : aa:bb:cc:dd:ee:ff
         Signal             : 86%
         Radio type         : 802.11ax
         Band               : 5 GHz
         Channel            : 36
         Basic rates (Mbps) : 6 12 24
         Other rates (Mbps) : 48 54
"""
    controller = WiFiController(config={"skip_discovery": True})

    networks = controller._parse_scan_results_windows(output, WiFiBand.BAND_5_GHZ)

    assert len(networks) == 1
    network = networks[0]
    assert network.ssid == "ProjectAI"
    assert network.signal_strength_dbm == -57
    assert network.security == ["WPA3"]
    assert network.max_rate_mbps == 54
    assert network.supports_wifi6 is True


def test_macos_airport_scan_parser_extracts_networks():
    output = """
                            SSID BSSID             RSSI CHANNEL HT CC SECURITY
                       ProjectAI aa:bb:cc:dd:ee:ff -62  11      Y  US WPA2(PSK/AES/AES)
"""
    controller = WiFiController(config={"skip_discovery": True})

    networks = controller._parse_scan_results_macos(output, WiFiBand.BAND_2_4_GHZ)

    assert len(networks) == 1
    network = networks[0]
    assert network.ssid == "ProjectAI"
    assert network.channel == 11
    assert network.frequency_mhz == 2462
    assert network.security == ["WPA2"]


def test_backend_scan_connect_disconnect_and_optimize_records_evidence():
    backend = WiFiBackend()
    controller = WiFiController(
        config={"skip_discovery": True}, wifi_backend=backend
    )

    networks = controller.scan_networks(WiFiBand.BAND_5_GHZ)
    assert networks == [backend.network]
    assert controller.connect("ProjectAI", "secret", "WPA3") is True
    assert controller.connected_network == backend.network
    assert controller.optimize_channel(WiFiBand.BAND_5_GHZ) == 149
    assert controller.disconnect() is True

    status = controller.get_status()
    assert status["backend"] == "WiFiBackend"
    assert status["connected"] is False
    assert status["last_operation_results"]["scan_networks"]["network_count"] == 1
    assert status["last_operation_results"]["connect"]["connected"] is True
    assert status["last_operation_results"]["disconnect"]["disconnected"] is True
    assert status["last_operation_results"]["optimize_channel"]["sample_count"] == 1


def test_optimize_channel_accepts_integer_backend_result():
    controller = WiFiController(
        config={"skip_discovery": True}, wifi_backend=IntegerChannelWiFiBackend()
    )

    assert controller.optimize_channel(WiFiBand.BAND_5_GHZ) == 44


def test_optimize_channel_rejects_non_integer_channel():
    controller = WiFiController(
        config={"skip_discovery": True}, wifi_backend=InvalidChannelWiFiBackend()
    )

    with pytest.raises(ValueError, match="integer or null 'channel'"):
        controller.optimize_channel(WiFiBand.BAND_5_GHZ)


def test_connect_and_optimize_without_backend_fail_closed():
    controller = WiFiController(config={"skip_discovery": True})

    assert controller.connect("ProjectAI", "secret", "WPA3") is False
    assert controller.optimize_channel(WiFiBand.BAND_5_GHZ) is None

    status = controller.get_status()
    assert status["last_operation_results"]["connect"]["status"] == "unavailable"
    assert (
        status["last_operation_results"]["optimize_channel"]["status"]
        == "unavailable"
    )


def test_disconnect_without_backend_fails_closed_when_connected():
    controller = WiFiController(config={"skip_discovery": True})
    controller.connected_network = WiFiNetwork(
        ssid="ProjectAI",
        bssid="aa:bb:cc:dd:ee:ff",
        band=WiFiBand.BAND_5_GHZ,
        channel=36,
        frequency_mhz=5180,
        signal_strength_dbm=-45,
        security=["WPA3"],
        max_rate_mbps=1200,
        bandwidth_mhz=80,
        supports_wifi6=True,
        supports_wifi7=False,
    )

    assert controller.disconnect() is False
    assert (
        controller.get_status()["last_operation_results"]["disconnect"]["status"]
        == "unavailable"
    )
