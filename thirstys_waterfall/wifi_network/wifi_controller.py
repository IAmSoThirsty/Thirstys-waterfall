"""
WiFi Controller - Full-Spectrum WiFi Network Direct Control
Supports 2.4GHz, 5GHz, 6GHz (WiFi 6E/7), and 60GHz (WiGig)
"""

import subprocess  # nosec B404
import platform
import logging
import shutil
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum


def _command_path(command: str) -> Optional[str]:
    """Resolve an executable path without invoking a shell."""
    return shutil.which(command)


class WiFiBand(Enum):
    """WiFi frequency bands"""

    BAND_2_4_GHZ = "2.4GHz"
    BAND_5_GHZ = "5GHz"
    BAND_6_GHZ = "6GHz"  # WiFi 6E/7
    BAND_60_GHZ = "60GHz"  # WiGig


class WiFiStandard(Enum):
    """WiFi standards (802.11)"""

    WIFI_4 = "802.11n"  # WiFi 4
    WIFI_5 = "802.11ac"  # WiFi 5
    WIFI_6 = "802.11ax"  # WiFi 6
    WIFI_6E = "802.11ax_6GHz"  # WiFi 6E
    WIFI_7 = "802.11be"  # WiFi 7
    WIGIG = "802.11ad/ay"  # 60GHz WiGig


@dataclass
class WiFiAdapter:
    """WiFi adapter information"""

    interface_name: str
    mac_address: str
    supported_bands: List[WiFiBand]
    supported_standards: List[WiFiStandard]
    max_speed_mbps: int
    supports_monitor_mode: bool
    supports_injection: bool
    supports_mesh: bool
    supports_mu_mimo: bool
    supports_beamforming: bool
    supports_ofdma: bool
    driver: str
    chipset: str


@dataclass
class WiFiNetwork:
    """Detected WiFi network"""

    ssid: str
    bssid: str
    band: WiFiBand
    channel: int
    frequency_mhz: int
    signal_strength_dbm: int
    security: List[str]  # WPA2, WPA3, OWE, etc.
    max_rate_mbps: int
    bandwidth_mhz: int  # 20, 40, 80, 160
    supports_wifi6: bool
    supports_wifi7: bool


class WiFiController:
    """
    Full-Spectrum WiFi Network Controller

    Features:
    - Direct WiFi adapter control (all bands)
    - Connection management with intelligent band steering
    - Spectrum analysis and channel optimization
    - Monitor mode for network analysis
    - Mesh networking support
    - God Tier WiFi security (WPA3, OWE, SAE)
    - Bandwidth marketplace integration
    """

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        wifi_backend: Optional[Any] = None,
    ):
        self.config = config or {}
        self.logger = logging.getLogger(self.__class__.__name__)
        self.platform = platform.system()
        self.wifi_backend = wifi_backend or self.config.get("wifi_backend")

        # Detected adapters and networks
        self.adapters: List[WiFiAdapter] = []
        self.available_networks: List[WiFiNetwork] = []
        self.connected_network: Optional[WiFiNetwork] = None
        self.last_operation_results: Dict[str, Dict[str, Any]] = {}

        # Performance settings
        self.enable_band_steering = self.config.get("band_steering", True)
        self.enable_beamforming = self.config.get("beamforming", True)
        self.enable_mu_mimo = self.config.get("mu_mimo", True)
        self.enable_ofdma = self.config.get("ofdma", True)

        # Bandwidth marketplace integration
        self.marketplace_mode = self.config.get("marketplace_mode", False)

        if not self.config.get("skip_discovery", False):
            self._discover_adapters()

    def _discover_adapters(self) -> None:
        """Discover available WiFi adapters on the system"""
        try:
            if self.platform == "Linux":
                self._discover_adapters_linux()
            elif self.platform == "Windows":
                self._discover_adapters_windows()
            elif self.platform == "Darwin":
                self._discover_adapters_macos()

            self.logger.info(f"Discovered {len(self.adapters)} WiFi adapter(s)")

        except Exception as e:
            self.logger.error(f"Adapter discovery failed: {e}")

    def _discover_adapters_linux(self) -> None:
        """Discover WiFi adapters on Linux using iw/iwconfig"""
        try:
            # Use 'iw dev' to list wireless interfaces
            iw = _command_path("iw") or "iw"
            result = subprocess.run(
                [iw, "dev"], capture_output=True, text=True, timeout=10
            )  # nosec B603

            if result.returncode == 0:
                lines = result.stdout.split("\n")
                current_interface = None

                for line in lines:
                    if "Interface" in line:
                        current_interface = line.split()[-1]

                    if current_interface and "addr" in line:
                        mac = line.split()[-1]

                        # Get detailed adapter capabilities
                        adapter = self._get_adapter_capabilities_linux(
                            current_interface, mac
                        )
                        if adapter:
                            self.adapters.append(adapter)

                        current_interface = None

        except FileNotFoundError:
            self.logger.warning("iw command not found - install iw package")
        except Exception as e:
            self.logger.error(f"Linux adapter discovery error: {e}")

    def _get_adapter_capabilities_linux(
        self, interface: str, mac: str
    ) -> Optional[WiFiAdapter]:
        """Get detailed capabilities of Linux WiFi adapter"""
        try:
            # Use 'iw phy' to get physical capabilities
            iw = _command_path("iw") or "iw"
            result = subprocess.run(
                [iw, "phy"], capture_output=True, text=True, timeout=10
            )  # nosec B603

            if result.returncode != 0:
                return None

            supported_bands = []
            supported_standards = []

            # Check for band support
            if "2.4 GHz" in result.stdout or "2400 MHz" in result.stdout:
                supported_bands.append(WiFiBand.BAND_2_4_GHZ)
            if "5 GHz" in result.stdout or "5000 MHz" in result.stdout:
                supported_bands.append(WiFiBand.BAND_5_GHZ)
            if "6 GHz" in result.stdout or "6000 MHz" in result.stdout:
                supported_bands.append(WiFiBand.BAND_6_GHZ)
            if "60 GHz" in result.stdout or "60000 MHz" in result.stdout:
                supported_bands.append(WiFiBand.BAND_60_GHZ)

            # Check for WiFi standards
            if "HE" in result.stdout or "WiFi 6" in result.stdout:
                supported_standards.append(WiFiStandard.WIFI_6)
                if WiFiBand.BAND_6_GHZ in supported_bands:
                    supported_standards.append(WiFiStandard.WIFI_6E)
            if "VHT" in result.stdout:
                supported_standards.append(WiFiStandard.WIFI_5)
            if "HT" in result.stdout:
                supported_standards.append(WiFiStandard.WIFI_4)

            # Check advanced features
            supports_mu_mimo = "MU-MIMO" in result.stdout
            supports_beamforming = "beamforming" in result.stdout.lower()
            supports_ofdma = "OFDMA" in result.stdout
            supports_monitor = "monitor" in result.stdout.lower()

            return WiFiAdapter(
                interface_name=interface,
                mac_address=mac,
                supported_bands=supported_bands,
                supported_standards=supported_standards,
                max_speed_mbps=self._estimate_max_speed(supported_standards),
                supports_monitor_mode=supports_monitor,
                supports_injection=supports_monitor,  # Usually correlated
                supports_mesh=True,  # Most modern adapters support mesh
                supports_mu_mimo=supports_mu_mimo,
                supports_beamforming=supports_beamforming,
                supports_ofdma=supports_ofdma,
                driver=self._get_driver_linux(interface),
                chipset=self._get_chipset_linux(interface),
            )

        except Exception as e:
            self.logger.error(f"Error getting adapter capabilities: {e}")
            return None

    def _discover_adapters_windows(self) -> None:
        """Discover WiFi adapters on Windows using netsh"""
        try:
            # Use netsh to list wireless interfaces
            netsh = _command_path("netsh") or "netsh"
            result = subprocess.run(
                [netsh, "wlan", "show", "interfaces"],
                capture_output=True,
                text=True,
                timeout=10,
            )  # nosec B603

            if result.returncode == 0:
                lines = result.stdout.split("\n")
                interface_name = None

                for line in lines:
                    if "Name" in line and ":" in line:
                        interface_name = line.split(":", 1)[1].strip()

                    if "Physical address" in line and interface_name:
                        mac = line.split(":", 1)[1].strip()

                        adapter = self._get_adapter_capabilities_windows(
                            interface_name, mac
                        )
                        if adapter:
                            self.adapters.append(adapter)

                        interface_name = None

        except Exception as e:
            self.logger.error(f"Windows adapter discovery error: {e}")

    def _get_adapter_capabilities_windows(
        self, interface: str, mac: str
    ) -> Optional[WiFiAdapter]:
        """Get WiFi adapter capabilities on Windows"""
        try:
            # Get detailed capabilities using netsh
            netsh = _command_path("netsh") or "netsh"
            result = subprocess.run(
                [netsh, "wlan", "show", "drivers"],
                capture_output=True,
                text=True,
                timeout=10,
            )  # nosec B603

            if result.returncode != 0:
                return None

            supported_bands = [WiFiBand.BAND_2_4_GHZ, WiFiBand.BAND_5_GHZ]
            supported_standards = [WiFiStandard.WIFI_4, WiFiStandard.WIFI_5]

            # Check for WiFi 6/6E support
            if "WiFi 6" in result.stdout or "ax" in result.stdout:
                supported_standards.append(WiFiStandard.WIFI_6)
            if "6E" in result.stdout or "6 GHz" in result.stdout:
                supported_bands.append(WiFiBand.BAND_6_GHZ)
                supported_standards.append(WiFiStandard.WIFI_6E)

            return WiFiAdapter(
                interface_name=interface,
                mac_address=mac,
                supported_bands=supported_bands,
                supported_standards=supported_standards,
                max_speed_mbps=self._estimate_max_speed(supported_standards),
                supports_monitor_mode=False,  # Limited on Windows
                supports_injection=False,
                supports_mesh=True,
                supports_mu_mimo=True,
                supports_beamforming=True,
                supports_ofdma="ax" in result.stdout.lower(),
                driver=self._get_driver_windows(interface),
                chipset="Unknown",
            )

        except Exception as e:
            self.logger.error(f"Error getting Windows adapter capabilities: {e}")
            return None

    def _discover_adapters_macos(self) -> None:
        """Discover WiFi adapters on macOS using airport utility"""
        try:
            # macOS typically has one primary WiFi interface (en0)
            result = subprocess.run(
                ["/usr/sbin/networksetup", "-listallhardwareports"],
                capture_output=True,
                text=True,
                timeout=10,
            )  # nosec B603

            if result.returncode == 0:
                lines = result.stdout.split("\n")

                for i, line in enumerate(lines):
                    if "Wi-Fi" in line:
                        # Next line typically has device name
                        if i + 1 < len(lines):
                            device_line = lines[i + 1]
                            if "Device:" in device_line:
                                interface = device_line.split(":", 1)[1].strip()

                                adapter = self._get_adapter_capabilities_macos(
                                    interface
                                )
                                if adapter:
                                    self.adapters.append(adapter)

        except Exception as e:
            self.logger.error(f"macOS adapter discovery error: {e}")

    def _get_adapter_capabilities_macos(self, interface: str) -> Optional[WiFiAdapter]:
        """Get WiFi adapter capabilities on macOS"""
        try:
            # Use system_profiler for detailed info
            system_profiler = _command_path("system_profiler") or "/usr/sbin/system_profiler"
            result = subprocess.run(
                [system_profiler, "SPAirPortDataType"],
                capture_output=True,
                text=True,
                timeout=10,
            )  # nosec B603

            if result.returncode != 0:
                return None

            # Get MAC address
            ifconfig = _command_path("ifconfig") or "/sbin/ifconfig"
            mac_result = subprocess.run(
                [ifconfig, interface], capture_output=True, text=True, timeout=5
            )  # nosec B603

            mac = "Unknown"
            if mac_result.returncode == 0:
                for line in mac_result.stdout.split("\n"):
                    if "ether" in line:
                        mac = line.split()[1]
                        break

            # Parse capabilities
            supported_bands = [WiFiBand.BAND_2_4_GHZ, WiFiBand.BAND_5_GHZ]
            supported_standards = [
                WiFiStandard.WIFI_4,
                WiFiStandard.WIFI_5,
                WiFiStandard.WIFI_6,
            ]

            # macOS typically supports WiFi 6 on newer devices
            if "WiFi 6" in result.stdout or "ax" in result.stdout:
                if "6E" in result.stdout:
                    supported_bands.append(WiFiBand.BAND_6_GHZ)
                    supported_standards.append(WiFiStandard.WIFI_6E)

            return WiFiAdapter(
                interface_name=interface,
                mac_address=mac,
                supported_bands=supported_bands,
                supported_standards=supported_standards,
                max_speed_mbps=self._estimate_max_speed(supported_standards),
                supports_monitor_mode=True,  # macOS supports monitor mode
                supports_injection=False,  # Limited
                supports_mesh=True,
                supports_mu_mimo=True,
                supports_beamforming=True,
                supports_ofdma=True,
                driver="Apple",
                chipset="Broadcom/Apple",
            )

        except Exception as e:
            self.logger.error(f"Error getting macOS adapter capabilities: {e}")
            return None

    def _estimate_max_speed(self, standards: List[WiFiStandard]) -> int:
        """Estimate maximum speed based on supported standards"""
        speed_map = {
            WiFiStandard.WIFI_4: 600,  # 802.11n
            WiFiStandard.WIFI_5: 1300,  # 802.11ac
            WiFiStandard.WIFI_6: 2400,  # 802.11ax
            WiFiStandard.WIFI_6E: 3600,  # 802.11ax (6 GHz)
            WiFiStandard.WIFI_7: 5800,  # 802.11be
            WiFiStandard.WIGIG: 4600,  # 60 GHz
        }

        return max([speed_map.get(std, 0) for std in standards]) if standards else 0

    def _get_driver_linux(self, interface: str) -> str:
        """Get driver name for Linux WiFi interface"""
        try:
            with open(f"/sys/class/net/{interface}/device/uevent", "r") as f:
                for line in f:
                    if "DRIVER=" in line:
                        return line.split("=")[1].strip()
        except Exception as e:
            self.logger.debug(f"Failed to read Linux driver for {interface}: {e}")
        return "Unknown"

    def _get_chipset_linux(self, interface: str) -> str:
        """Get chipset information for Linux WiFi interface"""
        try:
            lspci = _command_path("lspci") or "lspci"
            result = subprocess.run(
                [lspci, "-k"], capture_output=True, text=True, timeout=5
            )  # nosec B603

            if result.returncode == 0:
                # Parse lspci output for wireless controller
                for line in result.stdout.split("\n"):
                    if "Network controller" in line or "Wireless" in line:
                        return line.split(":", 1)[1].strip()
        except Exception as e:
            self.logger.debug(f"Failed to read Linux chipset for {interface}: {e}")
        return "Unknown"

    def _get_driver_windows(self, interface: str) -> str:
        """Get driver name for Windows WiFi interface"""
        driver_reader = getattr(self.wifi_backend, "get_driver_windows", None)
        if callable(driver_reader):
            result = driver_reader(interface=interface)
            if isinstance(result, str) and result:
                return result

        self._record_operation(
            "windows_driver_lookup",
            {
                "status": "unavailable",
                "interface": interface,
                "backend": self._backend_name(),
                "error": "No WiFi backend is configured for Windows driver lookup",
            },
        )
        return "Unknown"

    def scan_networks(self, band: Optional[WiFiBand] = None) -> List[WiFiNetwork]:
        """
        Scan for available WiFi networks

        Args:
            band: Specific band to scan (None for all bands)

        Returns:
            List of detected WiFi networks
        """
        try:
            scanner = getattr(self.wifi_backend, "scan_networks", None)
            if callable(scanner):
                networks = self._normalize_networks(
                    scanner(band=band), "backend network scan"
                )
                self.available_networks = self._filter_networks_by_band(
                    networks, band
                )
                self._record_operation(
                    "scan_networks",
                    {
                        "status": "scanned",
                        "backend": self._backend_name(),
                        "network_count": len(self.available_networks),
                    },
                )
                return self.available_networks

            if self.platform == "Linux":
                return self._scan_networks_linux(band)
            elif self.platform == "Windows":
                return self._scan_networks_windows(band)
            elif self.platform == "Darwin":
                return self._scan_networks_macos(band)

            return []

        except Exception as e:
            self.logger.error(f"Network scan failed: {e}")
            return []

    def _scan_networks_linux(self, band: Optional[WiFiBand]) -> List[WiFiNetwork]:
        """Scan networks on Linux"""
        networks = []

        try:
            # Use iwlist or iw to scan
            sudo = _command_path("sudo") or "sudo"
            iw = _command_path("iw") or "iw"
            for adapter in self.adapters:
                result = subprocess.run(
                    [sudo, iw, adapter.interface_name, "scan"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )  # nosec B603

            if result.returncode == 0:
                networks.extend(self._parse_scan_results_linux(result.stdout, band))

        except Exception as e:
            self.logger.error(f"Linux network scan error: {e}")

        self.available_networks = networks
        return networks

    def _parse_scan_results_linux(
        self, output: str, band_filter: Optional[WiFiBand]
    ) -> List[WiFiNetwork]:
        """Parse Linux iw scan output"""
        networks = []
        current: Dict[str, Any] = {}
        security_lines: List[str] = []

        def flush_current() -> None:
            if not current:
                return

            frequency = int(current.get("frequency_mhz") or 0)
            channel = int(current.get("channel") or 0)
            if not frequency and channel:
                frequency = self._channel_to_frequency(channel)
            if not channel and frequency:
                channel = self._frequency_to_channel(frequency)

            band = self._frequency_to_band(frequency)
            if band_filter is not None and band != band_filter:
                return

            ssid = str(current.get("ssid") or "<hidden>")
            network = WiFiNetwork(
                ssid=ssid,
                bssid=str(current.get("bssid") or "Unknown"),
                band=band,
                channel=channel,
                frequency_mhz=frequency,
                signal_strength_dbm=int(current.get("signal_strength_dbm") or 0),
                security=self._security_from_text("\n".join(security_lines)),
                max_rate_mbps=int(current.get("max_rate_mbps") or 0),
                bandwidth_mhz=int(current.get("bandwidth_mhz") or 20),
                supports_wifi6=bool(current.get("supports_wifi6")),
                supports_wifi7=bool(current.get("supports_wifi7")),
            )
            networks.append(network)

        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            if line.startswith("BSS "):
                flush_current()
                bssid = line.split()[1].split("(")[0]
                current = {"bssid": bssid}
                security_lines = []
                continue

            if not current:
                continue

            security_lines.append(line)

            if line.startswith("SSID:"):
                current["ssid"] = line.split(":", 1)[1].strip()
            elif line.startswith("freq:"):
                current["frequency_mhz"] = self._first_int(line)
            elif line.startswith("signal:"):
                current["signal_strength_dbm"] = self._first_int(line)
            elif "DS Parameter set: channel" in line:
                current["channel"] = self._first_int(line)
            elif line.startswith("primary channel:"):
                current["channel"] = self._first_int(line)
            elif "HE capabilities" in line or "HE PHY Capabilities" in line:
                current["supports_wifi6"] = True
            elif "EHT" in line:
                current["supports_wifi7"] = True
            elif "VHT" in line:
                current.setdefault("bandwidth_mhz", 80)
            elif "MHz" in line and "width" in line.lower():
                current["bandwidth_mhz"] = self._first_int(line) or 20
            elif "MBit/s" in line or "Mbps" in line:
                current["max_rate_mbps"] = max(
                    int(current.get("max_rate_mbps") or 0),
                    self._first_int(line) or 0,
                )

        flush_current()
        return networks

    def _scan_networks_windows(self, band: Optional[WiFiBand]) -> List[WiFiNetwork]:
        """Scan networks on Windows"""
        networks = []

        try:
            netsh = _command_path("netsh") or "netsh"
            result = subprocess.run(
                [netsh, "wlan", "show", "networks", "mode=bssid"],
                capture_output=True,
                text=True,
                timeout=10,
            )  # nosec B603

            if result.returncode == 0:
                networks.extend(self._parse_scan_results_windows(result.stdout, band))

        except Exception as e:
            self.logger.error(f"Windows network scan error: {e}")

        self.available_networks = networks
        return networks

    def _parse_scan_results_windows(
        self, output: str, band_filter: Optional[WiFiBand]
    ) -> List[WiFiNetwork]:
        """Parse Windows netsh scan output"""
        networks = []
        ssid = None
        ssid_security = ""
        current: Dict[str, Any] = {}

        def flush_current() -> None:
            if not current:
                return

            channel = int(current.get("channel") or 0)
            frequency = int(current.get("frequency_mhz") or 0)
            if not frequency and channel:
                frequency = self._channel_to_frequency(channel)
            band = self._frequency_to_band(frequency)
            if band_filter is not None and band != band_filter:
                return

            radio_type = str(current.get("radio_type") or "")
            security = self._security_from_text(str(current.get("security") or ""))
            network = WiFiNetwork(
                ssid=str(ssid or "<hidden>"),
                bssid=str(current.get("bssid") or "Unknown"),
                band=band,
                channel=channel,
                frequency_mhz=frequency,
                signal_strength_dbm=self._signal_percent_to_dbm(
                    int(current.get("signal_percent") or 0)
                ),
                security=security,
                max_rate_mbps=int(current.get("max_rate_mbps") or 0),
                bandwidth_mhz=int(current.get("bandwidth_mhz") or 20),
                supports_wifi6="ax" in radio_type.lower(),
                supports_wifi7="be" in radio_type.lower(),
            )
            networks.append(network)

        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            if line.startswith("SSID ") and ":" in line:
                flush_current()
                ssid = line.split(":", 1)[1].strip()
                ssid_security = ""
                current = {}
                continue

            if line.startswith("BSSID ") and ":" in line:
                flush_current()
                current = {
                    "bssid": line.split(":", 1)[1].strip(),
                    "security": ssid_security,
                }
                continue

            if line.startswith("Authentication") and ":" in line:
                ssid_security = line.split(":", 1)[1].strip()
                if current:
                    current["security"] = ssid_security
            elif line.startswith("Encryption") and ":" in line:
                encryption = line.split(":", 1)[1].strip()
                ssid_security = f"{ssid_security} {encryption}".strip()
                if current:
                    current["security"] = ssid_security
            elif not current:
                continue
            elif line.startswith("Signal") and ":" in line:
                current["signal_percent"] = self._first_int(line)
            elif line.startswith("Radio type") and ":" in line:
                current["radio_type"] = line.split(":", 1)[1].strip()
            elif line.startswith("Band") and ":" in line:
                band_text = line.split(":", 1)[1].strip()
                current["frequency_mhz"] = self._frequency_from_band_text(band_text)
            elif line.startswith("Channel") and ":" in line:
                current["channel"] = self._first_int(line)
            elif "rates (Mbps)" in line and ":" in line:
                rates = [int(value) for value in line.split(":", 1)[1].split() if value.isdigit()]
                if rates:
                    current["max_rate_mbps"] = max(
                        int(current.get("max_rate_mbps") or 0), max(rates)
                    )

        flush_current()
        return networks

    def _scan_networks_macos(self, band: Optional[WiFiBand]) -> List[WiFiNetwork]:
        """Scan networks on macOS"""
        networks = []

        try:
            # Use airport utility for scanning
            result = subprocess.run(
                [
                    "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport",
                    "-s",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )  # nosec B603

            if result.returncode == 0:
                networks.extend(self._parse_scan_results_macos(result.stdout, band))

        except Exception as e:
            self.logger.error(f"macOS network scan error: {e}")

        self.available_networks = networks
        return networks

    def _parse_scan_results_macos(
        self, output: str, band_filter: Optional[WiFiBand]
    ) -> List[WiFiNetwork]:
        """Parse macOS airport scan output"""
        networks = []
        for raw_line in output.splitlines()[1:]:
            line = raw_line.strip()
            if not line:
                continue

            parts = line.split()
            if len(parts) < 6:
                continue

            bssid_index = None
            for index, part in enumerate(parts):
                if self._looks_like_mac(part):
                    bssid_index = index
                    break

            if bssid_index is None or bssid_index == 0:
                continue

            ssid = " ".join(parts[:bssid_index])
            bssid = parts[bssid_index]
            signal = int(parts[bssid_index + 1])
            channel_text = parts[bssid_index + 2]
            channel = self._first_int(channel_text) or 0
            frequency = self._channel_to_frequency(channel)
            band = self._frequency_to_band(frequency)
            if band_filter is not None and band != band_filter:
                continue

            security_text = " ".join(parts[bssid_index + 5:])
            networks.append(
                WiFiNetwork(
                    ssid=ssid,
                    bssid=bssid,
                    band=band,
                    channel=channel,
                    frequency_mhz=frequency,
                    signal_strength_dbm=signal,
                    security=self._security_from_text(security_text),
                    max_rate_mbps=0,
                    bandwidth_mhz=40 if "," in channel_text else 20,
                    supports_wifi6="HE" in security_text,
                    supports_wifi7="EHT" in security_text,
                )
            )

        return networks

    def connect(
        self, ssid: str, password: Optional[str] = None, security: Optional[str] = None
    ) -> bool:
        """
        Connect to WiFi network with God Tier security

        Args:
            ssid: Network SSID
            password: Network password (if required)
            security: Security protocol (WPA2, WPA3, OWE, etc.)

        Returns:
            True if connection successful
        """
        try:
            self.logger.info(f"Connecting to {ssid} with God Tier security")

            if self.platform == "Linux":
                return self._connect_linux(ssid, password, security)
            elif self.platform == "Windows":
                return self._connect_windows(ssid, password, security)
            elif self.platform == "Darwin":
                return self._connect_macos(ssid, password, security)

            return False

        except Exception as e:
            self.logger.error(f"WiFi connection failed: {e}")
            return False

    def _connect_linux(
        self, ssid: str, password: Optional[str], security: Optional[str]
    ) -> bool:
        """Connect to WiFi on Linux using NetworkManager or wpa_supplicant"""
        return self._connect_via_backend("linux", ssid, password, security)

    def _connect_windows(
        self, ssid: str, password: Optional[str], security: Optional[str]
    ) -> bool:
        """Connect to WiFi on Windows"""
        return self._connect_via_backend("windows", ssid, password, security)

    def _connect_macos(
        self, ssid: str, password: Optional[str], security: Optional[str]
    ) -> bool:
        """Connect to WiFi on macOS"""
        return self._connect_via_backend("macos", ssid, password, security)

    def disconnect(self) -> bool:
        """Disconnect from current WiFi network"""
        try:
            if not self.connected_network:
                return True

            disconnector = getattr(self.wifi_backend, "disconnect", None)
            if not callable(disconnector):
                self._record_operation(
                    "disconnect",
                    {
                        "status": "unavailable",
                        "disconnected": False,
                        "backend": self._backend_name(),
                        "error": "No WiFi backend is configured for disconnect",
                    },
                )
                return False

            result = disconnector(network=self.connected_network)
            normalized = self._normalize_bool_or_dict_result(
                result, "disconnected", "disconnect"
            )
            normalized.setdefault("status", "disconnected")
            normalized["backend"] = self._backend_name()
            self._record_operation("disconnect", normalized)
            if not normalized["disconnected"]:
                return False

            self.connected_network = None
            self.logger.info("WiFi disconnected")
            return True

        except Exception as e:
            self.logger.error(f"WiFi disconnect failed: {e}")
            return False

    def get_status(self) -> Dict[str, Any]:
        """Get WiFi connection status"""
        return {
            "connected": self.connected_network is not None,
            "network": (
                self.connected_network.__dict__ if self.connected_network else None
            ),
            "adapters": [adapter.__dict__ for adapter in self.adapters],
            "available_networks_count": len(self.available_networks),
            "marketplace_mode": self.marketplace_mode,
            "backend_configured": self.wifi_backend is not None,
            "backend": self._backend_name(),
            "last_operation_results": dict(self.last_operation_results),
        }

    def enable_marketplace_mode(self) -> bool:
        """
        Enable bandwidth marketplace integration
        Shares WiFi bandwidth with marketplace pool
        """
        self.marketplace_mode = True
        self.logger.info("WiFi marketplace mode enabled")
        return True

    def optimize_channel(self, band: WiFiBand) -> Optional[int]:
        """
        Analyze spectrum and select optimal channel

        Args:
            band: WiFi band to optimize

        Returns:
            Optimal channel number
        """
        optimizer = getattr(self.wifi_backend, "optimize_channel", None)
        if not callable(optimizer):
            self._record_operation(
                "optimize_channel",
                {
                    "status": "unavailable",
                    "band": band.value,
                    "channel": None,
                    "backend": self._backend_name(),
                    "error": "No WiFi backend is configured for spectrum analysis",
                },
            )
            return None

        result = optimizer(band=band, networks=list(self.available_networks))
        if isinstance(result, int):
            normalized = {"status": "optimized", "channel": result}
        elif isinstance(result, dict):
            if "channel" not in result or not isinstance(
                result["channel"], (int, type(None))
            ):
                raise ValueError(
                    "WiFi backend optimize_channel result must include "
                    "integer or null 'channel'"
                )
            normalized = dict(result)
            normalized.setdefault("status", "optimized")
        else:
            raise TypeError(
                "WiFi backend optimize_channel must return int or dict"
            )

        normalized["backend"] = self._backend_name()
        normalized["band"] = band.value
        self._record_operation("optimize_channel", normalized)
        return normalized["channel"]

    def _connect_via_backend(
        self, platform_name: str, ssid: str, password: Optional[str], security: Optional[str]
    ) -> bool:
        connector = getattr(
            self.wifi_backend, f"connect_{platform_name}", None
        ) or getattr(self.wifi_backend, "connect", None)
        if not callable(connector):
            self._record_operation(
                "connect",
                {
                    "status": "unavailable",
                    "connected": False,
                    "ssid": ssid,
                    "platform": platform_name,
                    "backend": self._backend_name(),
                    "error": "No WiFi backend is configured for connection",
                },
            )
            return False

        result = connector(ssid=ssid, password=password, security=security)
        normalized = self._normalize_bool_or_dict_result(
            result, "connected", "connect"
        )
        normalized.setdefault("status", "connected")
        normalized["backend"] = self._backend_name()
        normalized["ssid"] = ssid
        self._record_operation("connect", normalized)

        if not normalized["connected"]:
            return False

        network = normalized.get("network")
        if isinstance(network, WiFiNetwork):
            self.connected_network = network
        else:
            self.connected_network = self._find_available_network(ssid)

        return True

    def _normalize_bool_or_dict_result(
        self, result: Any, bool_field: str, operation: str
    ) -> Dict[str, Any]:
        if isinstance(result, bool):
            return {bool_field: result}

        if not isinstance(result, dict):
            raise TypeError(f"WiFi backend {operation} must return bool or dict")

        if bool_field not in result or not isinstance(result[bool_field], bool):
            raise ValueError(
                f"WiFi backend {operation} result must include "
                f"boolean {bool_field!r}"
            )

        return dict(result)

    def _normalize_networks(self, result: Any, operation: str) -> List[WiFiNetwork]:
        if not isinstance(result, list):
            raise TypeError(f"WiFi backend {operation} must return a list")

        for network in result:
            if not isinstance(network, WiFiNetwork):
                raise TypeError(
                    f"WiFi backend {operation} returned a non-WiFiNetwork item"
                )

        return list(result)

    def _filter_networks_by_band(
        self, networks: List[WiFiNetwork], band: Optional[WiFiBand]
    ) -> List[WiFiNetwork]:
        if band is None:
            return networks
        return [network for network in networks if network.band == band]

    def _find_available_network(self, ssid: str) -> Optional[WiFiNetwork]:
        for network in self.available_networks:
            if network.ssid == ssid:
                return network
        return None

    def _record_operation(self, operation: str, result: Dict[str, Any]) -> None:
        self.last_operation_results[operation] = result

    def _backend_name(self) -> Optional[str]:
        if self.wifi_backend is None:
            return None
        return self.wifi_backend.__class__.__name__

    def _frequency_to_band(self, frequency_mhz: int) -> WiFiBand:
        if 2400 <= frequency_mhz < 2500:
            return WiFiBand.BAND_2_4_GHZ
        if 4900 <= frequency_mhz < 5925:
            return WiFiBand.BAND_5_GHZ
        if 5925 <= frequency_mhz < 7125:
            return WiFiBand.BAND_6_GHZ
        if 57000 <= frequency_mhz < 71000:
            return WiFiBand.BAND_60_GHZ
        return WiFiBand.BAND_2_4_GHZ

    def _channel_to_frequency(self, channel: int) -> int:
        if channel <= 0:
            return 0
        if channel == 14:
            return 2484
        if 1 <= channel <= 13:
            return 2407 + channel * 5
        if 32 <= channel <= 177:
            return 5000 + channel * 5
        if 1 <= channel <= 233:
            return 5950 + channel * 5
        return 0

    def _frequency_to_channel(self, frequency_mhz: int) -> int:
        if frequency_mhz == 2484:
            return 14
        if 2412 <= frequency_mhz <= 2472:
            return int((frequency_mhz - 2407) / 5)
        if 5000 <= frequency_mhz <= 5885:
            return int((frequency_mhz - 5000) / 5)
        if 5955 <= frequency_mhz <= 7115:
            return int((frequency_mhz - 5950) / 5)
        return 0

    def _frequency_from_band_text(self, band_text: str) -> int:
        normalized = band_text.lower()
        if "6" in normalized:
            return 5955
        if "5" in normalized:
            return 5180
        if "60" in normalized:
            return 60480
        return 2412

    def _security_from_text(self, text: str) -> List[str]:
        upper_text = text.upper()
        security = []
        if "WPA3" in upper_text or "SAE" in upper_text:
            security.append("WPA3")
        if "WPA2" in upper_text or "RSN" in upper_text:
            security.append("WPA2")
        if "WPA" in upper_text and "WPA2" not in upper_text and "WPA3" not in upper_text:
            security.append("WPA")
        if "OWE" in upper_text:
            security.append("OWE")
        if "WEP" in upper_text:
            security.append("WEP")
        if "PRIVACY" in upper_text and not security:
            security.append("WEP")
        return security or ["OPEN"]

    def _signal_percent_to_dbm(self, signal_percent: int) -> int:
        bounded = max(0, min(signal_percent, 100))
        return int((bounded / 2) - 100)

    def _first_int(self, text: str) -> int:
        digits = []
        current = ""
        for char in text:
            if char.isdigit() or (char == "-" and not current):
                current += char
            elif current:
                digits.append(current)
                current = ""
        if current:
            digits.append(current)
        return int(digits[0]) if digits else 0

    def _looks_like_mac(self, value: str) -> bool:
        parts = value.split(":")
        return len(parts) == 6 and all(len(part) == 2 for part in parts)
