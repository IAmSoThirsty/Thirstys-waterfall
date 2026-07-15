"""System Theme Detector"""

import importlib
import logging
import platform
import shutil
from typing import Any, cast


class SystemThemeDetector:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.os_name = platform.system()

    def detect_system_theme(self):
        try:
            if self.os_name == "Windows":
                return self._detect_windows()
            elif self.os_name == "Darwin":
                return self._detect_macos()
            else:
                return "dark"
        except Exception:
            return "dark"

    def _detect_windows(self):
        try:
            winreg = cast(Any, importlib.import_module("winreg"))

            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize",  # pragma: allowlist secret
            )
            value, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
            winreg.CloseKey(key)
            return "light" if value == 1 else "dark"
        except Exception:
            return "dark"

    def _detect_macos(self):
        import subprocess  # nosec B404

        try:
            defaults = shutil.which("defaults") or "/usr/bin/defaults"
            result = subprocess.run(
                [defaults, "read", "-g", "AppleInterfaceStyle"],
                capture_output=True,
                text=True,
                timeout=2,
            )  # nosec B603
            return "dark" if "Dark" in result.stdout else "light"
        except Exception:
            return "light"
