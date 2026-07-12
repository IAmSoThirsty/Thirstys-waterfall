"""
Thirstys Waterfall - Ultimate Privacy-First System
"""

from .orchestrator import ThirstysWaterfall
from .platform_capabilities import (
    PlatformCapabilityReport,
    get_platform_capabilities,
)

__version__ = "1.0.2"
__all__ = [
    "PlatformCapabilityReport",
    "ThirstysWaterfall",
    "get_platform_capabilities",
]
