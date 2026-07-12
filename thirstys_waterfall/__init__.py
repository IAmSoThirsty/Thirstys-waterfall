"""
Thirstys Waterfall - Ultimate Privacy-First System
"""

from .orchestrator import ThirstysWaterfall
from .encryption_evidence import (
    DataSurfaceEvidence,
    EncryptionEvidenceReport,
    get_encryption_evidence_report,
)
from .platform_capabilities import (
    PlatformCapabilityReport,
    get_platform_capabilities,
)

__version__ = "1.0.2"
__all__ = [
    "DataSurfaceEvidence",
    "EncryptionEvidenceReport",
    "PlatformCapabilityReport",
    "ThirstysWaterfall",
    "get_encryption_evidence_report",
    "get_platform_capabilities",
]
