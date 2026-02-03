"""Security module for Thirstys Waterfall - Advanced Security Features"""

from .hardware_root_of_trust import HardwareRootOfTrust, TPMInterface, SecureEnclaveInterface, HSMInterface
from .privacy_risk_engine import PrivacyRiskEngine, RiskLevel
from .microvm_isolation import MicroVMIsolationManager, MicroVMInstance
from .mfa_auth import (
    MFAAuthenticator,
    AuthContext,
    AuthMethod,
    AuthLevel,
    TOTPProvider,
    FIDO2Provider,
    PasskeyProvider,
    CertificateProvider,
    BiometricProvider,
    BiometricType,
)

__all__ = [
    'HardwareRootOfTrust',
    'TPMInterface',
    'SecureEnclaveInterface',
    'HSMInterface',
    'PrivacyRiskEngine',
    'RiskLevel',
    'MicroVMIsolationManager',
    'MicroVMInstance',
    'MFAAuthenticator',
    'AuthContext',
    'AuthMethod',
    'AuthLevel',
    'TOTPProvider',
    'FIDO2Provider',
    'PasskeyProvider',
    'CertificateProvider',
    'BiometricProvider',
    'BiometricType',
]
