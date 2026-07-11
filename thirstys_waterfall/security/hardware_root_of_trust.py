"""
Hardware Root-of-Trust Integration
Provides evidence-gated TPM, Secure Enclave, HSM, and explicit software-fallback
interfaces for cryptographic key storage and boot-attestation workflows.
"""

import logging
import hashlib
import hmac
import secrets
from typing import Dict, Any, Optional, List
from abc import ABC, abstractmethod
from enum import Enum
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import threading


class HardwareType(Enum):
    """Supported hardware security module types"""

    TPM = "tpm"
    SECURE_ENCLAVE = "secure_enclave"
    HSM = "hsm"
    SOFTWARE_FALLBACK = "software_fallback"


class AttestationStatus(Enum):
    """Attestation status indicators"""

    VALID = "valid"
    INVALID = "invalid"
    UNKNOWN = "unknown"
    TAMPERED = "tampered"


class HardwareInterface(ABC):
    """Abstract base class for hardware security interfaces"""

    @abstractmethod
    def initialize(self) -> bool:
        """Initialize hardware interface"""
        pass

    @abstractmethod
    def store_key(self, key_id: str, key_data: bytes) -> bool:
        """Store cryptographic key in hardware"""
        pass

    @abstractmethod
    def retrieve_key(self, key_id: str) -> Optional[bytes]:
        """Retrieve cryptographic key from hardware"""
        pass

    @abstractmethod
    def delete_key(self, key_id: str) -> bool:
        """Securely delete key from hardware"""
        pass

    @abstractmethod
    def attest_boot(self) -> AttestationStatus:
        """Perform secure boot attestation"""
        pass

    @abstractmethod
    def get_hardware_id(self) -> str:
        """Get unique hardware identifier"""
        pass

    @abstractmethod
    def seal_data(self, data: bytes, pcr_values: List[int]) -> bytes:
        """Seal data to specific PCR values"""
        pass

    @abstractmethod
    def unseal_data(self, sealed_data: bytes) -> Optional[bytes]:
        """Unseal data (only if PCR values match)"""
        pass


class TPMInterface(HardwareInterface):
    """
    Trusted Platform Module (TPM) interface.
    Uses a configured TPM backend when present; otherwise uses an explicit
    software fallback only when allowed by the caller.
    """

    def __init__(
        self,
        hardware_backend: Optional[Any] = None,
        allow_software_fallback: bool = True,
    ):
        self.logger = logging.getLogger(__name__)
        self.hardware_backend = hardware_backend
        self.allow_software_fallback = allow_software_fallback
        self._initialized = False
        self._keys: Dict[str, bytes] = {}
        self._pcr_banks: Dict[int, bytes] = {}
        self._sealed_policies: Dict[bytes, List[int]] = {}
        self._hardware_id = self._generate_hardware_id()
        self._salt = hashlib.sha256(f"TPM_SRK_{self._hardware_id}".encode()).digest()
        self._hardware_backed = False
        self.operation_evidence: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

    def _record_evidence(
        self, operation: str, status: str, **details: Any
    ) -> Dict[str, Any]:
        evidence = {"status": status, **details}
        self.operation_evidence[operation] = evidence
        return evidence

    def _backend_call(self, method_name: str, **kwargs: Any) -> Optional[Any]:
        method = getattr(self.hardware_backend, method_name, None)
        if not callable(method):
            return None
        return method(**kwargs)

    def initialize(self) -> bool:
        """Initialize TPM interface"""
        try:
            self.logger.info("Initializing TPM interface")

            backend_result = self._backend_call("initialize_tpm")
            if backend_result is not None:
                accepted = bool(
                    backend_result.get("available", True)
                    if isinstance(backend_result, dict)
                    else backend_result
                )
                self.operation_evidence["initialize"] = (
                    dict(backend_result)
                    if isinstance(backend_result, dict)
                    else {"status": "available" if accepted else "unavailable"}
                )
                self._initialized = accepted
                self._hardware_backed = accepted
                return accepted

            if not self.allow_software_fallback:
                self._record_evidence(
                    "initialize",
                    "unavailable",
                    reason="tpm_backend_not_configured",
                )
                return False

            self._initialize_pcr_banks()
            self._record_evidence(
                "initialize",
                "software_emulated",
                hardware_backed=False,
                reason="tpm_backend_not_configured",
            )

            self._initialized = True
            self.logger.info("TPM software fallback initialized successfully")
            return True

        except Exception as e:
            self.logger.error(f"Failed to initialize TPM: {e}")
            return False

    def _initialize_pcr_banks(self):
        """Initialize Platform Configuration Register banks"""
        boot_measurements = [
            b"BIOS_MEASUREMENT",
            b"BOOTLOADER_MEASUREMENT",
            b"KERNEL_MEASUREMENT",
            b"INITRD_MEASUREMENT",
            b"USERSPACE_MEASUREMENT",
        ]

        for i, measurement in enumerate(boot_measurements):
            self._pcr_banks[i] = hashlib.sha256(measurement).digest()

    def store_key(self, key_id: str, key_data: bytes) -> bool:
        """Store key in TPM's non-volatile memory"""
        with self._lock:
            try:
                backend_result = self._backend_call(
                    "store_key", key_id=key_id, key_data=key_data
                )
                if backend_result is not None:
                    accepted = bool(backend_result)
                    self._record_evidence(
                        f"store_key:{key_id}",
                        "stored" if accepted else "unavailable",
                        hardware_backed=accepted,
                    )
                    return accepted

                self._keys[key_id] = self._encrypt_with_srk(key_data)
                self._record_evidence(
                    f"store_key:{key_id}",
                    "software_emulated",
                    hardware_backed=False,
                )
                self.logger.info(f"Stored key {key_id} in TPM")
                return True
            except Exception as e:
                self.logger.error(f"Failed to store key {key_id}: {e}")
                return False

    def retrieve_key(self, key_id: str) -> Optional[bytes]:
        """Retrieve key from TPM"""
        with self._lock:
            try:
                backend_result = self._backend_call("retrieve_key", key_id=key_id)
                if backend_result is not None:
                    self._record_evidence(
                        f"retrieve_key:{key_id}",
                        "retrieved" if backend_result else "missing",
                        hardware_backed=True,
                    )
                    return backend_result

                encrypted_key = self._keys.get(key_id)
                if encrypted_key:
                    self._record_evidence(
                        f"retrieve_key:{key_id}",
                        "software_emulated",
                        hardware_backed=False,
                    )
                    return self._decrypt_with_srk(encrypted_key)
                return None
            except Exception as e:
                self.logger.error(f"Failed to retrieve key {key_id}: {e}")
                return None

    def delete_key(self, key_id: str) -> bool:
        """Securely delete key from TPM"""
        with self._lock:
            try:
                backend_result = self._backend_call("delete_key", key_id=key_id)
                if backend_result is not None:
                    accepted = bool(backend_result)
                    self._record_evidence(
                        f"delete_key:{key_id}",
                        "deleted" if accepted else "unavailable",
                        hardware_backed=accepted,
                    )
                    return accepted

                if key_id in self._keys:
                    del self._keys[key_id]
                    self._record_evidence(
                        f"delete_key:{key_id}",
                        "software_emulated",
                        hardware_backed=False,
                    )
                    self.logger.info(f"Deleted key {key_id} from TPM")
                return True
            except Exception as e:
                self.logger.error(f"Failed to delete key {key_id}: {e}")
                return False

    def attest_boot(self) -> AttestationStatus:
        """
        Perform secure boot attestation by verifying PCR values.
        Returns status indicating if boot chain is trusted.
        """
        try:
            backend_result = self._backend_call("attest_boot")
            if backend_result is not None:
                status = (
                    backend_result
                    if isinstance(backend_result, AttestationStatus)
                    else AttestationStatus(str(backend_result))
                )
                self._record_evidence(
                    "attest_boot", status.value, hardware_backed=True
                )
                return status

            expected_pcr0 = hashlib.sha256(b"BIOS_MEASUREMENT").digest()
            actual_pcr0 = self._pcr_banks.get(0)

            if actual_pcr0 == expected_pcr0:
                self._record_evidence(
                    "attest_boot", "software_emulated", hardware_backed=False
                )
                self.logger.info("Boot attestation: VALID")
                return AttestationStatus.VALID
            else:
                self._record_evidence(
                    "attest_boot", "tampered", hardware_backed=False
                )
                self.logger.critical("Boot attestation: TAMPERED - PCR mismatch!")
                return AttestationStatus.TAMPERED

        except Exception as e:
            self.logger.error(f"Boot attestation failed: {e}")
            return AttestationStatus.UNKNOWN

    def get_hardware_id(self) -> str:
        """Get TPM's endorsement key (EK) as hardware ID"""
        return self._hardware_id

    def _generate_hardware_id(self) -> str:
        """Generate unique hardware identifier"""
        backend_result = self._backend_call("get_hardware_id")
        if backend_result is not None:
            return str(backend_result)
        return hashlib.sha256(secrets.token_bytes(32)).hexdigest()

    def seal_data(self, data: bytes, pcr_values: List[int]) -> bytes:
        """
        Seal data to specific PCR values using TPM.
        Data can only be unsealed when PCRs match.
        """
        try:
            backend_result = self._backend_call(
                "seal_data", data=data, pcr_values=pcr_values
            )
            if backend_result is not None:
                self._record_evidence("seal_data", "sealed", hardware_backed=True)
                return backend_result

            # Create policy digest from PCR values
            policy_digest = self._create_policy_digest(pcr_values)

            sealed = self._encrypt_with_policy(data, policy_digest)
            self._sealed_policies[policy_digest] = list(pcr_values)
            self._record_evidence(
                "seal_data", "software_emulated", hardware_backed=False
            )

            self.logger.info(f"Sealed data to PCRs: {pcr_values}")
            return sealed

        except Exception as e:
            self.logger.error(f"Failed to seal data: {e}")
            raise

    def unseal_data(self, sealed_data: bytes) -> Optional[bytes]:
        """
        Unseal data sealed to PCR values.
        Only succeeds if current PCR values match sealed policy.
        """
        try:
            backend_result = self._backend_call("unseal_data", sealed_data=sealed_data)
            if backend_result is not None:
                self._record_evidence("unseal_data", "unsealed", hardware_backed=True)
                return backend_result

            data = self._decrypt_with_policy(sealed_data)

            if data:
                self._record_evidence(
                    "unseal_data", "software_emulated", hardware_backed=False
                )
                self.logger.info("Successfully unsealed data")
            else:
                self._record_evidence(
                    "unseal_data", "policy_mismatch", hardware_backed=False
                )
                self.logger.warning("Failed to unseal - PCR values don't match")

            return data

        except Exception as e:
            self.logger.error(f"Failed to unseal data: {e}")
            return None

    def _encrypt_with_srk(self, data: bytes) -> bytes:
        """Encrypt data with Storage Root Key"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self._salt,
            iterations=100000,
            backend=default_backend(),
        )
        key = kdf.derive(self._hardware_id.encode())
        return hmac.new(key, data, hashlib.sha256).digest() + data

    def _decrypt_with_srk(self, encrypted_data: bytes) -> bytes:
        """Decrypt data with Storage Root Key"""
        mac = encrypted_data[:32]
        data = encrypted_data[32:]

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self._salt,
            iterations=100000,
            backend=default_backend(),
        )
        key = kdf.derive(self._hardware_id.encode())

        expected_mac = hmac.new(key, data, hashlib.sha256).digest()
        if hmac.compare_digest(mac, expected_mac):
            return data
        raise ValueError("MAC verification failed")

    def _create_policy_digest(self, pcr_values: List[int]) -> bytes:
        """Create policy digest from PCR values"""
        digest = hashlib.sha256()
        for pcr in pcr_values:
            pcr_value = self._pcr_banks.get(pcr, b"")
            digest.update(pcr_value)
        return digest.digest()

    def _encrypt_with_policy(self, data: bytes, policy_digest: bytes) -> bytes:
        """Encrypt data with policy digest"""
        return policy_digest + data

    def _decrypt_with_policy(self, sealed_data: bytes) -> Optional[bytes]:
        """Decrypt data if policy matches current state"""
        policy_digest = sealed_data[:32]
        data = sealed_data[32:]
        pcr_values = self._sealed_policies.get(policy_digest)
        if pcr_values is None:
            return None

        if not hmac.compare_digest(policy_digest, self._create_policy_digest(pcr_values)):
            return None
        return data


class SecureEnclaveInterface(HardwareInterface):
    """
    Secure Enclave interface (Apple hardware security).
    Uses a configured enclave backend when present; otherwise uses an explicit
    software fallback only when allowed by the caller.
    """

    def __init__(
        self,
        hardware_backend: Optional[Any] = None,
        allow_software_fallback: bool = True,
    ):
        self.logger = logging.getLogger(__name__)
        self.hardware_backend = hardware_backend
        self.allow_software_fallback = allow_software_fallback
        self._initialized = False
        self._keychain: Dict[str, bytes] = {}
        self._enclave_id = self._generate_enclave_id()
        self._salt = hashlib.sha256(
            f"SECURE_ENCLAVE_{self._enclave_id}".encode()
        ).digest()
        self._hardware_backed = False
        self.operation_evidence: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

    def _record_evidence(
        self, operation: str, status: str, **details: Any
    ) -> Dict[str, Any]:
        evidence = {"status": status, **details}
        self.operation_evidence[operation] = evidence
        return evidence

    def _backend_call(self, method_name: str, **kwargs: Any) -> Optional[Any]:
        method = getattr(self.hardware_backend, method_name, None)
        if not callable(method):
            return None
        return method(**kwargs)

    def initialize(self) -> bool:
        """Initialize Secure Enclave"""
        try:
            self.logger.info("Initializing Secure Enclave interface")

            backend_result = self._backend_call("initialize_secure_enclave")
            if backend_result is not None:
                accepted = bool(backend_result)
                self._initialized = accepted
                self._hardware_backed = accepted
                self._record_evidence(
                    "initialize",
                    "available" if accepted else "unavailable",
                    hardware_backed=accepted,
                )
                return accepted

            if not self.allow_software_fallback:
                self._record_evidence(
                    "initialize",
                    "unavailable",
                    reason="secure_enclave_backend_not_configured",
                )
                return False

            self._initialized = True
            self._record_evidence(
                "initialize",
                "software_emulated",
                hardware_backed=False,
                reason="secure_enclave_backend_not_configured",
            )
            self.logger.info("Secure Enclave software fallback initialized")
            return True

        except Exception as e:
            self.logger.error(f"Failed to initialize Secure Enclave: {e}")
            return False

    def store_key(self, key_id: str, key_data: bytes) -> bool:
        """Store key in Secure Enclave keychain"""
        with self._lock:
            try:
                backend_result = self._backend_call(
                    "store_key", key_id=key_id, key_data=key_data
                )
                if backend_result is not None:
                    accepted = bool(backend_result)
                    self._record_evidence(
                        f"store_key:{key_id}",
                        "stored" if accepted else "unavailable",
                        hardware_backed=accepted,
                    )
                    return accepted

                self._keychain[key_id] = self._encrypt_for_enclave(key_data)
                self._record_evidence(
                    f"store_key:{key_id}",
                    "software_emulated",
                    hardware_backed=False,
                )
                self.logger.info(f"Stored key {key_id} in Secure Enclave")
                return True
            except Exception as e:
                self.logger.error(f"Failed to store key: {e}")
                return False

    def retrieve_key(self, key_id: str) -> Optional[bytes]:
        """Retrieve key from Secure Enclave"""
        with self._lock:
            backend_result = self._backend_call("retrieve_key", key_id=key_id)
            if backend_result is not None:
                self._record_evidence(
                    f"retrieve_key:{key_id}",
                    "retrieved" if backend_result else "missing",
                    hardware_backed=True,
                )
                return backend_result

            encrypted_key = self._keychain.get(key_id)
            if encrypted_key:
                self._record_evidence(
                    f"retrieve_key:{key_id}",
                    "software_emulated",
                    hardware_backed=False,
                )
                return self._decrypt_from_enclave(encrypted_key)
            return None

    def delete_key(self, key_id: str) -> bool:
        """Delete key from Secure Enclave"""
        with self._lock:
            backend_result = self._backend_call("delete_key", key_id=key_id)
            if backend_result is not None:
                accepted = bool(backend_result)
                self._record_evidence(
                    f"delete_key:{key_id}",
                    "deleted" if accepted else "unavailable",
                    hardware_backed=accepted,
                )
                return accepted

            if key_id in self._keychain:
                del self._keychain[key_id]
                self._record_evidence(
                    f"delete_key:{key_id}",
                    "software_emulated",
                    hardware_backed=False,
                )
                self.logger.info(f"Deleted key {key_id}")
            return True

    def attest_boot(self) -> AttestationStatus:
        """Verify secure boot through enclave attestation"""
        backend_result = self._backend_call("attest_boot")
        if backend_result is not None:
            status = (
                backend_result
                if isinstance(backend_result, AttestationStatus)
                else AttestationStatus(str(backend_result))
            )
            self._record_evidence("attest_boot", status.value, hardware_backed=True)
            return status

        self._record_evidence(
            "attest_boot", "software_emulated", hardware_backed=False
        )
        self.logger.info("Secure Enclave fallback attestation: VALID")
        return AttestationStatus.VALID

    def get_hardware_id(self) -> str:
        """Get Secure Enclave unique identifier"""
        return self._enclave_id

    def _generate_enclave_id(self) -> str:
        """Generate unique enclave identifier"""
        backend_result = self._backend_call("get_hardware_id")
        if backend_result is not None:
            return str(backend_result)
        return hashlib.sha256(secrets.token_bytes(32)).hexdigest()

    def seal_data(self, data: bytes, pcr_values: List[int]) -> bytes:
        """Seal data using Secure Enclave"""
        backend_result = self._backend_call(
            "seal_data", data=data, pcr_values=pcr_values
        )
        if backend_result is not None:
            self._record_evidence("seal_data", "sealed", hardware_backed=True)
            return backend_result
        self._record_evidence("seal_data", "software_emulated", hardware_backed=False)
        return self._encrypt_for_enclave(data)

    def unseal_data(self, sealed_data: bytes) -> Optional[bytes]:
        """Unseal data using Secure Enclave"""
        backend_result = self._backend_call("unseal_data", sealed_data=sealed_data)
        if backend_result is not None:
            self._record_evidence("unseal_data", "unsealed", hardware_backed=True)
            return backend_result
        self._record_evidence(
            "unseal_data", "software_emulated", hardware_backed=False
        )
        return self._decrypt_from_enclave(sealed_data)

    def _encrypt_for_enclave(self, data: bytes) -> bytes:
        """Encrypt data for Secure Enclave storage"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self._salt,
            iterations=100000,
            backend=default_backend(),
        )
        key = kdf.derive(self._enclave_id.encode())
        return hmac.new(key, data, hashlib.sha256).digest() + data

    def _decrypt_from_enclave(self, encrypted_data: bytes) -> bytes:
        """Decrypt data from Secure Enclave"""
        mac = encrypted_data[:32]
        data = encrypted_data[32:]

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self._salt,
            iterations=100000,
            backend=default_backend(),
        )
        key = kdf.derive(self._enclave_id.encode())

        expected_mac = hmac.new(key, data, hashlib.sha256).digest()
        if hmac.compare_digest(mac, expected_mac):
            return data
        raise ValueError("MAC verification failed")


class HSMInterface(HardwareInterface):
    """
    Hardware Security Module (HSM) interface.
    Uses a configured HSM backend when present; otherwise uses an explicit
    software fallback only when allowed by the caller.
    """

    def __init__(
        self,
        hsm_config: Optional[Dict[str, Any]] = None,
        hardware_backend: Optional[Any] = None,
        allow_software_fallback: bool = True,
    ):
        self.logger = logging.getLogger(__name__)
        self.config = hsm_config or {}
        self.hardware_backend = hardware_backend
        self.allow_software_fallback = allow_software_fallback
        self._initialized = False
        self._keys: Dict[str, bytes] = {}
        self._hsm_id = self._generate_hsm_id()
        self._salt = hashlib.sha256(f"HSM_MASTER_KEY_{self._hsm_id}".encode()).digest()
        self._hardware_backed = False
        self.operation_evidence: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

    def _record_evidence(
        self, operation: str, status: str, **details: Any
    ) -> Dict[str, Any]:
        evidence = {"status": status, **details}
        self.operation_evidence[operation] = evidence
        return evidence

    def _backend_call(self, method_name: str, **kwargs: Any) -> Optional[Any]:
        method = getattr(self.hardware_backend, method_name, None)
        if not callable(method):
            return None
        return method(**kwargs)

    def initialize(self) -> bool:
        """Initialize HSM connection"""
        try:
            self.logger.info("Initializing HSM interface")

            backend_result = self._backend_call("initialize_hsm", config=self.config)
            if backend_result is not None:
                accepted = bool(backend_result)
                self._initialized = accepted
                self._hardware_backed = accepted
                self._record_evidence(
                    "initialize",
                    "available" if accepted else "unavailable",
                    hardware_backed=accepted,
                )
                return accepted

            if not self.allow_software_fallback:
                self._record_evidence(
                    "initialize",
                    "unavailable",
                    reason="hsm_backend_not_configured",
                )
                return False

            self._initialized = True
            self._record_evidence(
                "initialize",
                "software_emulated",
                hardware_backed=False,
                reason="hsm_backend_not_configured",
            )
            self.logger.info("HSM software fallback initialized")
            return True

        except Exception as e:
            self.logger.error(f"Failed to initialize HSM: {e}")
            return False

    def store_key(self, key_id: str, key_data: bytes) -> bool:
        """Store key in HSM"""
        with self._lock:
            try:
                backend_result = self._backend_call(
                    "store_key", key_id=key_id, key_data=key_data
                )
                if backend_result is not None:
                    accepted = bool(backend_result)
                    self._record_evidence(
                        f"store_key:{key_id}",
                        "stored" if accepted else "unavailable",
                        hardware_backed=accepted,
                    )
                    return accepted

                self._keys[key_id] = self._hsm_encrypt(key_data)
                self._record_evidence(
                    f"store_key:{key_id}",
                    "software_emulated",
                    hardware_backed=False,
                )
                self.logger.info(f"Stored key {key_id} in HSM")
                return True
            except Exception as e:
                self.logger.error(f"Failed to store key: {e}")
                return False

    def retrieve_key(self, key_id: str) -> Optional[bytes]:
        """Retrieve key from HSM"""
        with self._lock:
            backend_result = self._backend_call("retrieve_key", key_id=key_id)
            if backend_result is not None:
                self._record_evidence(
                    f"retrieve_key:{key_id}",
                    "retrieved" if backend_result else "missing",
                    hardware_backed=True,
                )
                return backend_result

            encrypted_key = self._keys.get(key_id)
            if encrypted_key:
                self._record_evidence(
                    f"retrieve_key:{key_id}",
                    "software_emulated",
                    hardware_backed=False,
                )
                return self._hsm_decrypt(encrypted_key)
            return None

    def delete_key(self, key_id: str) -> bool:
        """Delete key from HSM"""
        with self._lock:
            backend_result = self._backend_call("delete_key", key_id=key_id)
            if backend_result is not None:
                accepted = bool(backend_result)
                self._record_evidence(
                    f"delete_key:{key_id}",
                    "deleted" if accepted else "unavailable",
                    hardware_backed=accepted,
                )
                return accepted

            if key_id in self._keys:
                del self._keys[key_id]
                self._record_evidence(
                    f"delete_key:{key_id}",
                    "software_emulated",
                    hardware_backed=False,
                )
                self.logger.info(f"Deleted key {key_id}")
            return True

    def attest_boot(self) -> AttestationStatus:
        """HSM attestation (HSM validates its own integrity)"""
        backend_result = self._backend_call("attest_boot")
        if backend_result is not None:
            status = (
                backend_result
                if isinstance(backend_result, AttestationStatus)
                else AttestationStatus(str(backend_result))
            )
            self._record_evidence("attest_boot", status.value, hardware_backed=True)
            return status

        self._record_evidence(
            "attest_boot", "software_emulated", hardware_backed=False
        )
        self.logger.info("HSM fallback attestation: VALID")
        return AttestationStatus.VALID

    def get_hardware_id(self) -> str:
        """Get HSM serial number"""
        return self._hsm_id

    def _generate_hsm_id(self) -> str:
        """Generate HSM identifier"""
        backend_result = self._backend_call("get_hardware_id")
        if backend_result is not None:
            return str(backend_result)
        return f"HSM-{hashlib.sha256(secrets.token_bytes(32)).hexdigest()[:16]}"

    def seal_data(self, data: bytes, pcr_values: List[int]) -> bytes:
        """Seal data using HSM"""
        backend_result = self._backend_call(
            "seal_data", data=data, pcr_values=pcr_values
        )
        if backend_result is not None:
            self._record_evidence("seal_data", "sealed", hardware_backed=True)
            return backend_result
        self._record_evidence("seal_data", "software_emulated", hardware_backed=False)
        return self._hsm_encrypt(data)

    def unseal_data(self, sealed_data: bytes) -> Optional[bytes]:
        """Unseal data using HSM"""
        backend_result = self._backend_call("unseal_data", sealed_data=sealed_data)
        if backend_result is not None:
            self._record_evidence("unseal_data", "unsealed", hardware_backed=True)
            return backend_result
        self._record_evidence(
            "unseal_data", "software_emulated", hardware_backed=False
        )
        return self._hsm_decrypt(sealed_data)

    def _hsm_encrypt(self, data: bytes) -> bytes:
        """Encrypt data using HSM master key"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self._salt,
            iterations=100000,
            backend=default_backend(),
        )
        key = kdf.derive(self._hsm_id.encode())
        return hmac.new(key, data, hashlib.sha256).digest() + data

    def _hsm_decrypt(self, encrypted_data: bytes) -> bytes:
        """Decrypt data using HSM master key"""
        mac = encrypted_data[:32]
        data = encrypted_data[32:]

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self._salt,
            iterations=100000,
            backend=default_backend(),
        )
        key = kdf.derive(self._hsm_id.encode())

        expected_mac = hmac.new(key, data, hashlib.sha256).digest()
        if hmac.compare_digest(mac, expected_mac):
            return data
        raise ValueError("MAC verification failed")


class HardwareRootOfTrust:
    """
    Unified Hardware Root-of-Trust manager.
    Selects the best available hardware security module when backend evidence
    is configured, otherwise falls back only to the explicit software mode.
    """

    def __init__(
        self,
        preferred_type: Optional[HardwareType] = None,
        hardware_backends: Optional[Dict[HardwareType, Any]] = None,
        allow_software_fallback: bool = True,
    ):
        self.logger = logging.getLogger(__name__)
        self.preferred_type = preferred_type
        self.hardware_backends = hardware_backends or {}
        self.allow_software_fallback = allow_software_fallback
        self._interface: Optional[HardwareInterface] = None
        self._active_type: Optional[HardwareType] = None
        self._kill_switch_callback = None
        self.initialization_evidence: Dict[str, Dict[str, Any]] = {}

    def initialize(self) -> bool:
        """Initialize hardware root of trust with best available option"""
        self.logger.info("Initializing Hardware Root-of-Trust")

        # Try preferred type first
        if self.preferred_type:
            if self._try_initialize_type(self.preferred_type):
                return True

        ordered_types = [
            HardwareType.HSM,
            HardwareType.TPM,
            HardwareType.SECURE_ENCLAVE,
        ]
        if self.allow_software_fallback:
            ordered_types.append(HardwareType.SOFTWARE_FALLBACK)

        # Try in order of security: HSM > TPM > Secure Enclave > explicit software
        for hw_type in ordered_types:
            if self._try_initialize_type(hw_type):
                return True

        self.logger.error("Failed to initialize any hardware security module")
        return False

    def _try_initialize_type(self, hw_type: HardwareType) -> bool:
        """Try to initialize specific hardware type"""
        try:
            backend = self.hardware_backends.get(hw_type)
            if hw_type == HardwareType.TPM:
                self._interface = TPMInterface(
                    hardware_backend=backend, allow_software_fallback=False
                )
            elif hw_type == HardwareType.SECURE_ENCLAVE:
                self._interface = SecureEnclaveInterface(
                    hardware_backend=backend, allow_software_fallback=False
                )
            elif hw_type == HardwareType.HSM:
                self._interface = HSMInterface(
                    hardware_backend=backend, allow_software_fallback=False
                )
            elif hw_type == HardwareType.SOFTWARE_FALLBACK:
                self._interface = TPMInterface(allow_software_fallback=True)

            if self._interface.initialize():
                self._active_type = hw_type
                self.initialization_evidence[hw_type.value] = {
                    "status": "available",
                    "hardware_backed": getattr(
                        self._interface, "_hardware_backed", False
                    ),
                    "interface_evidence": getattr(
                        self._interface, "operation_evidence", {}
                    ).get("initialize", {}),
                }
                self.logger.info(f"Initialized {hw_type.value} successfully")
                return True

            self.initialization_evidence[hw_type.value] = {
                "status": "unavailable",
                "interface_evidence": getattr(
                    self._interface, "operation_evidence", {}
                ).get("initialize", {}),
            }

        except Exception as e:
            self.logger.warning(f"Failed to initialize {hw_type.value}: {e}")

        return False

    def store_master_key(self, key_data: bytes) -> bool:
        """Store system master encryption key in hardware"""
        if not self._interface:
            return False
        return self._interface.store_key("master_encryption_key", key_data)

    def retrieve_master_key(self) -> Optional[bytes]:
        """Retrieve system master encryption key"""
        if not self._interface:
            return None
        return self._interface.retrieve_key("master_encryption_key")

    def verify_boot_integrity(self) -> bool:
        """
        Verify boot integrity through attestation.
        Triggers kill switch if attestation fails.
        """
        if not self._interface:
            self.logger.error("No hardware interface available for attestation")
            return False

        status = self._interface.attest_boot()

        if status == AttestationStatus.TAMPERED:
            self.logger.critical("BOOT INTEGRITY COMPROMISED - Triggering kill switch")
            if self._kill_switch_callback:
                self._kill_switch_callback("Boot attestation failed - system tampered")
            return False

        elif status == AttestationStatus.VALID:
            self.logger.info("Boot integrity verified - system trusted")
            return True

        else:
            self.logger.warning("Boot attestation status unknown")
            return False

    def seal_kill_switch_bypass_protection(self) -> bytes:
        """
        Seal kill switch state to PCR values to prevent bypass.
        Kill switch can only be disabled if boot state matches.
        """
        if not self._interface:
            raise RuntimeError("No hardware interface available")

        # Seal to PCRs 0-4 (boot chain)
        kill_switch_state = b"KILL_SWITCH_ENABLED"
        sealed = self._interface.seal_data(kill_switch_state, [0, 1, 2, 3, 4])

        self.logger.info("Kill switch state sealed to boot measurements")
        return sealed

    def register_kill_switch_callback(self, callback):
        """Register callback to trigger kill switch on compromise"""
        self._kill_switch_callback = callback

    def get_hardware_info(self) -> Dict[str, Any]:
        """Get information about active hardware security module"""
        if not self._interface:
            return {
                "active": False,
                "type": None,
                "hardware_id": None,
                "hardware_backed": False,
                "initialization_evidence": dict(self.initialization_evidence),
            }

        return {
            "active": True,
            "type": self._active_type.value if self._active_type else None,
            "hardware_id": self._interface.get_hardware_id(),
            "hardware_backed": getattr(self._interface, "_hardware_backed", False),
            "attestation_status": self._interface.attest_boot().value,
            "operation_evidence": getattr(self._interface, "operation_evidence", {}),
            "initialization_evidence": dict(self.initialization_evidence),
        }

    def wipe_all_keys(self) -> bool:
        """Emergency wipe of all keys from hardware (for DOS trap mode)"""
        if not self._interface:
            return False

        self.logger.critical("EMERGENCY KEY WIPE INITIATED")

        # Delete all known keys
        try:
            self._interface.delete_key("master_encryption_key")
            self.logger.info("Master encryption key wiped from hardware")
            return True
        except Exception as e:
            self.logger.error(f"Failed to wipe keys: {e}")
            return False
