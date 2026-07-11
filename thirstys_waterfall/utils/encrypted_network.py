"""Encrypted Network Traffic Handler"""

import json
import logging
from typing import Dict, Any
from cryptography.fernet import Fernet


class EncryptedNetworkHandler:
    """
    Encrypts and decrypts payloads explicitly passed through this handler.

    This helper does not claim host-wide traffic interception. Callers that need
    full transport coverage must route their network backend through this class
    or provide separate evidence for the platform-level tunnel.
    """

    def __init__(self, cipher: Fernet):
        self.logger = logging.getLogger(__name__)
        self._cipher = cipher
        self._active = False
        self._encryption_layers = ("fernet",)

    def start(self):
        """Start encrypted network handler"""
        self.logger.info(
            "Starting Encrypted Network Handler - explicit payload encryption active"
        )
        self._active = True

    def stop(self):
        """Stop encrypted network handler"""
        self.logger.info("Stopping Encrypted Network Handler")
        self._active = False

    def encrypt_request(self, request: Dict[str, Any]) -> bytes:
        """
        Encrypt outgoing network request.
        Request payload is JSON-serialized and encrypted.

        Args:
            request: Request data

        Returns:
            Encrypted request data
        """
        if not self._active:
            return b""

        request_bytes = self._serialize_payload(request)

        encrypted_layer1 = self._cipher.encrypt(request_bytes)

        self.logger.debug(f"Encrypted outgoing request: {len(encrypted_layer1)} bytes")
        return encrypted_layer1

    def decrypt_response(self, encrypted_response: bytes) -> Dict[str, Any]:
        """
        Decrypt incoming network response.

        Args:
            encrypted_response: Encrypted response data

        Returns:
            Decrypted response
        """
        if not self._active:
            return {}

        try:
            decrypted = self._cipher.decrypt(encrypted_response)
            return self._parse_payload(decrypted)

        except Exception as e:
            self.logger.error(f"Failed to decrypt response: {e}")
            return {}

    def encrypt_dns_query(self, hostname: str) -> bytes:
        """
        Encrypt DNS query.
        Hostname is encrypted before DNS resolution.
        """
        return self._cipher.encrypt(hostname.encode())

    def encrypt_packet(self, packet: Dict[str, Any]) -> bytes:
        """
        Encrypt individual network packet.
        Packet payload is JSON-serialized and encrypted.
        """
        packet_bytes = self._serialize_payload(packet)
        return self._cipher.encrypt(packet_bytes)

    def decrypt_packet(self, encrypted_packet: bytes) -> Dict[str, Any]:
        """Decrypt network packet"""
        try:
            decrypted = self._cipher.decrypt(encrypted_packet)
            packet = self._parse_payload(decrypted)
            packet.setdefault("decrypted", True)
            return packet
        except Exception:
            return {}

    def get_status(self) -> Dict[str, Any]:
        """Return evidence about the handler's configured encryption surface."""
        return {
            "active": self._active,
            "handler_scope": "explicit_payloads_only",
            "host_wide_interception": False,
            "encryption_layers": list(self._encryption_layers),
        }

    @staticmethod
    def _serialize_payload(payload: Dict[str, Any]) -> bytes:
        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    @staticmethod
    def _parse_payload(payload: bytes) -> Dict[str, Any]:
        decoded = payload.decode("utf-8")
        try:
            parsed = json.loads(decoded)
        except json.JSONDecodeError:
            return {"data": decoded}

        if isinstance(parsed, dict):
            return parsed

        return {"data": parsed}
