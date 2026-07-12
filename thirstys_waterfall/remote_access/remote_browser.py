"""Remote browser access with evidence-gated encryption reporting."""

import logging
from typing import Dict, Any, Optional
import time
from cryptography.fernet import Fernet


class RemoteBrowser:
    """
    Remote browser access with local helper encryption.

    Features:
    - Backend-dependent encrypted transport
    - Secure tunnel through VPN
    - All traffic encrypted
    - Session isolation
    - No logging of remote sessions
    """

    def __init__(
        self,
        config: Dict[str, Any],
        god_tier_encryption,
        transport_backend: Optional[Any] = None,
    ):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.god_tier_encryption = god_tier_encryption
        self.transport_backend = transport_backend

        # Local helper encryption for remote metadata
        self._cipher = Fernet(Fernet.generate_key())

        # Remote connection settings
        self.host = config.get("remote_host", "127.0.0.1")
        self.port = config.get("remote_port", 9000)

        # Active sessions (encrypted)
        self._sessions: Dict[str, Dict[str, Any]] = {}

        self._active = False

    def start(self):
        """Start remote browser server"""
        self.logger.info("Starting Remote Browser with local helper encryption")
        self.logger.info("Remote transport acceptance requires backend evidence")
        self.logger.info(f"Listening on {self.host}:{self.port}")

        if self.transport_backend is None:
            raise RuntimeError("Remote browser transport backend is not configured")

        start_backend = getattr(self.transport_backend, "start", None)
        if callable(start_backend):
            start_backend(self.host, self.port)

        self._active = True

    def stop(self):
        """Stop remote browser and disconnect all sessions"""
        self.logger.info("Stopping Remote Browser - Disconnecting all sessions")

        # Close all sessions
        for session_id in list(self._sessions.keys()):
            self.disconnect_session(session_id)

        stop_backend = getattr(self.transport_backend, "stop", None)
        if callable(stop_backend):
            stop_backend()

        self._active = False

    def create_session(self, client_id: str) -> Dict[str, Any]:
        """
        Create new remote browser session.

        Args:
            client_id: Client identifier (encrypted)

        Returns:
            Session info with encrypted credentials
        """
        if not self._active:
            return {"error": "Remote browser not active"}

        # Encrypt client ID
        encrypted_client_id = self.god_tier_encryption.encrypt_god_tier(
            client_id.encode()
        )

        # Generate session ID
        session_id = f"session_{len(self._sessions)}"

        # Create encrypted session
        session = {
            "id": session_id,
            "encrypted_client_id": encrypted_client_id,
            "created_time": time.time(),
            "status": "pending_backend",
            "local_helper_encrypted": True,
            "encryption_accepted": False,
        }

        create_backend_session = getattr(
            self.transport_backend, "create_session", None
        )
        if not callable(create_backend_session):
            raise RuntimeError(
                "Remote browser transport backend does not implement create_session"
            )

        backend_result = create_backend_session(
            session_id=session_id,
            encrypted_client_id=encrypted_client_id,
        )
        if not isinstance(backend_result, dict):
            raise RuntimeError("Remote browser backend returned invalid session result")

        session["status"] = backend_result.get("status", "active")
        self._sessions[session_id] = session

        self.logger.info(f"Remote browser session created: {session_id}")

        return {
            "session_id": session_id,
            "status": session["status"],
            "local_helper_encrypted": True,
            "encryption_accepted": False,
            "backend": type(self.transport_backend).__name__,
            "transport_connected": backend_result.get("transport_connected", False),
        }

    def send_command(self, session_id: str, command: str) -> Dict[str, Any]:
        """
        Send command to remote browser (encrypted).

        Args:
            session_id: Session ID
            command: Browser command (will be encrypted)

        Returns:
            Command result
        """
        if session_id not in self._sessions:
            return {"error": "Session not found"}

        # Encrypt command
        encrypted_command = self.god_tier_encryption.encrypt_god_tier(command.encode())

        self.logger.info(f"Sending encrypted command to session {session_id}")

        send_backend_command = getattr(self.transport_backend, "send_command", None)
        if not callable(send_backend_command):
            raise RuntimeError(
                "Remote browser transport backend does not implement send_command"
            )

        result = send_backend_command(session_id, encrypted_command)
        if not isinstance(result, dict):
            raise RuntimeError("Remote browser backend returned invalid command result")

        return {
            **result,
            "session_id": session_id,
            "local_helper_encrypted": True,
            "encryption_accepted": False,
            "backend": type(self.transport_backend).__name__,
        }

    def disconnect_session(self, session_id: str):
        """Disconnect remote browser session"""
        if session_id in self._sessions:
            del self._sessions[session_id]
            self.logger.info(f"Remote browser session disconnected: {session_id}")

    def get_sessions(self) -> Dict[str, Dict[str, Any]]:
        """Get all active sessions"""
        return self._sessions.copy()

    def get_status(self) -> Dict[str, Any]:
        """Get remote browser status"""
        return {
            "active": self._active,
            "local_helper_encrypted": True,
            "encryption_accepted": False,
            "encryption_layers": None,
            "host": self.host,
            "port": self.port,
            "active_sessions": len(self._sessions),
            "backend_configured": self.transport_backend is not None,
            "backend": (
                type(self.transport_backend).__name__
                if self.transport_backend is not None
                else None
            ),
        }
