"""Privacy Auditor - Real-time privacy monitoring"""

import logging
import json
from typing import Dict, Any, List, Optional
from datetime import datetime
from cryptography.fernet import Fernet


class PrivacyAuditor:
    """
    Real-time privacy audit system.
    Monitors and logs privacy-related events.
    """

    def __init__(self, config: Dict[str, Any]):
        self.enabled = config.get("session_auditing", True)
        self.leak_auditing = config.get("leak_auditing", True)
        self.leak_audit_backend = config.get("leak_audit_backend")
        self.logger = logging.getLogger(__name__)
        self._active = False
        self._cipher = config.get("audit_cipher") or Fernet(Fernet.generate_key())

        self._encrypted_audit_log: List[bytes] = []
        self._violation_indexes: List[int] = []
        self._leak_tests: List[Any] = []
        self._last_leak_results: Dict[str, Optional[Dict[str, Any]]] = {
            "dns": None,
            "ipv6": None,
            "webrtc": None,
        }

    def start(self):
        """Start privacy auditor"""
        self.logger.info("Starting Privacy Auditor")
        self._active = True
        self._run_initial_audit()

    def stop(self):
        """Stop privacy auditor"""
        self.logger.info("Stopping Privacy Auditor")
        self._active = False

    def _run_initial_audit(self):
        """Run initial privacy audit"""
        self.log_event("audit_started", {"timestamp": datetime.now().isoformat()})

    def log_event(self, event_type: str, details: Dict[str, Any]):
        """Log privacy event"""
        if not self._active:
            return

        event = {
            "type": event_type,
            "timestamp": datetime.now().isoformat(),
            "details": details,
        }

        encrypted_event = self._cipher.encrypt(
            json.dumps(event, sort_keys=True).encode("utf-8")
        )
        self._encrypted_audit_log.append(encrypted_event)

        # Check for privacy violations
        if self._is_privacy_violation(event_type, details):
            self._violation_indexes.append(len(self._encrypted_audit_log) - 1)
            self.logger.warning(f"Privacy violation detected: {event_type}")

    def _is_privacy_violation(self, event_type: str, details: Dict[str, Any]) -> bool:
        """Check if event is a privacy violation"""
        violation_types = [
            "cookie_stored",
            "history_saved",
            "fingerprint_leaked",
            "dns_leaked",
            "ipv6_leaked",
            "tracker_allowed",
        ]

        return event_type in violation_types

    def audit_dns_leak(self) -> bool:
        """
        Audit for DNS leaks.

        Returns:
            True if no leak, False if leak detected
        """
        if not self.leak_auditing:
            return True

        result = self._run_leak_check("dns", "audit_dns_leak")
        return bool(result.get("protected"))

    def audit_ipv6_leak(self) -> bool:
        """
        Audit for IPv6 leaks.

        Returns:
            True if no leak, False if leak detected
        """
        if not self.leak_auditing:
            return True

        result = self._run_leak_check("ipv6", "audit_ipv6_leak")
        return bool(result.get("protected"))

    def audit_webrtc_leak(self) -> bool:
        """
        Audit for WebRTC IP leaks.

        Returns:
            True if no leak, False if leak detected
        """
        if not self.leak_auditing:
            return True

        result = self._run_leak_check("webrtc", "audit_webrtc_leak")
        return bool(result.get("protected"))

    def run_full_audit(self) -> Dict[str, Any]:
        """
        Run comprehensive privacy audit.

        Returns:
            Audit results
        """
        results = {
            "dns_leak": self.audit_dns_leak(),
            "ipv6_leak": self.audit_ipv6_leak(),
            "webrtc_leak": self.audit_webrtc_leak(),
            "violations": len(self._violation_indexes),
            "events_logged": len(self._encrypted_audit_log),
            "audit_events_encrypted": True,
            "leak_audit_backend_configured": self.leak_audit_backend is not None,
            "leak_results": self._last_leak_results.copy(),
        }

        self.logger.info(f"Full privacy audit completed: {results}")
        return results

    def get_audit_log(self) -> List[Dict[str, Any]]:
        """Get full audit log as a decrypted caller view."""
        return [self._decrypt_event(entry) for entry in self._encrypted_audit_log]

    def get_encrypted_audit_log(self) -> List[bytes]:
        """Get encrypted audit log records."""
        return self._encrypted_audit_log.copy()

    def get_violations(self) -> List[Dict[str, Any]]:
        """Get privacy violations"""
        events = self.get_audit_log()
        return [events[index] for index in self._violation_indexes]

    def clear_logs(self):
        """Clear audit logs"""
        self._encrypted_audit_log.clear()
        self._violation_indexes.clear()

    def _decrypt_event(self, encrypted_event: bytes) -> Dict[str, Any]:
        """Decrypt one audit event."""
        return json.loads(self._cipher.decrypt(encrypted_event).decode("utf-8"))

    def _run_leak_check(self, leak_type: str, backend_method: str) -> Dict[str, Any]:
        """Run a leak audit through a configured backend."""
        event_type = f"{leak_type}_leak_check"
        if self.leak_audit_backend is None:
            result = {
                "status": "unavailable",
                "error": "Privacy leak audit backend is not configured",
                "protected": False,
                "leak_type": leak_type,
            }
            self._last_leak_results[leak_type] = result
            self.log_event(event_type, result)
            return result

        check = getattr(self.leak_audit_backend, backend_method, None)
        if not callable(check):
            raise RuntimeError(
                f"Privacy leak audit backend does not implement {backend_method}"
            )

        result = check()
        if not isinstance(result, dict):
            raise RuntimeError("Privacy leak audit backend returned invalid result")

        result.setdefault("status", "verified")
        if "protected" not in result:
            result["protected"] = not bool(result.get("leak_detected", True))
        result.setdefault("leak_type", leak_type)
        result.setdefault("backend", type(self.leak_audit_backend).__name__)
        self._last_leak_results[leak_type] = result
        self.log_event(event_type, result)
        return result
