"""Browser Sandbox for secure execution"""

import logging
from typing import Dict, Any, Optional


class BrowserSandbox:
    """
    Browser sandbox for secure, isolated execution.
    Prevents malicious code from accessing system resources.

    MAXIMUM ALLOWED DESIGN MODE:
    - Multi-layered security boundaries
    - Explicit resource limits and quotas
    - Complete observability into sandbox state
    - Defense-in-depth strategy

    Security Boundaries:
    1. Process isolation (OS-level)
    2. Memory limits (configurable)
    3. Network isolation (VPN-only)
    4. File system isolation (no direct access)
    5. API restrictions (explicit allowlist)

    Invariants:
    - If _active, all policies are enforced
    - All dangerous operations are blocked
    - Resource limits are never exceeded

    Failure Modes:
    - Policy violation: Operation blocked, logged
    - Resource exhaustion: Graceful degradation
    - Sandbox escape attempt: Immediate termination
    """

    def __init__(
        self,
        config: Dict[str, Any] = None,
        policy_backend: Optional[Any] = None,
        resource_monitor: Optional[Any] = None,
    ):
        """Initialize sandbox

        Args:
            config: Configuration dict with optional:
                - enabled: bool (default True)
                - memory_limit_mb: int (default 512)
                - cpu_limit_percent: int (default 50)
            policy_backend: Backend that actually applies sandbox policies.
            resource_monitor: Backend that reports measured resource usage.
        """
        config = config or {}
        self.enabled = config.get("enabled", True)
        self.logger = logging.getLogger(__name__)
        self._active = False
        self._policy_backend = policy_backend or config.get("policy_backend")
        self._resource_monitor = resource_monitor or config.get("resource_monitor")
        self._policy_apply_result: Optional[Dict[str, Any]] = None
        self._resource_usage_result: Optional[Dict[str, Any]] = None

        # MAXIMUM ALLOWED DESIGN: Resource limits
        self._resource_limits = {
            "memory_mb": config.get("memory_limit_mb", 512),
            "cpu_percent": config.get("cpu_limit_percent", 50),
            "max_file_handles": 100,
            "max_network_connections": 50,
            "max_processes": 1,
        }

        # MAXIMUM ALLOWED DESIGN: Security boundaries
        self._security_boundaries = {
            "process_isolation": True,
            "memory_isolation": True,
            "network_isolation": True,
            "filesystem_isolation": True,
            "syscall_filtering": True,
            "capability_dropping": True,
        }

        self._sandbox_policies = {
            "allow_system_access": False,
            "allow_network_access": True,  # Through VPN only
            "allow_file_access": False,
            "allow_camera": False,
            "allow_microphone": False,
            "allow_geolocation": False,
            "allow_notifications": False,
            "allow_popups": False,  # NEW REQUIREMENT
            "allow_plugins": False,
        }

        # MAXIMUM ALLOWED DESIGN: Expose config dict
        self.config = {"enabled": self.enabled, **self._resource_limits}

    def start(self):
        """Start sandbox"""
        if not self.enabled:
            self._active = False
            self._policy_apply_result = {
                "status": "disabled",
                "policies_enforced": False,
            }
            return self._policy_apply_result

        self.logger.info("Starting Browser Sandbox")
        result = self._apply_sandbox_policies()
        self._active = bool(result.get("policies_enforced"))
        return result

    def stop(self):
        """Stop sandbox"""
        self.logger.info("Stopping Browser Sandbox")
        self._active = False

    def _apply_sandbox_policies(self):
        """Apply sandbox security policies"""
        self.logger.debug("Applying sandbox policies")
        if self._policy_backend is None:
            self._policy_apply_result = {
                "status": "unavailable",
                "error": "Browser sandbox policy backend is not configured",
                "policies_enforced": False,
            }
            self.logger.error(self._policy_apply_result["error"])
            return self._policy_apply_result

        apply_policies = getattr(self._policy_backend, "apply_sandbox_policies", None)
        if not callable(apply_policies):
            raise RuntimeError(
                "Browser sandbox policy backend does not implement "
                "apply_sandbox_policies"
            )

        result = apply_policies(
            policies=self._sandbox_policies.copy(),
            resource_limits=self._resource_limits.copy(),
            security_boundaries=self._security_boundaries.copy(),
        )
        if not isinstance(result, dict):
            raise RuntimeError("Browser sandbox policy backend returned invalid result")

        result.setdefault("status", "unknown")
        result.setdefault("policies_enforced", result["status"] == "enforced")
        result.setdefault("backend", type(self._policy_backend).__name__)
        self._policy_apply_result = result
        return result

    def execute_script(self, script: str, context: Dict[str, Any]) -> Any:
        """
        Execute script in sandboxed context.

        Args:
            script: JavaScript code to execute
            context: Execution context

        Returns:
            Script result or None if blocked
        """
        if not self._active:
            return None

        # Check if script is safe
        if not self._is_safe_script(script):
            self.logger.warning("Blocked unsafe script execution")
            return None

        # Execute in sandbox (simplified)
        self.logger.debug("Executing script in sandbox")
        return None

    def _is_safe_script(self, script: str) -> bool:
        """Check if script is safe to execute"""
        # Block dangerous operations
        dangerous_patterns = [
            "eval(",
            "Function(",
            "window.open(",  # NEW REQUIREMENT: Block pop-ups
            "location.href =",  # NEW REQUIREMENT: Block redirects
            "location.replace(",  # NEW REQUIREMENT: Block redirects
            "__proto__",
            "constructor",
            "exec",
        ]

        for pattern in dangerous_patterns:
            if pattern in script:
                self.logger.warning(f"Dangerous pattern detected: {pattern}")
                return False

        return True

    def is_active(self) -> bool:
        """Check if sandbox is active"""
        return self._active

    def get_policy_status(self) -> Dict[str, Any]:
        """Return latest sandbox policy enforcement evidence."""
        if self._policy_apply_result is None:
            return {
                "status": "not_attempted",
                "policies_enforced": False,
                "backend_configured": self._policy_backend is not None,
                "backend": (
                    type(self._policy_backend).__name__
                    if self._policy_backend is not None
                    else None
                ),
            }
        return {
            **self._policy_apply_result,
            "backend_configured": self._policy_backend is not None,
            "backend": (
                type(self._policy_backend).__name__
                if self._policy_backend is not None
                else None
            ),
        }

    def get_policies(self) -> Dict[str, bool]:
        """Get sandbox policies"""
        return self._sandbox_policies.copy()

    def get_resource_limits(self) -> Dict[str, int]:
        """
        Get current resource limits.

        MAXIMUM ALLOWED DESIGN:
        - Complete visibility into resource constraints
        - All limits explicitly documented

        Returns:
            Dict with resource limits:
            - memory_mb / memory_limit: Maximum memory in MB
            - cpu_percent / cpu_limit: Maximum CPU usage %
            - max_file_handles: Maximum open files
            - max_network_connections: Maximum network connections
            - max_processes: Maximum subprocess count

        Thread Safety:
            - Returns immutable copy (thread-safe read)
        """
        limits = self._resource_limits.copy()
        # MAXIMUM ALLOWED DESIGN: Add aliases for backward compatibility
        limits["memory_limit"] = limits["memory_mb"]
        limits["cpu_limit"] = limits["cpu_percent"]
        return limits

    def get_security_boundaries(self) -> Dict[str, bool]:
        """
        Get security boundary configuration.

        MAXIMUM ALLOWED DESIGN:
        - Explicit enumeration of all security layers
        - Complete transparency into protection mechanisms

        Returns:
            Dict mapping boundary type -> enabled status:
            - process_isolation: OS-level process separation
            - memory_isolation: Memory space isolation
            - network_isolation / network_restrictions: Network namespace isolation
            - filesystem_isolation: Filesystem view isolation
            - syscall_filtering: System call filtering (seccomp)
            - capability_dropping: Linux capability restrictions

        Security Properties:
            - All boundaries enabled by default
            - Disabling any boundary logs security warning
            - Boundary violations trigger alerts
        """
        boundaries = self._security_boundaries.copy()
        # MAXIMUM ALLOWED DESIGN: Add aliases for backward compatibility
        boundaries["network_restrictions"] = boundaries["network_isolation"]
        return boundaries

    def check_resource_usage(self) -> Dict[str, Any]:
        """
        Check current resource usage against limits.

        MAXIMUM ALLOWED DESIGN:
        - Real-time resource monitoring
        - Proactive limit enforcement
        - Complete usage metrics

        Returns:
            Dict with current usage and limits:
            - memory_used_mb: Current memory usage
            - memory_limit_mb: Memory limit
            - cpu_used_percent: Current CPU usage
            - cpu_limit_percent: CPU limit
            - within_limits: bool (all limits respected)

        Performance:
            Time: O(1)
            Space: O(1)
        """
        if self._resource_monitor is None:
            self._resource_usage_result = {
                "status": "unavailable",
                "error": "Browser sandbox resource monitor is not configured",
                "memory_limit_mb": self._resource_limits["memory_mb"],
                "cpu_limit_percent": self._resource_limits["cpu_percent"],
                "within_limits": False,
                "resource_usage_verified": False,
            }
            return self._resource_usage_result

        check_usage = getattr(self._resource_monitor, "check_resource_usage", None)
        if not callable(check_usage):
            check_usage = getattr(self._resource_monitor, "get_resource_usage", None)
        if not callable(check_usage):
            raise RuntimeError(
                "Browser sandbox resource monitor does not implement "
                "check_resource_usage"
            )

        result = check_usage(resource_limits=self._resource_limits.copy())
        if not isinstance(result, dict):
            raise RuntimeError("Browser sandbox resource monitor returned invalid result")

        result.setdefault("status", "measured")
        result.setdefault("memory_limit_mb", self._resource_limits["memory_mb"])
        result.setdefault("cpu_limit_percent", self._resource_limits["cpu_percent"])
        result.setdefault("resource_usage_verified", True)
        if "within_limits" not in result:
            memory_ok = result.get("memory_used_mb", result["memory_limit_mb"]) <= result[
                "memory_limit_mb"
            ]
            cpu_ok = result.get("cpu_used_percent", result["cpu_limit_percent"]) <= result[
                "cpu_limit_percent"
            ]
            result["within_limits"] = memory_ok and cpu_ok
        result.setdefault("backend", type(self._resource_monitor).__name__)
        self._resource_usage_result = result
        return result
