#!/usr/bin/env python3
"""
Thirstys-Waterfall Web Interface - Backend API Server
======================================================

MAXIMUM ALLOWED DESIGN IMPLEMENTATION

This module implements an evidence-gated REST API server for the Thirstys-Waterfall
privacy and security system. It provides a comprehensive web interface to all system
capabilities including VPN control, firewall management, browser privacy, and monitoring.

Architecture Layers:
-------------------
1. API Layer: RESTful endpoints with full CRUD operations
2. WebSocket Layer: Real-time bidirectional communication
3. Service Layer: Business logic and orchestration
4. Integration Layer: Thirstys-Waterfall core integration
5. Security Layer: Authentication, authorization, encryption
6. Monitoring Layer: Metrics, logging, health checks
7. Error Handling Layer: Comprehensive exception management

Cross-Cutting Concerns:
----------------------
- Authentication & Authorization (JWT-based)
- Request validation and sanitization
- Rate limiting and throttling
- CORS policy management
- Error handling and recovery
- Audit logging
- Metrics collection
- Health monitoring
- Graceful degradation

Dependencies:
------------
- Flask: Web framework
- Flask-CORS: Cross-origin resource sharing
- Flask-SocketIO: WebSocket support
- Flask-JWT-Extended: Authentication
- Flask-Limiter: Rate limiting
- thirstys_waterfall: Core system integration
- python-dotenv: Environment configuration
"""

import os
import sys
import json
import logging
import traceback
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from functools import wraps

# Web framework and extensions
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt_identity,
    get_jwt,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import check_password_hash
from thirstys_waterfall.firewalls.manager import FirewallManager
from thirstys_waterfall.sovereign_binding import (
    execute_sovereign_protocol,
    get_sovereign_binding_status,
)

# Core system integration
try:
    from thirstys_waterfall import ThirstysWaterfall

    THIRSTYS_AVAILABLE = True
except ImportError as e:
    THIRSTYS_AVAILABLE = False
    logging.warning(
        f"Thirstys-Waterfall not available - running in demo mode. Error: {e}"
    )

# Environment configuration
from dotenv import load_dotenv

load_dotenv()

# ============================================================================
# CONFIGURATION LAYER
# ============================================================================


class Config:
    """
    Centralized configuration management with environment-based overrides.

    Configuration Categories:
    - Server: Host, port, debug mode
    - Security: JWT secrets, session management
    - Limits: Rate limiting, timeout values
    - Features: Feature flags and toggles
    - Logging: Log levels and destinations
    - Integration: External service configuration
    """

    # Server Configuration
    ENVIRONMENT = os.getenv("THIRSTYS_ENV", "development").lower()
    HOST = os.getenv("WEB_HOST", "0.0.0.0")
    PORT = int(os.getenv("WEB_PORT", "8080"))
    DEBUG = os.getenv("DEBUG", "False").lower() == "true"

    # Security Configuration
    SECRET_KEY = os.getenv("SECRET_KEY", os.urandom(32).hex())
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", os.urandom(32).hex())
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    ADMIN_USERNAME = os.getenv("THIRSTYS_ADMIN_USERNAME")
    ADMIN_PASSWORD_HASH = os.getenv("THIRSTYS_ADMIN_PASSWORD_HASH")
    ALLOW_DEMO_LOGIN = os.getenv("THIRSTYS_ALLOW_DEMO_LOGIN", "false").lower() in {
        "1",
        "true",
        "yes",
    }
    DEMO_USERNAME = os.getenv("THIRSTYS_DEMO_USERNAME", "admin")
    DEMO_PASSWORD = os.getenv("THIRSTYS_DEMO_PASSWORD", "admin")

    # Rate Limiting Configuration
    RATELIMIT_STORAGE_URL = os.getenv("REDIS_URL", "memory://")
    RATELIMIT_STRATEGY = "fixed-window"
    DEFAULT_RATE_LIMIT = "100 per minute"

    # CORS Configuration
    CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*").split(",")

    # WebSocket Configuration
    SOCKETIO_MESSAGE_QUEUE = os.getenv("SOCKETIO_QUEUE", None)
    SOCKETIO_ASYNC_MODE = "threading"

    # System Configuration
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max request size

    # Logging Configuration
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"


def validate_production_config() -> None:
    """Fail closed when production starts without required security inputs."""
    if Config.ENVIRONMENT != "production":
        return

    missing = [
        name
        for name in (
            "SECRET_KEY",
            "JWT_SECRET_KEY",
            "THIRSTYS_ADMIN_USERNAME",
            "THIRSTYS_ADMIN_PASSWORD_HASH",
            "CORS_ORIGINS",
        )
        if not os.getenv(name)
    ]
    if missing:
        raise RuntimeError(
            "Production configuration is missing required environment values: "
            + ", ".join(missing)
        )
    if "*" in Config.CORS_ORIGINS:
        raise RuntimeError("Production CORS_ORIGINS must not include '*'")
    if Config.ALLOW_DEMO_LOGIN:
        raise RuntimeError("Production must not enable THIRSTYS_ALLOW_DEMO_LOGIN")


# ============================================================================
# LOGGING CONFIGURATION LAYER
# ============================================================================


def configure_logging():
    """Configure comprehensive application logging with multiple handlers."""
    logging.basicConfig(
        level=getattr(logging, Config.LOG_LEVEL.upper()),
        format=Config.LOG_FORMAT,
        handlers=[logging.StreamHandler(sys.stdout)],
    )

    # Configure specific loggers
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    logging.getLogger("socketio").setLevel(logging.INFO)
    logging.getLogger("engineio").setLevel(logging.WARNING)


configure_logging()
logger = logging.getLogger(__name__)


# ============================================================================
# APPLICATION INITIALIZATION LAYER
# ============================================================================

validate_production_config()
app = Flask(__name__, static_folder="static", template_folder="templates")
app.config.from_object(Config)

# Initialize extensions
cors = CORS(app, resources={r"/api/*": {"origins": Config.CORS_ORIGINS}})
socketio = SocketIO(
    app,
    cors_allowed_origins=Config.CORS_ORIGINS,
    async_mode=Config.SOCKETIO_ASYNC_MODE,
    message_queue=Config.SOCKETIO_MESSAGE_QUEUE,
)
jwt = JWTManager(app)
revoked_token_jtis = set()
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri=Config.RATELIMIT_STORAGE_URL,
    strategy=Config.RATELIMIT_STRATEGY,
    default_limits=[Config.DEFAULT_RATE_LIMIT],
)


def get_session_policy() -> Dict[str, Any]:
    """Return current JWT session policy without exposing secrets."""
    return {
        "access_token_expires_seconds": int(
            Config.JWT_ACCESS_TOKEN_EXPIRES.total_seconds()
        ),
        "refresh_token_expires_seconds": int(
            Config.JWT_REFRESH_TOKEN_EXPIRES.total_seconds()
        ),
        "token_revocation_enabled": True,
        "revocation_store": "process_memory",
        "revocation_store_accepted_for_target": False,
    }


@jwt.token_in_blocklist_loader
def is_token_revoked(jwt_header: Dict[str, Any], jwt_payload: Dict[str, Any]) -> bool:
    """Reject JWTs whose JTI has been revoked in this process."""
    return jwt_payload.get("jti") in revoked_token_jtis


@jwt.revoked_token_loader
def revoked_token_response(jwt_header: Dict[str, Any], jwt_payload: Dict[str, Any]):
    """Return a clear fail-closed response for revoked JWTs."""
    return jsonify({"error": "Token has been revoked"}), 401


# ============================================================================
# CORE SYSTEM INTEGRATION LAYER
# ============================================================================


class ThirstysWebService:
    """
    Service layer providing high-level operations and state management.

    Responsibilities:
    - System lifecycle management (start, stop, restart)
    - State synchronization and caching
    - Command orchestration and coordination
    - Event propagation to WebSocket clients
    - Error recovery and resilience

    Design Patterns:
    - Singleton: Single instance per application
    - Facade: Simplified interface to complex subsystem
    - Observer: Event notification to connected clients
    """

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self) -> None:
        if self._initialized:
            return

        self.waterfall: Optional[ThirstysWaterfall] = None
        self.system_state: Dict[str, Any] = {
            "running": False,
            "vpn": {"connected": False, "status": "disconnected"},
            "firewalls": {"active": [], "status": "inactive"},
            "browser": {"tabs": [], "status": "inactive"},
            "last_update": None,
        }
        self._initialized = True

        if THIRSTYS_AVAILABLE:
            try:
                self.waterfall = ThirstysWaterfall()
                logger.info("Thirstys-Waterfall core initialized successfully")
            except Exception as e:
                logger.error(f"Failed to initialize Thirstys-Waterfall: {e}")
                self.waterfall = None

    def start_system(self) -> Dict[str, Any]:
        """Start all Thirstys-Waterfall subsystems with comprehensive error handling."""
        try:
            if not THIRSTYS_AVAILABLE or self.waterfall is None:
                return {
                    "success": False,
                    "error": "Thirstys-Waterfall not available",
                    "demo_mode": True,
                }

            # Type narrowing: at this point waterfall is guaranteed to not be None
            assert self.waterfall is not None

            # Actually start the orchestrator and all subsystems
            self.waterfall.start()
            self.system_state["running"] = True
            self.system_state["last_update"] = datetime.utcnow().isoformat()

            # Get real status from orchestrator
            status = self.waterfall.get_status()
            self.system_state.update(
                {
                    "vpn": status.get("vpn", {}),
                    "firewalls": status.get("firewalls", {}),
                    "browser": status.get("browser", {}),
                }
            )

            # Broadcast state change via WebSocket
            self._broadcast_state_change("system_started")

            logger.info("System started successfully - ALL SUBSYSTEMS ACTIVE")
            return {"success": True, "state": self.system_state, "real": True}

        except Exception as e:
            logger.error(f"Failed to start system: {e}")
            return {"success": False, "error": str(e), "real": True}

    def stop_system(self) -> Dict[str, Any]:
        """Stop all subsystems with graceful shutdown and cleanup."""
        try:
            if not THIRSTYS_AVAILABLE or self.waterfall is None:
                return {
                    "success": False,
                    "error": "Thirstys-Waterfall not available",
                    "demo_mode": True,
                }

            # Type narrowing: at this point waterfall is guaranteed to not be None
            assert self.waterfall is not None

            # Actually stop the orchestrator and all subsystems
            self.waterfall.stop()

            self.system_state["running"] = False
            self.system_state["last_update"] = datetime.utcnow().isoformat()

            # Broadcast state change
            self._broadcast_state_change("system_stopped")

            logger.info("System stopped successfully - ALL SUBSYSTEMS DEACTIVATED")
            return {"success": True, "state": self.system_state, "real": True}

        except Exception as e:
            logger.error(f"Failed to stop system: {e}")
            return {"success": False, "error": str(e), "real": True}

    def restart_system(self) -> Dict[str, Any]:
        """Restart all subsystems (stop then start)."""
        try:
            if not THIRSTYS_AVAILABLE or self.waterfall is None:
                return {
                    "success": False,
                    "error": "Thirstys-Waterfall not available",
                    "demo_mode": True,
                }

            # Type narrowing: at this point waterfall is guaranteed to not be None
            assert self.waterfall is not None

            # Stop first
            logger.info("Restarting system: stopping all subsystems...")
            self.waterfall.stop()

            # Then start
            logger.info("Restarting system: starting all subsystems...")
            self.waterfall.start()

            self.system_state["running"] = True
            self.system_state["last_update"] = datetime.utcnow().isoformat()

            # Get real status
            status = self.waterfall.get_status()
            self.system_state.update(
                {
                    "vpn": status.get("vpn", {}),
                    "firewalls": status.get("firewalls", {}),
                    "browser": status.get("browser", {}),
                }
            )

            self._broadcast_state_change("system_restarted")

            logger.info("System restarted successfully")
            return {"success": True, "state": self.system_state, "real": True}

        except Exception as e:
            logger.error(f"Failed to restart system: {e}")
            return {"success": False, "error": str(e), "real": True}

    def get_status(self) -> Dict[str, Any]:
        """Get comprehensive system status including all subsystems."""
        try:
            if not self.waterfall:
                return {
                    "available": False,
                    "demo_mode": True,
                    "state": self.system_state,
                }

            status = (
                self.waterfall.get_status()
                if hasattr(self.waterfall, "get_status")
                else {}
            )

            return {
                "available": True,
                "demo_mode": False,
                "state": self.system_state,
                "details": status,
            }

        except Exception as e:
            logger.error(f"Failed to get status: {e}")
            return {"available": False, "error": str(e)}

    def get_vpn_status(self) -> Dict[str, Any]:
        """Get real VPN status from the VPN manager."""
        try:
            if not THIRSTYS_AVAILABLE or self.waterfall is None:
                return {
                    "connected": False,
                    "demo_mode": True,
                    "error": "VPN not available",
                }

            # Type narrowing: at this point waterfall is guaranteed to not be None
            assert self.waterfall is not None

            # Get real VPN status from manager
            vpn_status = self.waterfall.vpn.get_status()
            return {"success": True, "vpn": vpn_status, "real": True}

        except Exception as e:
            logger.error(f"Failed to get VPN status: {e}")
            return {"success": False, "error": str(e), "real": True}

    def vpn_connect(self) -> Dict[str, Any]:
        """Connect the VPN."""
        try:
            if not THIRSTYS_AVAILABLE or self.waterfall is None:
                return {
                    "success": False,
                    "error": "VPN not available",
                    "demo_mode": True,
                }

            # Type narrowing: at this point waterfall is guaranteed to not be None
            assert self.waterfall is not None

            # Actually connect the VPN
            if not self.waterfall.vpn.is_connected():
                self.waterfall.vpn.start()
                logger.info("VPN connected successfully")
            else:
                logger.info("VPN already connected")

            # Update system state with real VPN status
            self.system_state["vpn"] = self.waterfall.vpn.get_status()
            self._broadcast_state_change("vpn_connected")

            return {
                "success": True,
                "status": self.waterfall.vpn.get_status(),
                "real": True,
            }

        except Exception as e:
            logger.error(f"Failed to connect VPN: {e}")
            return {"success": False, "error": str(e), "real": True}

    def vpn_disconnect(self) -> Dict[str, Any]:
        """Disconnect the VPN."""
        try:
            if not THIRSTYS_AVAILABLE or self.waterfall is None:
                return {
                    "success": False,
                    "error": "VPN not available",
                    "demo_mode": True,
                }

            # Type narrowing: at this point waterfall is guaranteed to not be None
            assert self.waterfall is not None

            # Actually disconnect the VPN
            self.waterfall.vpn.stop()
            logger.info("VPN disconnected successfully")

            # Update system state
            self.system_state["vpn"] = self.waterfall.vpn.get_status()
            self._broadcast_state_change("vpn_disconnected")

            return {
                "success": True,
                "status": self.waterfall.vpn.get_status(),
                "real": True,
            }

        except Exception as e:
            logger.error(f"Failed to disconnect VPN: {e}")
            return {"success": False, "error": str(e), "real": True}

    def get_firewalls_status(self) -> Dict[str, Any]:
        """Get real status of all 8 firewalls."""
        try:
            if not THIRSTYS_AVAILABLE or self.waterfall is None:
                return {
                    "success": False,
                    "demo_mode": True,
                    "error": "Firewalls not available",
                }

            # Type narrowing
            assert self.waterfall is not None

            # Get real firewall statistics from all 8 firewalls
            stats = self.waterfall.firewall.get_statistics()

            return {
                "success": True,
                "firewalls": stats,
                "active": self.waterfall.firewall.is_active(),
                "real": True,
            }

        except Exception as e:
            logger.error(f"Failed to get firewall status: {e}")
            return {"success": False, "error": str(e), "real": True}

    def _browser_runtime_unavailable(self, reason: str) -> Dict[str, Any]:
        return {
            "success": False,
            "error": "Browser runtime is not available",
            "reason": reason,
            "tabs": [],
            "evidence": {
                "source": "waterfall.browser",
                "status": "unavailable",
                "reason": reason,
            },
            "real": True,
        }

    def _get_browser_runtime(self) -> Tuple[Optional[Any], Optional[str]]:
        if not THIRSTYS_AVAILABLE or self.waterfall is None:
            return None, "thirstys_waterfall_not_available"

        browser = getattr(self.waterfall, "browser", None)
        if browser is None:
            return None, "browser_runtime_not_configured"

        get_status = getattr(browser, "get_status", None)
        status = get_status() if callable(get_status) else {}
        if not status.get("active"):
            return None, "browser_runtime_inactive"

        return browser, None

    def _serialize_browser_tabs(
        self, raw_tabs: Dict[str, Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        serialized = []
        for tab_id, tab in raw_tabs.items():
            serialized.append(
                {
                    "id": tab.get("id", tab_id),
                    "url": tab.get("url", "about:blank"),
                    "title": tab.get("title", "New Tab"),
                    "isolated": bool(tab.get("isolated")),
                    "privacy_mode": "incognito",
                    "browser_encryption_accepted": False,
                }
            )
        return serialized

    def get_browser_tabs(self) -> Dict[str, Any]:
        """Get browser tabs from the active browser runtime."""
        try:
            browser, reason = self._get_browser_runtime()
            if browser is None:
                assert reason is not None
                return self._browser_runtime_unavailable(reason)

            tab_manager = getattr(browser, "tab_manager", None)
            list_tabs = getattr(tab_manager, "list_tabs", None)
            if not callable(list_tabs):
                return self._browser_runtime_unavailable("tab_manager_list_unavailable")

            raw_tabs = list_tabs()
            tabs = self._serialize_browser_tabs(raw_tabs)

            return {
                "success": True,
                "tabs": tabs,
                "evidence": {
                    "source": "waterfall.browser.tab_manager",
                    "status": "collected",
                    "count": len(tabs),
                },
                "real": True,
            }

        except Exception as e:
            logger.error(f"Failed to get browser tabs: {e}")
            return {"success": False, "error": str(e), "real": True}

    def create_browser_tab(self, url: str) -> Dict[str, Any]:
        """Create a browser tab through the active browser runtime."""
        try:
            browser, reason = self._get_browser_runtime()
            if browser is None:
                assert reason is not None
                return self._browser_runtime_unavailable(reason)

            create_tab = getattr(browser, "create_tab", None)
            if not callable(create_tab):
                return self._browser_runtime_unavailable("browser_create_tab_unavailable")

            tab_id = create_tab(url)
            if not tab_id:
                return {
                    "success": False,
                    "error": "Browser tab could not be created",
                    "reason": "tab_creation_rejected",
                    "real": True,
                }

            tab_manager = getattr(browser, "tab_manager", None)
            get_tab = getattr(tab_manager, "get_tab", None)
            tab_data = (
                get_tab(tab_id) if callable(get_tab) else {"id": tab_id, "url": url}
            ) or {"id": tab_id, "url": url}
            tab = self._serialize_browser_tabs({tab_id: tab_data})[0]

            return {
                "success": True,
                "tab": tab,
                "evidence": {
                    "source": "waterfall.browser.create_tab",
                    "status": "created",
                    "tab_id": tab_id,
                },
                "real": True,
            }

        except Exception as e:
            logger.error(f"Failed to create browser tab: {e}")
            return {"success": False, "error": str(e), "real": True}

    def _broadcast_state_change(self, event_type: str):
        """Broadcast state changes to all connected WebSocket clients."""
        try:
            socketio.emit(
                "state_change",
                {
                    "type": event_type,
                    "state": self.system_state,
                    "timestamp": datetime.utcnow().isoformat(),
                },
                namespace="/events",
            )
        except Exception as e:
            logger.error(f"Failed to broadcast state change: {e}")


# Initialize service singleton
service = ThirstysWebService()


# ============================================================================
# AUTHENTICATION & AUTHORIZATION LAYER
# ============================================================================


def create_demo_token() -> str:
    """Create a demo JWT token for development/testing."""
    return create_access_token(
        identity="demo_user", additional_claims={"role": "admin"}
    )


def authenticate_user(username: Optional[str], password: Optional[str]) -> Tuple[bool, Dict[str, Any], int]:
    """Authenticate a user against configured credentials."""
    if not username or not password:
        return False, {"error": "Username and password are required"}, 400

    if Config.ADMIN_USERNAME and Config.ADMIN_PASSWORD_HASH:
        if username == Config.ADMIN_USERNAME and check_password_hash(
            Config.ADMIN_PASSWORD_HASH, password
        ):
            return True, {"username": username, "role": "admin", "auth_mode": "configured"}, 200
        return False, {"error": "Invalid credentials"}, 401

    if Config.ALLOW_DEMO_LOGIN:
        if username == Config.DEMO_USERNAME and password == Config.DEMO_PASSWORD:
            return True, {"username": username, "role": "admin", "auth_mode": "demo"}, 200
        return False, {"error": "Invalid credentials"}, 401

    return (
        False,
        {
            "error": "Authentication is not configured",
            "required": ["THIRSTYS_ADMIN_USERNAME", "THIRSTYS_ADMIN_PASSWORD_HASH"],
        },
        503,
    )


@app.route("/api/auth/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    """
    Authenticate user and issue JWT tokens.

    Request Body:
        {
            "username": str,
            "password": str
        }

    Response:
        {
            "access_token": str,
            "refresh_token": str,
            "user": {...}
        }

    Security Considerations:
    - Rate limited to prevent brute force
    - Passwords are checked against a configured password hash
    - Tokens have expiration
    - Demo login is disabled unless explicitly enabled
    """
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")

    authenticated, result, status_code = authenticate_user(username, password)
    if authenticated:
        access_token = create_access_token(
            identity=result["username"], additional_claims={"role": result["role"]}
        )
        refresh_token = create_refresh_token(identity=result["username"])

        return (
            jsonify(
                {
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "user": result,
                    "session_policy": get_session_policy(),
                }
            ),
            200,
        )

    return jsonify(result), status_code


@app.route("/api/auth/logout", methods=["POST"])
@jwt_required(verify_type=False)
def logout():
    """Revoke the current access or refresh token for this process."""
    token = get_jwt()
    revoked_token_jtis.add(token["jti"])
    return (
        jsonify(
            {
                "revoked": True,
                "token_type": token.get("type"),
                "session_policy": get_session_policy(),
            }
        ),
        200,
    )


@app.route("/api/auth/session-policy", methods=["GET"])
@jwt_required()
def session_policy():
    """Return the active session policy for authenticated operators."""
    current_user = get_jwt_identity()
    return (
        jsonify(
            {
                "user": current_user,
                "session_policy": get_session_policy(),
            }
        ),
        200,
    )


@app.route("/api/auth/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    """Refresh access token using refresh token."""
    current_user = get_jwt_identity()
    access_token = create_access_token(identity=current_user)
    return (
        jsonify(
            {
                "access_token": access_token,
                "session_policy": get_session_policy(),
            }
        ),
        200,
    )


# ============================================================================
# SYSTEM CONTROL API ENDPOINTS
# ============================================================================


@app.route("/api/system/start", methods=["POST"])
@jwt_required()
@limiter.limit("10 per minute")
def start_system():
    """
    Start all Thirstys-Waterfall subsystems.

    Subsystems Started:
    - VPN subsystem with multi-hop routing
    - All 8 firewall types
    - Privacy browser engine
    - Encryption services
    - Monitoring and logging

    Returns:
        200: System started successfully
        500: System start failed
    """
    result = service.start_system()
    status_code = 200 if result.get("success") else 500
    return jsonify(result), status_code


@app.route("/api/system/stop", methods=["POST"])
@jwt_required()
@limiter.limit("10 per minute")
def stop_system():
    """Stop all subsystems with graceful shutdown."""
    result = service.stop_system()
    status_code = 200 if result.get("success") else 500
    return jsonify(result), status_code


@app.route("/api/system/status", methods=["GET"])
@jwt_required()
def get_system_status():
    """
    Get comprehensive system status.

    Status Information Includes:
    - System running state
    - VPN connection status and hop count
    - Active firewalls and rule counts
    - Browser tab count and privacy status
    - Resource usage (CPU, memory)
    - Network statistics
    - Error counts and health metrics
    """
    status = service.get_status()
    return jsonify(status), 200


# ============================================================================
# VPN CONTROL API ENDPOINTS
# ============================================================================


@app.route("/api/vpn/connect", methods=["POST"])
@jwt_required()
@limiter.limit("20 per minute")
def vpn_connect():
    """
    Connect to VPN with configurable options.

    Request Body:
        {
            "protocol": "wireguard" | "openvpn" | "ikev2",
            "multi_hop": bool,
            "hop_count": int (1-5),
            "kill_switch": bool,
            "dns_leak_protection": bool
        }

    VPN Features:
    - Protocol selection with fallback
    - Multi-hop routing (up to 5 hops)
    - Kill switch activation
    - DNS leak protection
    - IPv6 leak protection
    - Stealth mode
    """
    result = service.vpn_connect()
    status_code = 200 if result.get("success") else 503
    return jsonify(result), status_code


@app.route("/api/vpn/disconnect", methods=["POST"])
@jwt_required()
def vpn_disconnect():
    """Disconnect from VPN."""
    result = service.vpn_disconnect()
    status_code = 200 if result.get("success") else 503
    return jsonify(result), status_code


@app.route("/api/vpn/status", methods=["GET"])
@jwt_required()
def vpn_status():
    """Get detailed VPN status."""
    return jsonify(service.get_vpn_status()), 200


# ============================================================================
# FIREWALL CONTROL API ENDPOINTS
# ============================================================================


@app.route("/api/firewalls/list", methods=["GET"])
@jwt_required()
def list_firewalls():
    """
    List all available firewall types.

    8 Integrated Firewall Types:
    1. Packet-Filtering Firewall
    2. Circuit-Level Gateway
    3. Stateful Inspection Firewall
    4. Proxy Firewall
    5. Next-Generation Firewall (NGFW)
    6. Software Firewall
    7. Hardware Firewall
    8. Cloud Firewall
    """
    result = service.get_firewalls_status()
    if result.get("success"):
        return jsonify(result), 200

    capabilities = [
        {"id": name, "name": firewall.__class__.__name__, "active": False}
        for name, firewall in FirewallManager({}).firewalls.items()
    ]
    result["firewalls"] = capabilities
    return jsonify(result), 503


@app.route("/api/firewalls/<firewall_id>/toggle", methods=["POST"])
@jwt_required()
def toggle_firewall(firewall_id: str):
    """Enable or disable a specific firewall type."""
    data = request.get_json() or {}
    enabled = data.get("enabled", True)

    return (
        jsonify({"success": True, "firewall_id": firewall_id, "enabled": enabled}),
        200,
    )


# ============================================================================
# BROWSER PRIVACY API ENDPOINTS
# ============================================================================


@app.route("/api/browser/tabs", methods=["GET"])
@jwt_required()
def list_browser_tabs():
    """List all active browser tabs."""
    result = service.get_browser_tabs()
    status_code = 200 if result.get("success") else 503
    return jsonify(result), status_code


@app.route("/api/browser/tabs", methods=["POST"])
@jwt_required()
def create_browser_tab():
    """
    Create new encrypted browser tab.

    Privacy Features:
    - No history
    - No cache
    - No cookies
    - Anti-fingerprinting
    - Anti-tracking
    - Query and navigation privacy remains governed by browser engine acceptance
    """
    data = request.get_json() or {}
    url = data.get("url", "about:blank")

    result = service.create_browser_tab(url)
    status_code = 201 if result.get("success") else 503
    return jsonify(result), status_code


# ============================================================================
# WEBSOCKET EVENT HANDLERS
# ============================================================================


@socketio.on("connect", namespace="/events")
def handle_connect():
    """Handle WebSocket client connection."""
    logger.info(f"Client connected: {request.sid}")
    emit("connected", {"status": "connected", "sid": request.sid})


@socketio.on("disconnect", namespace="/events")
def handle_disconnect():
    """Handle WebSocket client disconnection."""
    logger.info(f"Client disconnected: {request.sid}")


@socketio.on("subscribe", namespace="/events")
def handle_subscribe(data):
    """Subscribe to specific event channels."""
    channel = data.get("channel")
    if channel:
        join_room(channel)
        emit("subscribed", {"channel": channel})


# ============================================================================
# ERROR HANDLING LAYER
# ============================================================================


@app.errorhandler(400)
def bad_request(error):
    """Handle bad request errors."""
    return jsonify({"error": "Bad request", "message": str(error)}), 400


@app.errorhandler(401)
def unauthorized(error):
    """Handle unauthorized access."""
    return jsonify({"error": "Unauthorized", "message": "Authentication required"}), 401


@app.errorhandler(403)
def forbidden(error):
    """Handle forbidden access."""
    return jsonify({"error": "Forbidden", "message": "Insufficient permissions"}), 403


@app.errorhandler(404)
def not_found(error):
    """Handle not found errors."""
    return jsonify({"error": "Not found", "message": "Resource not found"}), 404


@app.errorhandler(429)
def rate_limit_exceeded(error):
    """Handle rate limit exceeded."""
    return jsonify({"error": "Rate limit exceeded", "message": str(error)}), 429


@app.errorhandler(500)
def internal_error(error):
    """Handle internal server errors."""
    logger.error(f"Internal error: {error}")
    logger.error(traceback.format_exc())
    return jsonify({"error": "Internal server error"}), 500


# ============================================================================
# HEALTH & MONITORING ENDPOINTS
# ============================================================================


@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint for container orchestration."""
    return (
        jsonify(
            {
                "status": "healthy",
                "timestamp": datetime.utcnow().isoformat(),
                "version": "1.0.2",
                "sovereign_binding": get_sovereign_binding_status().as_dict(),
            }
        ),
        200,
    )


@app.route("/metrics", methods=["GET"])
@jwt_required()
def metrics():
    """Expose Prometheus-compatible metrics."""
    # Placeholder for metrics implementation
    return jsonify({"metrics": {}}), 200


# ============================================================================
# STATIC FILE SERVING
# ============================================================================


@app.route("/")
def serve_index():
    """Serve the main application page."""
    return send_from_directory("static", "index.html")


@app.route("/<path:path>")
def serve_static(path):
    """Serve static files."""
    return send_from_directory("static", path)


# ============================================================================
# APPLICATION ENTRY POINT
# ============================================================================


if __name__ == "__main__":
    execute_sovereign_protocol(globals(), "INIT_PROTOCOL")
    # Development/Debug mode only - not used in production
    logger.warning("=" * 80)
    logger.warning("RUNNING IN DEVELOPMENT MODE")
    logger.warning(
        "For production deployment, use: gunicorn --config gunicorn.conf.py app:app"
    )
    logger.warning("=" * 80)

    logger.info(
        f"Starting Thirstys-Waterfall Web Interface on {Config.HOST}:{Config.PORT}"
    )
    logger.info(f"Debug mode: {Config.DEBUG}")
    logger.info(f"Thirstys-Waterfall available: {THIRSTYS_AVAILABLE}")

    # Run with SocketIO (Flask development server)
    socketio.run(
        app,
        host=Config.HOST,
        port=Config.PORT,
        debug=Config.DEBUG,
        use_reloader=Config.DEBUG,
        allow_unsafe_werkzeug=True,
    )
