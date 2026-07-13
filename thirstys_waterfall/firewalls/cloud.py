"""Cloud Firewall implementation"""

from typing import Any, Dict, List, Optional
from .base import FirewallBase


class CloudFirewall(FirewallBase):
    """
    Cloud Firewall
    Distributed firewall across cloud infrastructure
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.distributed = config.get("distributed", True)
        self.cloud_backend = config.get("cloud_backend")
        self._cloud_nodes: List[Any] = []
        self._geo_rules: Dict[str, Dict[str, Any]] = {}
        self._backend_status: Dict[str, Any] = {
            "status": "unavailable",
            "error": "Cloud firewall backend is not configured",
            "backend_configured": False,
        }
        self._last_backend_result: Optional[Dict[str, Any]] = None

    def start(self):
        """Start cloud firewall"""
        self.logger.info("Starting Cloud Firewall")
        self._active = True
        self._initialize_cloud_nodes()

    def stop(self):
        """Stop cloud firewall"""
        self.logger.info("Stopping Cloud Firewall")
        self._active = False

    def _initialize_cloud_nodes(self):
        """Initialize distributed cloud nodes"""
        if self.cloud_backend is None:
            self._cloud_nodes = []
            self._backend_status = {
                "status": "unavailable",
                "error": "Cloud firewall backend is not configured",
                "backend_configured": False,
            }
            self.logger.warning("Cloud firewall backend is not configured")
            return

        initialize = getattr(self.cloud_backend, "initialize_nodes", None)
        if not callable(initialize):
            raise RuntimeError(
                "Cloud firewall backend does not implement initialize_nodes"
            )

        nodes = initialize()
        if not isinstance(nodes, list):
            raise RuntimeError("Cloud firewall backend returned invalid nodes")

        self._cloud_nodes = nodes
        self._backend_status = {
            "status": "ready",
            "backend": type(self.cloud_backend).__name__,
            "backend_configured": True,
            "node_count": len(nodes),
        }

    def add_rule(self, rule: Dict[str, Any]):
        """Add cloud firewall rule"""
        self._rules.append(rule)

        # Geo-based rules
        if "region" in rule:
            self._geo_rules[rule["region"]] = rule
        if self.cloud_backend is not None:
            add_rule = getattr(self.cloud_backend, "add_rule", None)
            if callable(add_rule):
                add_rule(rule)

    def remove_rule(self, rule_id: str):
        """Remove cloud firewall rule"""
        self._rules = [r for r in self._rules if r.get("id") != rule_id]
        self._geo_rules = {
            region: rule
            for region, rule in self._geo_rules.items()
            if rule.get("id") != rule_id
        }
        if self.cloud_backend is not None:
            remove_rule = getattr(self.cloud_backend, "remove_rule", None)
            if callable(remove_rule):
                remove_rule(rule_id)

    def process_packet(self, packet: Dict[str, Any]) -> bool:
        """Process packet through cloud firewall"""
        if not self._active:
            return True

        result = self._evaluate_cloud_packet(packet)
        if not result.get("allowed", False):
            self._update_statistics(False, threat=bool(result.get("threat")))
            return False

        # Geo-IP filtering
        if not self._check_geo_location(packet):
            self._update_statistics(False)
            return False

        self._update_statistics(True)
        return True

    def _check_geo_location(self, packet: Dict[str, Any]) -> bool:
        """Check geographic location restrictions"""
        packet.get("src_ip", "")
        geo_info = packet.get("geo_info", {})
        region = geo_info.get("region", "unknown")

        # Check region-specific rules
        if region in self._geo_rules:
            rule = self._geo_rules[region]
            return rule.get("action") == "allow"

        return True

    def _evaluate_cloud_packet(self, packet: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate packet through a configured cloud firewall backend."""
        if self.cloud_backend is None:
            result = {
                "status": "unavailable",
                "error": "Cloud firewall backend is not configured",
                "allowed": False,
                "backend_configured": False,
            }
            self._last_backend_result = result
            self.logger.error(result["error"])
            return result

        evaluate = getattr(self.cloud_backend, "evaluate_packet", None)
        if not callable(evaluate):
            raise RuntimeError(
                "Cloud firewall backend does not implement evaluate_packet"
            )

        result = evaluate(packet)
        if isinstance(result, bool):
            result = {"allowed": result}
        if not isinstance(result, dict) or "allowed" not in result:
            raise RuntimeError("Cloud firewall backend returned invalid result")

        result.setdefault("status", "verified")
        result.setdefault("backend", type(self.cloud_backend).__name__)
        result.setdefault("backend_configured", True)
        self._last_backend_result = result
        return result

    def get_cloud_status(self) -> Dict[str, Any]:
        """Get cloud firewall status"""
        status = {
            "distributed": self.distributed,
            "nodes": self._cloud_nodes,
            "active": self._active,
            "last_backend_result": self._last_backend_result,
        }
        status.update(self._backend_status)
        return status

    def add_geo_rule(self, region: str, action: str):
        """Add geographic-based rule"""
        self.add_rule({"id": f"geo_{region}", "region": region, "action": action})
