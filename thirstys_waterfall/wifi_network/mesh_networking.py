"""
WiFi Mesh Networking Engine
Self-healing mesh networks for bandwidth pooling and extended coverage
"""

import logging
import heapq
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum


class MeshRole(Enum):
    """Role of node in mesh network"""

    ROOT = "root"  # Gateway node with internet access
    NODE = "node"  # Intermediate relay node
    LEAF = "leaf"  # End-point node


@dataclass
class MeshNode:
    """Mesh network node"""

    node_id: str
    mac_address: str
    role: MeshRole
    signal_strength_dbm: int
    hop_count: int  # Hops to root
    bandwidth_mbps: int
    connected_peers: List[str]
    is_gateway: bool
    uptime_seconds: int


class MeshNetworkEngine:
    """
    WiFi Mesh Networking Engine

    Features:
    - Self-healing mesh topology
    - Automatic route optimization
    - Load balancing across mesh nodes
    - Bandwidth pooling for marketplace
    - Multi-hop routing
    - Seamless roaming between nodes

    Compatible with:
    - IEEE 802.11s (WiFi mesh standard)
    - Batman-adv (Better Approach To Mobile Ad-hoc Networking)
    - Custom mesh protocols
    """

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        mesh_backend: Optional[Any] = None,
    ):
        self.config = config or {}
        self.logger = logging.getLogger(self.__class__.__name__)
        self.mesh_backend = mesh_backend or self.config.get("mesh_backend")

        # Mesh configuration
        self.mesh_id = self.config.get("mesh_id", "ThirstysMesh")
        self.mesh_password = self.config.get("mesh_password")  # Optional encryption
        self.enable_encryption = self.config.get("encryption", True)

        # Mesh topology
        self.nodes: Dict[str, MeshNode] = {}
        self.my_node_id: Optional[str] = None
        self.root_node_id: Optional[str] = None

        # Routing table
        self.routing_table: Dict[str, List[str]] = {}  # destination -> path

        # Bandwidth pooling for marketplace
        self.enable_bandwidth_pooling = self.config.get("bandwidth_pooling", False)
        self.total_pool_bandwidth_mbps = 0
        self.last_operation_results: Dict[str, Dict[str, Any]] = {}

    def create_mesh(self, role: MeshRole = MeshRole.NODE) -> bool:
        """
        Create or join mesh network

        Args:
            role: Role of this node in mesh

        Returns:
            True if mesh created/joined successfully
        """
        try:
            self.logger.info(f"Creating mesh network '{self.mesh_id}' as {role.value}")

            # Generate unique node ID
            self.my_node_id = self._generate_node_id()

            # Configure mesh on WiFi adapter
            success = self._configure_mesh_interface(role)

            if success:
                self.logger.info("Mesh network active")

                # Start topology discovery
                self._discover_mesh_peers()

                # Start routing protocol
                self._update_routing_table()

            return success

        except Exception as e:
            self.logger.error(f"Mesh creation failed: {e}")
            return False

    def _generate_node_id(self) -> str:
        """Generate unique node ID"""
        import uuid

        return str(uuid.uuid4())[:8]

    def _configure_mesh_interface(self, role: MeshRole) -> bool:
        """Configure WiFi adapter for mesh mode"""
        try:
            configurator = getattr(self.mesh_backend, "configure_mesh_interface", None)
            if not callable(configurator):
                self._record_operation(
                    "configure_mesh_interface",
                    {
                        "status": "unavailable",
                        "configured": False,
                        "role": role.value,
                        "backend": self._backend_name(),
                        "error": (
                            "No mesh backend is configured for mesh interface "
                            "creation"
                        ),
                    },
                )
                return False

            result = configurator(
                mesh_id=self.mesh_id,
                role=role,
                encryption_enabled=self.enable_encryption,
                mesh_password=self.mesh_password,
                node_id=self.my_node_id,
            )
            normalized = self._normalize_bool_or_dict_result(
                result, "configured", "configure_mesh_interface"
            )
            normalized.setdefault("status", "configured")
            normalized["role"] = role.value
            normalized["backend"] = self._backend_name()
            self._record_operation("configure_mesh_interface", normalized)

            if not normalized["configured"]:
                return False

            if normalized.get("node_id"):
                self.my_node_id = str(normalized["node_id"])

            self.logger.info(f"Mesh interface configured with role: {role.value}")
            return True

        except Exception as e:
            self.logger.error(f"Mesh interface configuration failed: {e}")
            self._record_operation(
                "configure_mesh_interface",
                {"status": "error", "configured": False, "error": str(e)},
            )
            return False

    def _discover_mesh_peers(self) -> None:
        """Discover peer nodes in mesh network"""
        try:
            self.logger.info("Discovering mesh peers...")
            discoverer = getattr(self.mesh_backend, "discover_mesh_peers", None)
            if not callable(discoverer):
                self._record_operation(
                    "discover_mesh_peers",
                    {
                        "status": "unavailable",
                        "peer_count": None,
                        "backend": self._backend_name(),
                        "error": "No mesh backend is configured for peer discovery",
                    },
                )
                return

            peers = discoverer(mesh_id=self.mesh_id, node_id=self.my_node_id)
            if not isinstance(peers, list) or not all(
                isinstance(peer, MeshNode) for peer in peers
            ):
                raise TypeError(
                    "Mesh backend discover_mesh_peers must return a list of MeshNode"
                )

            for peer in peers:
                self.add_node(peer)

            self._record_operation(
                "discover_mesh_peers",
                {
                    "status": "discovered",
                    "peer_count": len(peers),
                    "backend": self._backend_name(),
                },
            )

        except Exception as e:
            self.logger.error(f"Peer discovery failed: {e}")
            self._record_operation(
                "discover_mesh_peers",
                {"status": "error", "peer_count": None, "error": str(e)},
            )

    def _update_routing_table(self) -> None:
        """Update mesh routing table using HWMP (Hybrid Wireless Mesh Protocol)"""
        try:
            # HWMP is the default routing protocol for 802.11s
            # Combines proactive (tree-based) and reactive (on-demand) routing

            # For each known node, calculate best path
            for node_id in self.nodes:
                path = self._calculate_best_path(node_id)
                if path:
                    self.routing_table[node_id] = path

            self.logger.debug(
                f"Routing table updated: {len(self.routing_table)} routes"
            )

        except Exception as e:
            self.logger.error(f"Routing table update failed: {e}")

    def _calculate_best_path(self, destination: str) -> Optional[List[str]]:
        """
        Calculate best path to destination using airtime metric

        Args:
            destination: Destination node ID

        Returns:
            List of node IDs representing path
        """
        start = self.my_node_id
        if not start or destination not in self.nodes:
            return None
        if destination == start:
            return [start]

        adjacency = self._build_adjacency()
        queue = [(0.0, start, [start])]
        visited = set()

        while queue:
            cost, node_id, path = heapq.heappop(queue)
            if node_id in visited:
                continue
            visited.add(node_id)

            if node_id == destination:
                return path

            for peer_id in adjacency.get(node_id, []):
                if peer_id in visited:
                    continue
                peer = self.nodes.get(peer_id)
                if peer is None:
                    continue
                heapq.heappush(
                    queue,
                    (
                        cost + self._airtime_cost(peer),
                        peer_id,
                        path + [peer_id],
                    ),
                )

        return None

    def add_node(self, node: MeshNode) -> None:
        """Add discovered node to mesh topology"""
        self.nodes[node.node_id] = node
        self.logger.info(f"Added mesh node: {node.node_id} (role: {node.role.value})")

        # Update total pool bandwidth
        if self.enable_bandwidth_pooling:
            self.total_pool_bandwidth_mbps += node.bandwidth_mbps

    def remove_node(self, node_id: str) -> None:
        """Remove node from mesh (node left or failed)"""
        if node_id in self.nodes:
            node = self.nodes[node_id]

            # Update pool bandwidth
            if self.enable_bandwidth_pooling:
                self.total_pool_bandwidth_mbps -= node.bandwidth_mbps

            del self.nodes[node_id]
            self.logger.info(f"Removed mesh node: {node_id}")

            # Trigger routing table update (self-healing)
            self._update_routing_table()

    def get_mesh_status(self) -> Dict[str, Any]:
        """Get mesh network status"""
        return {
            "mesh_id": self.mesh_id,
            "my_node_id": self.my_node_id,
            "node_count": len(self.nodes),
            "nodes": [node.__dict__ for node in self.nodes.values()],
            "routing_table_size": len(self.routing_table),
            "bandwidth_pooling_enabled": self.enable_bandwidth_pooling,
            "total_pool_bandwidth_mbps": self.total_pool_bandwidth_mbps,
            "backend_configured": self.mesh_backend is not None,
            "backend": self._backend_name(),
            "last_operation_results": dict(self.last_operation_results),
        }

    def optimize_mesh_topology(self) -> bool:
        """
        Optimize mesh topology for performance
        - Rebalance traffic across nodes
        - Identify bottlenecks
        - Suggest node repositioning
        """
        try:
            # Analyze current topology
            bottlenecks = self._identify_bottlenecks()

            if bottlenecks:
                self.logger.warning(f"Identified {len(bottlenecks)} bottleneck nodes")

                # Attempt automatic rebalancing
                self._rebalance_traffic()

            self._record_operation(
                "optimize_mesh_topology",
                {"status": "optimized", "bottlenecks": bottlenecks},
            )
            return True

        except Exception as e:
            self.logger.error(f"Mesh optimization failed: {e}")
            return False

    def _identify_bottlenecks(self) -> List[str]:
        """Identify nodes with high traffic load"""
        bottlenecks = []
        for node_id, node in self.nodes.items():
            has_many_peers = len(node.connected_peers) >= 4
            has_low_bandwidth = node.bandwidth_mbps < 50
            has_weak_signal = node.signal_strength_dbm < -75
            if has_many_peers or has_low_bandwidth or has_weak_signal:
                bottlenecks.append(node_id)
        return bottlenecks

    def _rebalance_traffic(self) -> None:
        """Rebalance traffic across mesh to avoid congestion"""
        rebalancer = getattr(self.mesh_backend, "rebalance_traffic", None)
        if callable(rebalancer):
            result = rebalancer(
                nodes=dict(self.nodes), routing_table=dict(self.routing_table)
            )
            normalized = self._normalize_bool_or_dict_result(
                result, "rebalanced", "rebalance_traffic"
            )
            normalized.setdefault("status", "rebalanced")
            normalized["backend"] = self._backend_name()
            self._record_operation("rebalance_traffic", normalized)
            return

        self._update_routing_table()
        self._record_operation(
            "rebalance_traffic",
            {
                "status": "local_routes_recomputed",
                "rebalanced": False,
                "backend": self._backend_name(),
                "route_count": len(self.routing_table),
            },
        )

    def enable_marketplace_pooling(self) -> None:
        """Enable bandwidth pooling for marketplace"""
        self.enable_bandwidth_pooling = True

        # Recalculate total pool bandwidth
        self.total_pool_bandwidth_mbps = sum(
            node.bandwidth_mbps for node in self.nodes.values()
        )

        self.logger.info(
            f"Marketplace pooling enabled: {self.total_pool_bandwidth_mbps} Mbps total"
        )

    def _build_adjacency(self) -> Dict[str, List[str]]:
        adjacency: Dict[str, List[str]] = {}

        if self.my_node_id:
            adjacency.setdefault(self.my_node_id, [])

        for node_id, node in self.nodes.items():
            adjacency.setdefault(node_id, [])
            if self.my_node_id and node.hop_count <= 1:
                adjacency[self.my_node_id].append(node_id)
                adjacency[node_id].append(self.my_node_id)

            for peer_id in node.connected_peers:
                if peer_id in self.nodes:
                    adjacency[node_id].append(peer_id)
                    adjacency.setdefault(peer_id, []).append(node_id)

        return adjacency

    def _airtime_cost(self, node: MeshNode) -> float:
        bandwidth = max(node.bandwidth_mbps, 1)
        signal_penalty = max(0, -70 - node.signal_strength_dbm) / 100
        hop_penalty = max(node.hop_count, 0) * 0.1
        return (1 / bandwidth) + signal_penalty + hop_penalty

    def _normalize_bool_or_dict_result(
        self, result: Any, bool_field: str, operation: str
    ) -> Dict[str, Any]:
        if isinstance(result, bool):
            return {bool_field: result}

        if not isinstance(result, dict):
            raise TypeError(f"Mesh backend {operation} must return bool or dict")

        if bool_field not in result or not isinstance(result[bool_field], bool):
            raise ValueError(
                f"Mesh backend {operation} result must include "
                f"boolean {bool_field!r}"
            )

        return dict(result)

    def _record_operation(self, operation: str, result: Dict[str, Any]) -> None:
        self.last_operation_results[operation] = result

    def _backend_name(self) -> Optional[str]:
        if self.mesh_backend is None:
            return None
        return self.mesh_backend.__class__.__name__
