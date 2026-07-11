from thirstys_waterfall.wifi_network.mesh_networking import (
    MeshNetworkEngine,
    MeshNode,
    MeshRole,
)


def mesh_node(
    node_id,
    peers=None,
    signal=-45,
    hops=1,
    bandwidth=100,
    role=MeshRole.NODE,
):
    return MeshNode(
        node_id=node_id,
        mac_address=f"00:11:22:33:44:{node_id[-1] * 2}",
        role=role,
        signal_strength_dbm=signal,
        hop_count=hops,
        bandwidth_mbps=bandwidth,
        connected_peers=peers or [],
        is_gateway=role == MeshRole.ROOT,
        uptime_seconds=100,
    )


class MeshBackend:
    def configure_mesh_interface(
        self,
        mesh_id,
        role,
        encryption_enabled,
        mesh_password,
        node_id,
    ):
        return {
            "configured": True,
            "node_id": "local",
            "interface": "mesh0",
            "mesh_id": mesh_id,
            "encryption_enabled": encryption_enabled,
        }

    def discover_mesh_peers(self, mesh_id, node_id):
        return [
            mesh_node("node-a", peers=["node-b"], bandwidth=200),
            mesh_node("node-b", peers=["node-a", "node-c"], hops=2),
            mesh_node("node-c", peers=["node-b"], hops=3, bandwidth=80),
        ]

    def rebalance_traffic(self, nodes, routing_table):
        return {"rebalanced": True, "route_count": len(routing_table)}


def test_create_mesh_without_backend_fails_closed():
    engine = MeshNetworkEngine()

    assert engine.create_mesh() is False

    status = engine.get_mesh_status()
    check = status["last_operation_results"]["configure_mesh_interface"]
    assert check["status"] == "unavailable"
    assert check["configured"] is False
    assert status["backend_configured"] is False


def test_create_mesh_with_backend_records_evidence_and_peers():
    engine = MeshNetworkEngine(mesh_backend=MeshBackend())

    assert engine.create_mesh(MeshRole.ROOT) is True

    status = engine.get_mesh_status()
    assert status["my_node_id"] == "local"
    assert status["node_count"] == 3
    assert status["backend"] == "MeshBackend"
    assert (
        status["last_operation_results"]["configure_mesh_interface"]["interface"]
        == "mesh0"
    )
    assert status["last_operation_results"]["discover_mesh_peers"]["peer_count"] == 3
    assert status["routing_table_size"] == 3


def test_best_path_uses_known_mesh_topology():
    engine = MeshNetworkEngine()
    engine.my_node_id = "local"
    engine.add_node(mesh_node("node-a", peers=["node-b"], bandwidth=200))
    engine.add_node(mesh_node("node-b", peers=["node-a", "node-c"], hops=2))
    engine.add_node(mesh_node("node-c", peers=["node-b"], hops=3))

    assert engine._calculate_best_path("node-c") == [
        "local",
        "node-a",
        "node-b",
        "node-c",
    ]


def test_bottleneck_detection_and_rebalance_records_local_evidence():
    engine = MeshNetworkEngine()
    engine.my_node_id = "local"
    engine.add_node(
        mesh_node(
            "node-a",
            peers=["node-b", "node-c", "node-d", "node-e"],
            bandwidth=25,
            signal=-82,
        )
    )
    engine.add_node(mesh_node("node-b", peers=["node-a"]))

    assert engine.optimize_mesh_topology() is True

    status = engine.get_mesh_status()
    assert status["last_operation_results"]["optimize_mesh_topology"][
        "bottlenecks"
    ] == ["node-a"]
    assert (
        status["last_operation_results"]["rebalance_traffic"]["status"]
        == "local_routes_recomputed"
    )


def test_backend_rebalance_records_backend_evidence():
    engine = MeshNetworkEngine(mesh_backend=MeshBackend())
    engine.my_node_id = "local"
    engine.add_node(mesh_node("node-a", peers=["node-b"], bandwidth=25))
    engine.add_node(mesh_node("node-b", peers=["node-a"]))

    assert engine.optimize_mesh_topology() is True

    check = engine.get_mesh_status()["last_operation_results"]["rebalance_traffic"]
    assert check["status"] == "rebalanced"
    assert check["rebalanced"] is True
    assert check["backend"] == "MeshBackend"
