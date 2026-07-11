"""Tests for advanced stealth backend evidence gates."""

import unittest

from thirstys_waterfall.network import AdvancedStealthManager


class FakeStealthTransportBackend:
    def __init__(self):
        self.connections = []

    def connect_transport(self, **kwargs):
        self.connections.append(kwargs)
        return {
            "status": "connected",
            "connected": True,
            "transport": kwargs["transport_type"],
        }


class FakeNodeProvider:
    def get_onion_nodes(self):
        return [
            {"id": "entry-1", "type": "entry", "bandwidth": 100},
            {"id": "middle-1", "type": "middle", "bandwidth": 100},
            {"id": "middle-2", "type": "middle", "bandwidth": 90},
            {"id": "exit-1", "type": "exit", "bandwidth": 100},
        ]


class FakeFrontingBackend:
    def __init__(self):
        self.fronts = []

    def setup_front(self, **kwargs):
        self.fronts.append(kwargs)
        return {
            "status": "fronted",
            "fronted": True,
            "front_domain": "front.example.invalid",
            "provider": "test-cdn",
        }


class TestAdvancedStealthEvidenceGates(unittest.TestCase):
    def test_start_without_backends_reports_unavailable_not_active(self):
        manager = AdvancedStealthManager(
            {
                "obfuscation": {"timing_randomization": False},
            }
        )

        manager.start()

        status = manager.get_status()
        self.assertFalse(manager.is_active())
        self.assertEqual(status["backend_evidence"]["status"], "unavailable")
        self.assertEqual(status["backend_evidence"]["active_transports"], 0)
        self.assertFalse(status["transport_backend_configured"])
        self.assertFalse(status["node_provider_configured"])
        self.assertEqual(status["circuits"]["available_nodes"], 0)

        request = {"domain": "target.example", "data": b"payload"}
        self.assertEqual(manager.route_request(request), request)

    def test_start_uses_configured_transport_and_node_backends(self):
        transport_backend = FakeStealthTransportBackend()
        node_provider = FakeNodeProvider()
        manager = AdvancedStealthManager(
            {
                "transport_backend": transport_backend,
                "node_provider": node_provider,
                "obfuscation": {"timing_randomization": False},
                "domain_fronting": {"domain_fronting_enabled": False},
            }
        )

        manager.start()

        status = manager.get_status()
        self.assertTrue(manager.is_active())
        self.assertEqual(status["backend_evidence"]["status"], "active")
        self.assertGreater(status["backend_evidence"]["active_transports"], 0)
        self.assertGreater(status["backend_evidence"]["active_circuits"], 0)
        self.assertTrue(status["transport_backend_configured"])
        self.assertTrue(status["node_provider_configured"])
        self.assertGreater(len(transport_backend.connections), 0)

    def test_route_request_requires_active_backend_evidence(self):
        transport_backend = FakeStealthTransportBackend()
        manager = AdvancedStealthManager(
            {
                "transport_backend": transport_backend,
                "node_provider": FakeNodeProvider(),
                "fronting_backend": FakeFrontingBackend(),
                "obfuscation": {"timing_randomization": False},
            }
        )
        manager.start()

        result = manager.route_request(
            {
                "domain": "target.example",
                "data": b"payload",
            }
        )

        self.assertTrue(result["domain_fronting"])
        self.assertEqual(result["sni_domain"], "front.example.invalid")
        self.assertTrue(result["transport_encrypted"])
        self.assertIn("transport", result)
        self.assertIn("circuit_id", result)
        self.assertIsInstance(result["data"], bytes)

    def test_invalid_node_provider_fails_loudly(self):
        class InvalidNodeProvider:
            def get_onion_nodes(self):
                return [{"id": "entry-1", "type": "entry"}]

        with self.assertRaisesRegex(RuntimeError, "incomplete node"):
            AdvancedStealthManager({"node_provider": InvalidNodeProvider()})


if __name__ == "__main__":
    unittest.main()
