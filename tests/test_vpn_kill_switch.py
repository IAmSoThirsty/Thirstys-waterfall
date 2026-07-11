"""Tests for VPN kill switch traffic blocker evidence."""

import unittest

from thirstys_waterfall.vpn import KillSwitch


class FakeVPNTrafficBlocker:
    def __init__(self):
        self.block_calls = 0
        self.restore_calls = 0

    def block_all_traffic(self):
        self.block_calls += 1
        return {"status": "blocked", "policy": "vpn_deny_all"}

    def restore_traffic(self):
        self.restore_calls += 1
        return {"status": "restored", "policy": "vpn_restore"}


class InvalidBlocker:
    def block_all_traffic(self):
        return "not-a-dict"

    def restore_traffic(self):
        return "not-a-dict"


class TestVPNKillSwitch(unittest.TestCase):
    def test_trigger_without_backend_records_unavailable_not_blocked(self):
        kill_switch = KillSwitch()
        kill_switch.enable()

        kill_switch.trigger("vpn disconnected")

        status = kill_switch.get_traffic_block_status()
        self.assertEqual(status["status"], "unavailable")
        self.assertEqual(
            status["error"],
            "VPN traffic blocker backend is not configured",
        )
        self.assertFalse(status["traffic_blocked"])
        self.assertFalse(status["backend_configured"])

    def test_trigger_delegates_to_backend_and_notifies_callback(self):
        blocker = FakeVPNTrafficBlocker()
        reasons = []
        kill_switch = KillSwitch(traffic_blocker=blocker)
        kill_switch.register_callback(reasons.append)
        kill_switch.enable()

        kill_switch.trigger("vpn disconnected")

        status = kill_switch.get_traffic_block_status()
        self.assertEqual(blocker.block_calls, 1)
        self.assertEqual(reasons, ["vpn disconnected"])
        self.assertEqual(status["status"], "blocked")
        self.assertTrue(status["traffic_blocked"])
        self.assertEqual(status["backend"], "FakeVPNTrafficBlocker")

    def test_restore_delegates_to_backend(self):
        blocker = FakeVPNTrafficBlocker()
        kill_switch = KillSwitch(traffic_blocker=blocker)
        kill_switch.enable()
        kill_switch.trigger("vpn disconnected")

        result = kill_switch.restore_traffic()

        self.assertEqual(blocker.restore_calls, 1)
        self.assertEqual(result["status"], "restored")
        self.assertTrue(result["traffic_restored"])
        self.assertEqual(
            kill_switch.get_traffic_restore_status()["backend"],
            "FakeVPNTrafficBlocker",
        )

    def test_invalid_backend_results_fail_loudly(self):
        kill_switch = KillSwitch(traffic_blocker=InvalidBlocker())
        kill_switch.enable()

        with self.assertRaisesRegex(RuntimeError, "returned invalid result"):
            kill_switch.trigger("vpn disconnected")

    def test_invalid_restore_result_fails_loudly(self):
        kill_switch = KillSwitch(traffic_blocker=InvalidBlocker())
        kill_switch.enable()

        with self.assertRaisesRegex(RuntimeError, "returned invalid restore result"):
            kill_switch.restore_traffic()


if __name__ == "__main__":
    unittest.main()
