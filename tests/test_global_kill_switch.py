"""Tests for global kill switch traffic blocker evidence."""

import unittest

from thirstys_waterfall.kill_switch import GlobalKillSwitch


class FakeTrafficBlocker:
    def __init__(self):
        self.calls = 0

    def block_all_traffic(self):
        self.calls += 1
        return {"status": "blocked", "policy": "deny_all"}


class InvalidTrafficBlocker:
    def block_all_traffic(self):
        return "not-a-dict"


class FakeComponent:
    def __init__(self):
        self.stopped = False

    def stop(self):
        self.stopped = True


class TestGlobalKillSwitch(unittest.TestCase):
    def test_initial_block_status_reports_not_attempted(self):
        kill_switch = GlobalKillSwitch()

        status = kill_switch.get_traffic_block_status()

        self.assertEqual(status["status"], "not_attempted")
        self.assertFalse(status["traffic_blocked"])
        self.assertFalse(status["backend_configured"])

    def test_trigger_without_backend_records_unavailable_not_blocked(self):
        kill_switch = GlobalKillSwitch()
        kill_switch.enable()

        kill_switch.trigger("vpn lost", "vpn")

        status = kill_switch.get_traffic_block_status()
        self.assertTrue(kill_switch.is_triggered())
        self.assertEqual(status["status"], "unavailable")
        self.assertEqual(
            status["error"],
            "Global traffic blocker backend is not configured",
        )
        self.assertFalse(status["traffic_blocked"])

    def test_trigger_delegates_to_traffic_blocker_backend(self):
        blocker = FakeTrafficBlocker()
        browser = FakeComponent()
        kill_switch = GlobalKillSwitch(traffic_blocker=blocker)
        kill_switch.register_browser_kill_switch(browser)
        kill_switch.enable()

        kill_switch.trigger("firewall failed", "firewall")

        status = kill_switch.get_traffic_block_status()
        self.assertTrue(kill_switch.is_triggered())
        self.assertEqual(blocker.calls, 1)
        self.assertTrue(browser.stopped)
        self.assertEqual(status["status"], "blocked")
        self.assertTrue(status["traffic_blocked"])
        self.assertEqual(status["backend"], "FakeTrafficBlocker")

    def test_traffic_blocker_result_must_be_mapping(self):
        kill_switch = GlobalKillSwitch(traffic_blocker=InvalidTrafficBlocker())
        kill_switch.enable()

        with self.assertRaisesRegex(RuntimeError, "returned invalid result"):
            kill_switch.trigger("vpn lost", "vpn")


if __name__ == "__main__":
    unittest.main()
