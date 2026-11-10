import asyncio
import os
import tempfile
import unittest
from unittest.mock import MagicMock

from starlette.testclient import TestClient

from controller.api.app import create_app
from controller.api.sse_broker import SSEBroadcaster
from controller.core.db import DefenseDatabase
from controller.core.detector import IntrusionDetector
from controller.mitigation.allowlist import AllowlistManager
from controller.mitigation.firewall import FirewallController
from controller.mitigation.quarantine import QuarantineManager


class TestSSEBroadcaster(unittest.IsolatedAsyncioTestCase):
    async def test_subscribe_broadcast_unsubscribe(self) -> None:
        broker = SSEBroadcaster()
        queue = await broker.subscribe()

        await broker.broadcast("test_alert", {"msg": "hello soc"})
        frame = await asyncio.wait_for(queue.get(), timeout=1.0)
        self.assertIn("event: test_alert", frame)
        self.assertIn('"msg": "hello soc"', frame)

        await broker.unsubscribe(queue)
        self.assertEqual(len(broker._subscribers), 0)


class TestAPIRoutes(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "api_test.db")
        self.db = DefenseDatabase(db_path=self.db_path)
        self.allowlist = AllowlistManager()
        self.firewall = FirewallController(allowlist_manager=self.allowlist, dry_run=True)
        self.detector = IntrusionDetector(
            firewall=self.firewall,
            db=self.db,
            allowlist=self.allowlist,
        )

        self.mock_quarantine = MagicMock(spec=QuarantineManager)
        self.mock_quarantine.get_container_network_status.return_value = "production"
        self.mock_quarantine.quarantine_container.return_value = {
            "status": "success",
            "current_state": "quarantined",
            "message": "isolated"
        }
        self.mock_quarantine.restore_container.return_value = {
            "status": "success",
            "current_state": "production",
            "message": "restored"
        }

        self.broadcaster = SSEBroadcaster()

        self.app = create_app(
            detector=self.detector,
            quarantine_manager=self.mock_quarantine,
            broadcaster=self.broadcaster,
            enable_tailer=False,
        )
        self.client = TestClient(self.app)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_health_check(self) -> None:
        res = self.client.get("/api/health")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["data"]["service"], "defense_controller")

    def test_defense_status(self) -> None:
        # Ban an IP first
        self.firewall.ban_ip("198.51.100.33")
        res = self.client.get("/api/defense/status")
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertEqual(body["status"], "success")
        self.assertIn("198.51.100.33", body["data"]["banned_ips"])
        self.assertEqual(body["data"]["banned_count"], 1)

    def test_manual_unban_endpoint(self) -> None:
        test_ip = "198.51.100.44"
        self.firewall.ban_ip(test_ip)
        self.assertTrue(self.firewall.is_ip_banned(test_ip))

        res = self.client.post("/api/defense/unban", json={"ip": test_ip, "admin_user": "tester"})
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertEqual(body["status"], "success")
        self.assertFalse(self.firewall.is_ip_banned(test_ip))

    def test_reset_bans_endpoint(self) -> None:
        self.firewall.ban_ip("198.51.100.55")
        res = self.client.post("/api/defense/reset-bans")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(len(self.firewall.list_banned_ips()), 0)

    def test_simulate_infection_and_restore(self) -> None:
        infect_res = self.client.post("/api/simulate/infect/iot_sensor_node")
        self.assertEqual(infect_res.status_code, 200)
        self.mock_quarantine.quarantine_container.assert_called_with("iot_sensor_node")

        restore_res = self.client.post("/api/simulate/restore/iot_sensor_node")
        self.assertEqual(restore_res.status_code, 200)
        self.mock_quarantine.restore_container.assert_called_with("iot_sensor_node")

    def test_sse_stream_headers_and_initial_handshake(self) -> None:
        with self.client.stream("GET", "/api/stream") as stream:
            self.assertIn("text/event-stream", stream.headers["content-type"])
            self.assertEqual(stream.headers["cache-control"], "no-cache")
            self.assertEqual(stream.headers["connection"], "keep-alive")
            self.assertEqual(stream.headers["x-accel-buffering"], "no")

            # Read first chunk
            first_line = next(stream.iter_lines())
            self.assertIn("event: connected", first_line)

    def test_simulate_bruteforce_attack(self) -> None:
        res = self.client.post("/api/simulate/attack/brute-force")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["data"]["target_ip"], "198.51.100.99")
        self.assertTrue(self.firewall.is_ip_banned("198.51.100.99"))

    def test_simulate_exploit_attack(self) -> None:
        res = self.client.post("/api/simulate/attack/exploit")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["data"]["target_ip"], "203.0.113.88")
        self.assertTrue(self.firewall.is_ip_banned("203.0.113.88"))

    def test_simulate_portsweep_attack(self) -> None:
        res = self.client.post("/api/simulate/attack/port-sweep")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["data"]["target_ip"], "198.51.100.77")
        self.assertTrue(self.firewall.is_ip_banned("198.51.100.77"))

    def test_defense_analytics_endpoint(self) -> None:
        # Trigger an attack first to populate stats
        self.client.post("/api/simulate/attack/brute-force")
        res = self.client.get("/api/defense/analytics")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "success")
        self.assertGreaterEqual(data["data"]["total_threat_events"], 5)
        self.assertIn("attack_breakdown", data["data"])

    def test_ip_forensics_endpoint(self) -> None:
        self.client.post("/api/simulate/attack/exploit")
        res = self.client.get("/api/defense/forensics/203.0.113.88")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["data"]["src_ip"], "203.0.113.88")
        self.assertTrue(data["data"]["is_banned"])
        self.assertGreaterEqual(data["data"]["total_events"], 1)

    def test_export_audit_report_endpoint(self) -> None:
        res = self.client.get("/api/defense/export")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "success")
        self.assertIn("threat_intelligence", data["data"])
        self.assertIn("mitigation_audit_log", data["data"])


if __name__ == "__main__":
    unittest.main()
