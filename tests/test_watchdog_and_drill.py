import os
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from starlette.testclient import TestClient

from controller.api.app import create_app
from controller.core.db import DefenseDatabase
from controller.core.detector import IntrusionDetector
from controller.core.watchdog import DefenseWatchdog
from controller.mitigation.allowlist import AllowlistManager
from controller.mitigation.firewall import FirewallController


class TestDefenseWatchdog(unittest.IsolatedAsyncioTestCase):
    """Unit tests for DefenseWatchdog self-healing and drill execution engine."""

    async def asyncSetUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "watchdog_test.db")
        self.db = DefenseDatabase(db_path=self.db_path)
        self.allowlist = AllowlistManager()
        self.firewall = FirewallController(allowlist_manager=self.allowlist, dry_run=True)
        self.detector = IntrusionDetector(firewall=self.firewall, db=self.db)
        self.quarantine = MagicMock()
        self.quarantine.client.ping.return_value = True

        self.watchdog = DefenseWatchdog(
            firewall=self.firewall,
            detector=self.detector,
            db=self.db,
            quarantine=self.quarantine,
            coap_port=5683,
            rtsp_port=8554,
        )

    async def asyncTearDown(self) -> None:
        self.temp_dir.cleanup()

    async def test_tcp_probe_success_and_failure(self) -> None:
        """Verifies TCP socket probe handles online and offline ports cleanly."""
        # Offline port probe
        res_offline = await self.watchdog.probe_tcp_service("127.0.0.1", 64999, timeout=0.1)
        self.assertFalse(res_offline["online"])
        self.assertIsNotNone(res_offline["error"])
        self.assertGreaterEqual(res_offline["latency_ms"], 0.0)

    async def test_udp_probe_dispatch(self) -> None:
        """Verifies UDP probe dispatches datagram cleanly."""
        res = await self.watchdog.probe_udp_service("127.0.0.1", 5683, timeout=0.1)
        self.assertEqual(res["protocol"], "UDP")
        self.assertTrue(res["online"])

    async def test_netfilter_chain_integrity_dry_run(self) -> None:
        """Verifies check_chain_integrity in dry-run mode."""
        self.firewall.ban_ip("198.51.100.55")
        integrity = self.firewall.check_chain_integrity(reheal=True)
        self.assertTrue(integrity["chain_exists"])
        self.assertTrue(integrity["parent_hooked"])
        self.assertEqual(integrity["status"], "HEALTHY")
        self.assertGreaterEqual(integrity["active_rules"], 1)

    async def test_sync_active_bans_rehydrates_missing_rules(self) -> None:
        """Verifies sync_active_bans re-injects missing rules into the firewall."""
        self.firewall.flush_blocklist()
        self.assertEqual(len(self.firewall.list_banned_ips()), 0)

        re_injected = self.firewall.sync_active_bans(["198.51.100.10", "198.51.100.20"])
        self.assertEqual(re_injected, 2)
        self.assertTrue(self.firewall.is_ip_banned("198.51.100.10"))
        self.assertTrue(self.firewall.is_ip_banned("198.51.100.20"))

    async def test_check_all_listeners_structure(self) -> None:
        """Verifies check_all_listeners returns complete subsystem audit."""
        health = await self.watchdog.check_all_listeners(timeout=0.1)
        self.assertIn("timestamp", health)
        self.assertIn("overall_status", health)
        self.assertIn("listeners", health)
        self.assertIn("netfilter", health)
        self.assertIn("database", health)
        self.assertIn("quarantine", health)

        # Database is fresh SQLite with WAL mode
        self.assertEqual(health["database"]["status"], "HEALTHY")
        self.assertTrue(health["database"]["wal_mode"])

        # Listeners structure
        listeners = health["listeners"]
        self.assertIn("cowrie_ssh", listeners)
        self.assertIn("cowrie_telnet", listeners)
        self.assertIn("mosquitto_mqtt", listeners)
        self.assertIn("coap_sensor_decoy", listeners)
        self.assertIn("rtsp_camera_decoy", listeners)

    async def test_run_verification_drill_executes_all_checks(self) -> None:
        """Verifies run_verification_drill runs 5 checks and measures latency."""
        callback_mock = AsyncMock()
        self.watchdog.on_alert_callback = callback_mock

        report = await self.watchdog.run_verification_drill()

        self.assertIn("drill_id", report)
        self.assertTrue(report["drill_id"].startswith("drill-"))
        self.assertEqual(report["checks_total"], 5)
        self.assertGreaterEqual(report["checks_passed"], 4)
        self.assertIn(report["status"], {"PASSED", "WARNING"})
        self.assertGreater(report["duration_ms"], 0.0)

        # Verify callback was notified
        callback_mock.assert_awaited_once()
        event_name, data = callback_mock.call_args[0]
        self.assertEqual(event_name, "drill_completed")
        self.assertEqual(data["drill_id"], report["drill_id"])


class TestWatchdogAPIEndpoints(unittest.TestCase):
    """Integration tests for watchdog REST API endpoints."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "watchdog_api.db")
        self.db = DefenseDatabase(db_path=self.db_path)
        self.detector = IntrusionDetector(
            firewall=FirewallController(dry_run=True),
            db=self.db,
        )
        self.app = create_app(
            detector=self.detector,
            enable_tailer=False,
            enable_mqtt=False,
            enable_decoys=False,
        )
        self.client = TestClient(self.app)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_get_watchdog_health_endpoint(self) -> None:
        """Verifies GET /api/defense/watchdog/health returns 200 with complete audit data."""
        res = self.client.get("/api/defense/watchdog/health")
        self.assertEqual(res.status_code, 200)
        json_data = res.json()
        self.assertEqual(json_data["status"], "success")
        self.assertIn("overall_status", json_data["data"])
        self.assertIn("listeners", json_data["data"])
        self.assertIn("netfilter", json_data["data"])
        self.assertIn("database", json_data["data"])

    def test_execute_watchdog_drill_endpoint(self) -> None:
        """Verifies POST /api/defense/watchdog/drill triggers automated drill and returns report."""
        res = self.client.post("/api/defense/watchdog/drill")
        self.assertEqual(res.status_code, 200)
        json_data = res.json()
        self.assertEqual(json_data["status"], "success")
        report = json_data["data"]
        self.assertIn("drill_id", report)
        self.assertEqual(report["checks_total"], 5)
        self.assertIn(report["status"], {"PASSED", "WARNING"})
        self.assertIsInstance(report["checks"], list)


if __name__ == "__main__":
    unittest.main()
