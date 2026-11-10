import unittest
from unittest.mock import MagicMock

from controller.mitigation.allowlist import AllowlistManager
from controller.mitigation.firewall import CHAIN_NAME, PARENT_CHAIN, FirewallController
from controller.mitigation.quarantine import QuarantineManager


class TestAllowlistManager(unittest.TestCase):
    def setUp(self) -> None:
        self.allowlist = AllowlistManager()

    def test_protected_loopback_and_gateway(self) -> None:
        self.assertTrue(self.allowlist.is_ip_protected("127.0.0.1"))
        self.assertTrue(self.allowlist.is_ip_protected("127.0.0.5"))
        self.assertTrue(self.allowlist.is_ip_protected("::1"))
        self.assertTrue(self.allowlist.is_ip_protected("172.20.0.1"))
        self.assertTrue(self.allowlist.is_ip_protected("172.21.0.1"))

    def test_unprotected_external_ips(self) -> None:
        self.assertFalse(self.allowlist.is_ip_protected("198.51.100.25"))
        self.assertFalse(self.allowlist.is_ip_protected("203.0.113.10"))
        self.assertFalse(self.allowlist.is_ip_protected("172.20.0.55"))

    def test_validate_target_ip_success(self) -> None:
        sanitized = self.allowlist.validate_target_ip("  198.51.100.42  ")
        self.assertEqual(sanitized, "198.51.100.42")

    def test_validate_target_ip_protected_raises(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            self.allowlist.validate_target_ip("127.0.0.1")
        self.assertIn("protected by the management safety allowlist", str(ctx.exception))

    def test_validate_target_ip_invalid_format_raises(self) -> None:
        with self.assertRaises(ValueError):
            self.allowlist.validate_target_ip("invalid-ip-string")
        with self.assertRaises(ValueError):
            self.allowlist.validate_target_ip("")


class TestFirewallController(unittest.TestCase):
    def setUp(self) -> None:
        self.fw = FirewallController(dry_run=True)

    def test_initialization(self) -> None:
        self.assertTrue(self.fw.initialize_chains())

    def test_ban_and_unban_idempotency(self) -> None:
        test_ip = "198.51.100.99"
        self.assertFalse(self.fw.is_ip_banned(test_ip))

        # First ban
        self.assertTrue(self.fw.ban_ip(test_ip))
        self.assertTrue(self.fw.is_ip_banned(test_ip))
        self.assertIn(test_ip, self.fw.list_banned_ips())

        # Second ban (idempotent no-op)
        self.assertTrue(self.fw.ban_ip(test_ip))
        self.assertEqual(len(self.fw.list_banned_ips()), 1)

        # Unban
        self.assertTrue(self.fw.unban_ip(test_ip))
        self.assertFalse(self.fw.is_ip_banned(test_ip))
        self.assertNotIn(test_ip, self.fw.list_banned_ips())

        # Second unban (idempotent no-op)
        self.assertTrue(self.fw.unban_ip(test_ip))

    def test_ban_protected_ip_blocked(self) -> None:
        # Loopback must be rejected
        self.assertFalse(self.fw.ban_ip("127.0.0.1"))
        self.assertFalse(self.fw.is_ip_banned("127.0.0.1"))

    def test_flush_blocklist(self) -> None:
        self.fw.ban_ip("198.51.100.1")
        self.fw.ban_ip("198.51.100.2")
        self.assertEqual(len(self.fw.list_banned_ips()), 2)

        self.assertTrue(self.fw.flush_blocklist())
        self.assertEqual(len(self.fw.list_banned_ips()), 0)


class TestQuarantineManager(unittest.TestCase):
    def test_fallback_when_docker_unavailable(self) -> None:
        qm = QuarantineManager(docker_client=None)
        self.assertEqual(qm.get_container_network_status("any_container"), "unknown")
        res = qm.quarantine_container("any_container")
        self.assertEqual(res["status"], "failed")

    def test_quarantine_with_mock_client(self) -> None:
        mock_docker = MagicMock()
        mock_container = MagicMock()
        mock_container.attrs = {
            "NetworkSettings": {
                "Networks": {"iot_production_net": {}}
            }
        }
        mock_docker.containers.get.return_value = mock_container

        mock_prod_net = MagicMock()
        mock_quar_net = MagicMock()
        mock_docker.networks.get.side_effect = lambda name: mock_prod_net if name == "iot_production_net" else mock_quar_net

        qm = QuarantineManager(docker_client=mock_docker)

        # Before quarantine: production
        self.assertEqual(qm.get_container_network_status("iot_sensor_node"), "production")

        # Execute quarantine
        res = qm.quarantine_container("iot_sensor_node")
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["current_state"], "quarantined")

        # Verify network calls
        mock_quar_net.connect.assert_called_once_with(mock_container)
        mock_prod_net.disconnect.assert_called_once_with(mock_container)


if __name__ == "__main__":
    unittest.main()

