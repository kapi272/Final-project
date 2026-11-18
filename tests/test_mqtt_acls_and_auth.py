import os
import unittest
from unittest.mock import MagicMock, patch

from controller.core.mqtt_listener import IoTTelemetryListener


class TestMQTTBrokerACLAndAuth(unittest.TestCase):
    """
    Unit and integration tests for MQTT Broker Authentication and ACL Separation (Part 2 - Task 2).
    """

    def setUp(self) -> None:
        self.config_dir = os.path.join(os.path.dirname(__file__), "..", "config", "mosquitto")
        self.acl_file = os.path.join(self.config_dir, "acl.conf")
        self.passwd_file = os.path.join(self.config_dir, "password.txt")
        self.conf_file = os.path.join(self.config_dir, "mosquitto.conf")

    def test_mosquitto_config_files_exist(self) -> None:
        """Verifies that acl.conf, password.txt, and mosquitto.conf exist and are non-empty."""
        self.assertTrue(os.path.exists(self.acl_file), "acl.conf should exist")
        self.assertTrue(os.path.exists(self.passwd_file), "password.txt should exist")
        self.assertTrue(os.path.exists(self.conf_file), "mosquitto.conf should exist")

        with open(self.conf_file, "r") as f:
            conf_content = f.read()
        self.assertIn("acl_file /mosquitto/config/acl.conf", conf_content)
        self.assertIn("password_file /mosquitto/config/password.txt", conf_content)
        self.assertIn("allow_anonymous true", conf_content)

    def test_acl_rules_structure(self) -> None:
        """Verifies that ACL rules define anonymous and authenticated boundaries correctly."""
        with open(self.acl_file, "r") as f:
            acl_content = f.read()

        # Anonymous permissions
        self.assertIn("topic readwrite home/sensors/#", acl_content)
        self.assertIn("topic readwrite home/devices/#", acl_content)
        self.assertIn("topic readwrite home/admin/#", acl_content)  # Honeypot trap topics
        self.assertIn("topic read $SYS/#", acl_content)

        # Authenticated users
        self.assertIn("user soc_admin", acl_content)
        self.assertIn("topic readwrite #", acl_content)
        self.assertIn("user iot_gateway", acl_content)
        self.assertIn("topic readwrite home/#", acl_content)

    def test_password_file_format(self) -> None:
        """Verifies password file contains entries for soc_admin and iot_gateway."""
        with open(self.passwd_file, "r") as f:
            lines = [line.strip() for line in f if line.strip() and not line.startswith("#")]

        users = [line.split(":")[0] for line in lines]
        self.assertIn("soc_admin", users)
        self.assertIn("iot_gateway", users)

    @patch("paho.mqtt.client.Client")
    def test_listener_sets_credentials_when_provided(self, mock_client_cls: MagicMock) -> None:
        """Verifies that IoTTelemetryListener configures username and password on paho client."""
        mock_instance = MagicMock()
        mock_client_cls.return_value = mock_instance

        listener = IoTTelemetryListener(
            broker_host="127.0.0.1",
            broker_port=1883,
            username="soc_admin",
            password="soc_password_2026",
        )
        listener.start()

        mock_instance.username_pw_set.assert_called_once_with("soc_admin", "soc_password_2026")
        listener.stop()

    @patch("paho.mqtt.client.Client")
    def test_listener_anonymous_when_no_credentials(self, mock_client_cls: MagicMock) -> None:
        """Verifies that IoTTelemetryListener does not set credentials when none provided."""
        mock_instance = MagicMock()
        mock_client_cls.return_value = mock_instance

        with patch.dict(os.environ, {}, clear=True):
            listener = IoTTelemetryListener(
                broker_host="127.0.0.1",
                broker_port=1883,
                username=None,
                password=None,
            )
            listener.start()

            mock_instance.username_pw_set.assert_not_called()
            listener.stop()


if __name__ == "__main__":
    unittest.main()
