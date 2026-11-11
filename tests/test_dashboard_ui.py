import os
import unittest
from starlette.testclient import TestClient
from controller.api.app import create_app


class TestDashboardUI(unittest.TestCase):
    def setUp(self) -> None:
        self.app = create_app(enable_tailer=False)
        self.client = TestClient(self.app)

    def test_dashboard_index_serves_html(self) -> None:
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        self.assertIn("text/html", res.headers["content-type"])
        body = res.text
        self.assertIn("Autonomous IoT Cyber Defense System", body)
        self.assertIn("IOT_DEFENSE_BLOCKLIST", body)
        self.assertIn("iot_sensor_node", body)
        self.assertIn("iot_cowrie_honeypot", body)
        self.assertIn("mitigation-table-body", body)
        self.assertIn("terminal-feed", body)
        self.assertIn("General Activity Logs", body)
        self.assertIn("btn-clear-console", body)
        self.assertIn("btn-export-logs", body)
        self.assertIn("export-logs-modal", body)
        self.assertIn("filter-btn-all", body)
        self.assertIn("filter-btn-honeypot", body)
        self.assertIn("filter-btn-quarantine", body)
        self.assertIn("filter-btn-iot", body)
        self.assertIn("siem-grid-header", body)
        self.assertIn("v1.8.1-SOC", body)
        self.assertIn("select-ip-bruteforce", body)
        self.assertIn("select-ip-exploit", body)
        self.assertIn("select-ip-portsweep", body)
        self.assertIn("custom-ip-bruteforce", body)
        self.assertIn("/static/app.js?v=1.8.1", body)
        self.assertIn("no-store", res.headers.get("cache-control", "").lower())
        self.assertIn("DATE & TIME (IST)", body)
        self.assertIn("w-[145px]", body)
        self.assertIn("min-w-[860px]", body)
        self.assertIn("SOURCE/NODE", body)
        self.assertIn("PROTOCOL", body)
        self.assertIn("PAYLOAD & EVENT DATA", body)
        # Verify de-duplication: no duplicate reset button in ledger
        self.assertNotIn("🗑️ Reset DB", body)

    def test_static_js_client_served(self) -> None:
        res = self.client.get("/static/app.js")
        self.assertEqual(res.status_code, 200)
        self.assertIn("javascript", res.headers["content-type"].lower())
        self.assertIn("no-store", res.headers.get("cache-control", "").lower())
        body = res.text
        self.assertIn("EventSource", body)
        self.assertIn("textContent", body)
        self.assertIn("fetchInitialStatus", body)
        self.assertIn("setLogFilter", body)
        self.assertIn("clearConsole", body)
        self.assertIn("iot_telemetry", body)
        self.assertIn("quarantine", body)
        # Verify Indian Standard Date & Time integration
        self.assertIn("formatDateTime", body)
        self.assertIn("Asia/Kolkata", body)
        self.assertIn("en-IN", body)
        self.assertIn("w-[145px]", body)
        self.assertIn("min-w-[860px]", body)
        # Verify Multi-format Activity Log Exporter
        self.assertIn("openExportLogsModal", body)
        self.assertIn("closeExportLogsModal", body)
        self.assertIn("downloadActivityLogs", body)
        self.assertIn("updateExportPreviewCount", body)
        self.assertIn("terminalLogsBuffer", body)
        # Verify Multi-IP Adversary Simulation Pools & Swarm Support
        self.assertIn("ATTACK_IP_POOLS", body)
        self.assertIn("toggleCustomAttackIp", body)
        self.assertIn("allowlist_protected", body)
        self.assertIn("already_banned", body)
        self.assertIn("dataset.srcIp", body)

    def test_quarantine_ui_category_integration(self) -> None:
        res = self.client.get("/static/app.js")
        self.assertIn("quarantine", res.text)
        self.assertIn("Dynamic containment triggered", res.text)

    def test_mqtt_telemetry_listener_lifecycle(self) -> None:
        from controller.core.mqtt_listener import IoTTelemetryListener
        received = []
        listener = IoTTelemetryListener(
            broker_host="127.0.0.1",
            broker_port=1883,
            on_message_callback=lambda t, p, ts: received.append((t, p)),
        )
        self.assertFalse(listener._running)
        listener.start()
        self.assertTrue(listener._running)
        # Simulate message reception directly
        mock_msg = type("MockMsg", (), {"topic": "home/sensors/temperature", "payload": b'{"temp": 24.5}'})()
        listener._on_message(None, None, mock_msg)
        self.assertEqual(len(received), 1)
        self.assertEqual(received[0][0], "home/sensors/temperature")
        self.assertIn("24.5", received[0][1])
        listener.stop()
        self.assertFalse(listener._running)


if __name__ == "__main__":
    unittest.main()

