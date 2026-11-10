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

    def test_static_js_client_served(self) -> None:
        res = self.client.get("/static/app.js")
        self.assertEqual(res.status_code, 200)
        self.assertIn("javascript", res.headers["content-type"].lower())
        body = res.text
        self.assertIn("EventSource", body)
        self.assertIn("textContent", body)
        self.assertIn("fetchInitialStatus", body)


if __name__ == "__main__":
    unittest.main()

