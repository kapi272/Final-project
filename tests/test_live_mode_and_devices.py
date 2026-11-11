"""Tests for Traffic Mode Toggle, Real-World IoT/CCTV Device Manager, and Log Rotation."""

import asyncio
import json
import os
import tempfile
import unittest
import urllib.error
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi.testclient import TestClient

from controller.api.app import create_app
from controller.api.sse_broker import SSEBroadcaster
from controller.core.db import DefenseDatabase
from controller.core.detector import IntrusionDetector
from controller.core.device_manager import RealDeviceManager
from controller.core.log_tailer import HoneypotLogTailer
from controller.mitigation.allowlist import AllowlistManager
from controller.mitigation.firewall import FirewallController


def _build_test_components(db_path: str) -> Dict[str, Any]:
    """Create isolated DB, detector, mock quarantine, and SSE broadcaster."""
    db = DefenseDatabase(db_path=db_path)
    allowlist = AllowlistManager()
    firewall = FirewallController(allowlist_manager=allowlist, dry_run=True)
    detector = IntrusionDetector(
        firewall=firewall,
        db=db,
        allowlist=allowlist,
        failed_login_threshold=5,
        time_window_seconds=30.0,
    )
    mock_quarantine = MagicMock()
    mock_quarantine.get_container_network_status.return_value = "production"
    mock_quarantine.quarantine_container.return_value = {
        "status": "success",
        "current_state": "quarantined",
        "message": "isolated",
    }
    mock_quarantine.restore_container.return_value = {
        "status": "success",
        "current_state": "production",
        "message": "restored",
    }
    broadcaster = SSEBroadcaster()
    return {
        "db": db,
        "allowlist": allowlist,
        "firewall": firewall,
        "detector": detector,
        "quarantine": mock_quarantine,
        "broadcaster": broadcaster,
    }


class _FakeHTTPResponse:
    """Minimal HTTP response context manager for mocking urllib opener.open."""

    def __init__(self, body: bytes, content_type: str = "image/jpeg") -> None:
        self._body = body
        self._offset = 0
        self.headers = {"Content-Type": content_type}

    def __enter__(self) -> "_FakeHTTPResponse":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        return False

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            chunk = self._body[self._offset:]
            self._offset = len(self._body)
            return chunk
        chunk = self._body[self._offset:self._offset + size]
        self._offset += len(chunk)
        return chunk


class TestTrafficModeAndLiveDevices(unittest.TestCase):
    """End-to-end API tests for Simulated/Live mode toggle and device lifecycle."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "live_mode_test.db")
        self.comp = _build_test_components(self.db_path)
        self.app = create_app(
            detector=self.comp["detector"],
            quarantine_manager=self.comp["quarantine"],
            broadcaster=self.comp["broadcaster"],
            enable_tailer=False,
            enable_mqtt=False,
        )
        self.client = TestClient(self.app)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_traffic_mode_persistence_and_simulation_guard(self) -> None:
        # Default mode should be simulated
        get_res = self.client.get("/api/system/mode")
        self.assertEqual(get_res.status_code, 200)
        mode_data = get_res.json()["data"]
        self.assertEqual(mode_data["mode"], "simulated")
        self.assertTrue(mode_data["simulated_endpoints_enabled"])

        # Switch to live mode
        set_live = self.client.post("/api/system/mode", json={"mode": "live"})
        self.assertEqual(set_live.status_code, 200)
        self.assertEqual(set_live.json()["data"]["mode"], "live")
        self.assertFalse(set_live.json()["data"]["simulated_endpoints_enabled"])

        # Invalid mode rejected with 400
        bad_mode = self.client.post("/api/system/mode", json={"mode": "hybrid"})
        self.assertEqual(bad_mode.status_code, 400)

        # Defense status reflects live mode
        status_res = self.client.get("/api/defense/status")
        self.assertEqual(status_res.status_code, 200)
        self.assertEqual(status_res.json()["data"]["traffic_mode"], "live")
        self.assertIn("registered_devices", status_res.json()["data"])

        # Simulation endpoints return 409 Conflict while in live mode
        for method_path in (
            "/api/simulate/attack/brute-force",
            "/api/simulate/attack/exploit",
            "/api/simulate/attack/port-sweep",
            "/api/simulate/infect/iot_sensor_node",
            "/api/simulate/restore/iot_sensor_node",
        ):
            res = self.client.post(method_path)
            self.assertEqual(res.status_code, 409, f"Expected 409 for {method_path} in live mode")

        # Verify persistence across a new app instance pointing at the same SQLite DB
        comp2 = _build_test_components(self.db_path)
        app2 = create_app(
            detector=comp2["detector"],
            quarantine_manager=comp2["quarantine"],
            broadcaster=comp2["broadcaster"],
            enable_tailer=False,
            enable_mqtt=False,
        )
        client2 = TestClient(app2)
        persisted = client2.get("/api/system/mode")
        self.assertEqual(persisted.status_code, 200)
        self.assertEqual(persisted.json()["data"]["mode"], "live")

        # Switch back to simulated mode restores simulation capabilities
        set_sim = self.client.post("/api/system/mode", json={"mode": "simulated"})
        self.assertEqual(set_sim.status_code, 200)
        self.assertEqual(set_sim.json()["data"]["mode"], "simulated")

        atk = self.client.post("/api/simulate/attack/exploit")
        self.assertEqual(atk.status_code, 200)

    def test_device_registration_validation_ssrf_and_masking(self) -> None:
        # SSRF / unsafe targets rejected with 400
        invalid_payloads = [
            {
                "device_id": "bad loopback",
                "name": "Bad ID",
                "ip_address": "192.168.1.50",
                "port": 554,
            },
            {
                "device_id": "ssrf_loopback",
                "name": "Loopback",
                "ip_address": "127.0.0.1",
                "port": 80,
            },
            {
                "device_id": "ssrf_metadata",
                "name": "Cloud Metadata",
                "ip_address": "169.254.169.254",
                "port": 80,
            },
            {
                "device_id": "ssrf_docker_gw",
                "name": "Docker GW",
                "ip_address": "172.20.0.1",
                "port": 80,
            },
            {
                "device_id": "bad_file_url",
                "name": "Local File Read",
                "ip_address": "192.168.1.50",
                "port": 80,
                "snapshot_url": "file:///etc/passwd",
            },
            {
                "device_id": "bad_url_ssrf",
                "name": "URL SSRF",
                "ip_address": "192.168.1.50",
                "port": 80,
                "snapshot_url": "http://169.254.169.254/latest/meta-data/",
            },
            {
                "device_id": "bad_port",
                "name": "Invalid Port",
                "ip_address": "192.168.1.50",
                "port": 70000,
            },
        ]
        for body in invalid_payloads:
            res = self.client.post("/api/devices", json=body)
            self.assertEqual(res.status_code, 400, f"Expected 400 for payload: {body}")

        # Valid RFC 1918 CCTV camera with credentials in snapshot URL
        create_res = self.client.post(
            "/api/devices",
            json={
                "device_id": "cam_gate_01",
                "name": "Front Gate CCTV",
                "device_type": "cctv_camera",
                "protocol": "rtsp_http",
                "ip_address": "192.168.1.50",
                "port": 554,
                "snapshot_url": "https://admin:SuperSecret123@192.168.1.50/snap.jpg",
            },
        )
        self.assertEqual(create_res.status_code, 200)
        created = create_res.json()["data"]["device"]
        self.assertIn("ingest_token", created)
        self.assertGreaterEqual(len(created["ingest_token"]), 24)
        self.assertNotIn("token_hash", created)
        self.assertNotIn("SuperSecret123", created["snapshot_url"])
        self.assertIn("***:***@192.168.1.50", created["snapshot_url"])

        # GET /api/devices omits ingest_token, token_hash, and raw snapshot credentials
        list_res = self.client.get("/api/devices")
        self.assertEqual(list_res.status_code, 200)
        devices = list_res.json()["data"]["devices"]
        self.assertEqual(len(devices), 1)
        listed = devices[0]
        self.assertEqual(listed["device_id"], "cam_gate_01")
        self.assertNotIn("ingest_token", listed)
        self.assertNotIn("token_hash", listed)
        self.assertNotIn("SuperSecret123", listed["snapshot_url"])

        # DELETE removes device cleanly and missing DELETE returns 404
        del_res = self.client.delete("/api/devices/cam_gate_01")
        self.assertEqual(del_res.status_code, 200)
        del_again = self.client.delete("/api/devices/cam_gate_01")
        self.assertEqual(del_again.status_code, 404)

    def test_webhook_auth_quarantine_block_and_unblock(self) -> None:
        create_res = self.client.post(
            "/api/devices",
            json={
                "device_id": "esp32_hall_01",
                "name": "Hallway ESP32 Sensor",
                "device_type": "iot_sensor",
                "protocol": "http_webhook",
                "ip_address": "198.51.100.75",
                "port": 80,
            },
        )
        self.assertEqual(create_res.status_code, 200)
        token = create_res.json()["data"]["device"]["ingest_token"]

        # Switch to live mode
        self.client.post("/api/system/mode", json={"mode": "live"})

        # Missing or wrong token returns 401
        unauth_missing = self.client.post(
            "/api/devices/ingest/esp32_hall_01",
            json={"payload": {"temp": 24.5}},
        )
        self.assertEqual(unauth_missing.status_code, 401)

        unauth_bad = self.client.post(
            "/api/devices/ingest/esp32_hall_01",
            headers={"X-Device-Token": "wrong-token-value"},
            json={"payload": {"temp": 24.5}},
        )
        self.assertEqual(unauth_bad.status_code, 401)

        # Valid token succeeds and updates status + last_payload
        ok_res = self.client.post(
            "/api/devices/ingest/esp32_hall_01",
            headers={"X-Device-Token": token},
            json={"payload": {"temp": 24.5, "motion": False}},
        )
        self.assertEqual(ok_res.status_code, 200)
        dev = ok_res.json()["data"]["device"]
        self.assertEqual(dev["status"], "ONLINE")
        self.assertIn("24.5", dev["last_payload"])

        # Block device -> sets BLOCKED, drops future ingest with 403, bans IP, logs mitigation
        blk_res = self.client.post(
            "/api/devices/esp32_hall_01/block",
            json={"reason": "Suspicious outbound beacon", "admin_user": "tester"},
        )
        self.assertEqual(blk_res.status_code, 200)
        blk_data = blk_res.json()["data"]
        self.assertEqual(blk_data["device"]["status"], "QUARANTINED")
        self.assertTrue(blk_data["device"]["blocked"])
        self.assertEqual(blk_data["mitigation"]["action"], "DEVICE_BLOCKED")
        self.assertTrue(self.comp["firewall"].is_ip_banned("198.51.100.75"))

        blocked_ingest = self.client.post(
            "/api/devices/ingest/esp32_hall_01",
            headers={"X-Device-Token": token},
            json={"payload": {"temp": 99.9}},
        )
        self.assertEqual(blocked_ingest.status_code, 403)

        # Unblock device -> clears blocked flag, unbans IP, logs DEVICE_RESTORED, allows telemetry again
        unblk_res = self.client.post(
            "/api/devices/esp32_hall_01/unblock",
            json={"admin_user": "tester"},
        )
        self.assertEqual(unblk_res.status_code, 200)
        unblk_data = unblk_res.json()["data"]
        self.assertFalse(unblk_data["device"]["blocked"])
        self.assertEqual(unblk_data["mitigation"]["action"], "DEVICE_RESTORED")
        self.assertFalse(self.comp["firewall"].is_ip_banned("198.51.100.75"))

        restored_ingest = self.client.post(
            "/api/devices/ingest/esp32_hall_01",
            headers={"X-Device-Token": token},
            json={"payload": {"temp": 23.1}},
        )
        self.assertEqual(restored_ingest.status_code, 200)

    def test_snapshot_proxy_validation_and_xss_blocking(self) -> None:
        create_res = self.client.post(
            "/api/devices",
            json={
                "device_id": "cam_driveway",
                "name": "Driveway Cam",
                "device_type": "cctv_camera",
                "protocol": "rtsp_http",
                "ip_address": "192.168.1.60",
                "port": 80,
                "snapshot_url": "http://192.168.1.60/snap.jpg",
            },
        )
        self.assertEqual(create_res.status_code, 200)

        jpeg_bytes = b"\xff\xd8\xff\xe0" + b"0" * 64 + b"\xff\xd9"
        png_bytes = b"\x89PNG\r\n\x1a\n" + b"1" * 64
        mjpeg_bytes = (
            b"--myboundary\r\n"
            b"Content-Type: image/jpeg\r\n\r\n"
            + jpeg_bytes
            + b"\r\n--myboundary--\r\n"
        )

        # Valid JPEG image returned with nosniff header
        fake_opener = MagicMock()
        fake_opener.open.return_value = _FakeHTTPResponse(jpeg_bytes, "image/jpeg")
        with patch("controller.core.device_manager.urllib.request.build_opener", return_value=fake_opener):
            snap_res = self.client.get("/api/devices/cam_driveway/snapshot")
        self.assertEqual(snap_res.status_code, 200)
        self.assertEqual(snap_res.headers.get("x-content-type-options"), "nosniff")
        self.assertIn("no-store", snap_res.headers.get("cache-control", ""))
        self.assertTrue(snap_res.content.startswith(b"\xff\xd8\xff"))

        # Valid PNG image
        fake_opener.open.return_value = _FakeHTTPResponse(png_bytes, "image/png")
        with patch("controller.core.device_manager.urllib.request.build_opener", return_value=fake_opener):
            png_res = self.client.get("/api/devices/cam_driveway/snapshot")
        self.assertEqual(png_res.status_code, 200)
        self.assertEqual(png_res.headers.get("content-type"), "image/png")

        # Valid MJPEG frame extracted cleanly
        fake_opener.open.return_value = _FakeHTTPResponse(
            mjpeg_bytes, "multipart/x-mixed-replace; boundary=myboundary"
        )
        with patch("controller.core.device_manager.urllib.request.build_opener", return_value=fake_opener):
            mj_res = self.client.get("/api/devices/cam_driveway/snapshot")
        self.assertEqual(mj_res.status_code, 200)
        self.assertTrue(mj_res.content.startswith(b"\xff\xd8\xff"))

        # Continuous multi-frame MJPEG stream (>2.5 MB total) stops at frame #1 cleanly
        large_jpeg = b"\xff\xd8\xff\xe0" + b"X" * 24000 + b"\xff\xd9"
        one_part = (
            b"\r\n--Ba4oTvQMY8ew04N8dcnM\r\n"
            b"Content-Type: image/jpeg\r\n"
            + f"Content-Length: {len(large_jpeg)}\r\n\r\n".encode("ascii")
            + large_jpeg
        )
        continuous_mjpeg = one_part * 120  # >2.8 MB total stream
        fake_opener.open.return_value = _FakeHTTPResponse(
            continuous_mjpeg, "multipart/x-mixed-replace;boundary=Ba4oTvQMY8ew04N8dcnM"
        )
        with patch("controller.core.device_manager.urllib.request.build_opener", return_value=fake_opener):
            stream_res = self.client.get("/api/devices/cam_driveway/snapshot")
        self.assertEqual(stream_res.status_code, 200)
        self.assertEqual(stream_res.headers.get("content-type"), "image/jpeg")
        self.assertEqual(len(stream_res.content), len(large_jpeg))

        # HTML / XSS payload rejected cleanly (400 validation error)
        fake_opener.open.return_value = _FakeHTTPResponse(
            b"<html><script>alert(1)</script></html>", "text/html"
        )
        with patch("controller.core.device_manager.urllib.request.build_opener", return_value=fake_opener):
            xss_res = self.client.get("/api/devices/cam_driveway/snapshot")
        self.assertEqual(xss_res.status_code, 400)

        # Oversized payload (>2 MB) rejected cleanly
        oversized = b"\xff\xd8\xff" + b"A" * (2 * 1024 * 1024 + 128)
        fake_opener.open.return_value = _FakeHTTPResponse(oversized, "image/jpeg")
        with patch("controller.core.device_manager.urllib.request.build_opener", return_value=fake_opener):
            big_res = self.client.get("/api/devices/cam_driveway/snapshot")
        self.assertIn(big_res.status_code, (400, 502))

        # HTTP Redirect rejected cleanly with 502
        redirect_err = urllib.error.HTTPError(
            url="http://192.168.1.60/snap.jpg",
            code=302,
            msg="Found",
            hdrs={},
            fp=None,
        )
        fake_opener.open.side_effect = redirect_err
        with patch("controller.core.device_manager.urllib.request.build_opener", return_value=fake_opener):
            redir_res = self.client.get("/api/devices/cam_driveway/snapshot")
        self.assertEqual(redir_res.status_code, 502)

    def test_tcp_probe_endpoint_online_and_offline(self) -> None:
        self.client.post(
            "/api/devices",
            json={
                "device_id": "cam_porch",
                "name": "Porch Camera",
                "device_type": "cctv_camera",
                "protocol": "rtsp_http",
                "ip_address": "192.168.1.70",
                "port": 554,
            },
        )

        fake_writer = MagicMock()
        fake_writer.close = MagicMock()
        fake_writer.wait_closed = AsyncMock(return_value=None)

        with patch(
            "controller.core.device_manager.asyncio.open_connection",
            new=AsyncMock(return_value=(MagicMock(), fake_writer)),
        ):
            online_res = self.client.post("/api/devices/cam_porch/probe")
        self.assertEqual(online_res.status_code, 200)
        self.assertEqual(online_res.json()["data"]["device"]["status"], "ONLINE")

        with patch(
            "controller.core.device_manager.asyncio.open_connection",
            new=AsyncMock(side_effect=OSError("Connection refused")),
        ):
            offline_res = self.client.post("/api/devices/cam_porch/probe")
        self.assertEqual(offline_res.status_code, 200)
        self.assertEqual(offline_res.json()["data"]["device"]["status"], "UNREACHABLE")


class TestLiveModeMQTTAndLogRotation(unittest.IsolatedAsyncioTestCase):
    """Async tests for strict Simulated vs Live MQTT routing and Cowrie log rotation."""

    async def asyncSetUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "mqtt_and_tailer.db")
        self.comp = _build_test_components(self.db_path)

    async def asyncTearDown(self) -> None:
        self.temp_dir.cleanup()

    async def test_mqtt_callback_strict_simulated_vs_live_filtering(self) -> None:
        captured: Dict[str, Any] = {}

        def _fake_listener_ctor(*args: Any, **kwargs: Any) -> MagicMock:
            captured["callback"] = kwargs.get("on_message_callback")
            inst = MagicMock()
            inst.start = MagicMock()
            inst.stop = MagicMock()
            return inst

        with patch("controller.api.app.IoTTelemetryListener", side_effect=_fake_listener_ctor):
            app = create_app(
                detector=self.comp["detector"],
                quarantine_manager=self.comp["quarantine"],
                broadcaster=self.comp["broadcaster"],
                enable_tailer=False,
                enable_mqtt=True,
                mqtt_host="127.0.0.1",
                mqtt_port=1883,
            )

            with TestClient(app):
                on_iot_telemetry = captured["callback"]
                self.assertIsNotNone(on_iot_telemetry)
                dm: RealDeviceManager = app.state.device_manager

                # Register a real MQTT device under home/garage/sensor
                dm.register_device(
                    device_id="garage_door_01",
                    name="Garage Door Sensor",
                    device_type="iot_sensor",
                    protocol="mqtt",
                    ip_address="192.168.1.90",
                    port=1883,
                    mqtt_topic="home/garage/sensor",
                )

                queue = await self.comp["broadcaster"].subscribe()

                # 1. In simulated mode, simulator payload passes through
                app.state.traffic_mode = "simulated"
                await on_iot_telemetry(
                    "home/sensors/temperature",
                    json.dumps({"device_id": "temp_sensor_01", "temperature": 22.5}),
                    1000.0,
                )
                frame1 = await asyncio.wait_for(queue.get(), timeout=1.0)
                self.assertIn("event: iot_telemetry", frame1)
                self.assertIn("temp_sensor_01", frame1)

                # 2. Switch to live mode -> simulator payload must be dropped!
                app.state.traffic_mode = "live"
                await on_iot_telemetry(
                    "home/sensors/temperature",
                    json.dumps({"device_id": "temp_sensor_01", "temperature": 22.6}),
                    1001.0,
                )
                with self.assertRaises(asyncio.TimeoutError):
                    await asyncio.wait_for(queue.get(), timeout=0.15)

                # 3. External/registered device telemetry in live mode updates DB & emits SSE
                await on_iot_telemetry(
                    "home/garage/sensor",
                    json.dumps({"device_id": "garage_door_01", "state": "CLOSED"}),
                    1002.0,
                )
                events: List[str] = []
                for _ in range(2):
                    events.append(await asyncio.wait_for(queue.get(), timeout=1.0))
                joined = "\n".join(events)
                self.assertIn("event: iot_telemetry", joined)
                self.assertIn("event: device_updated", joined)
                self.assertIn("garage_door_01", joined)

                # 4. Quarantined real device MQTT message is dropped & emits device_telemetry_blocked
                dm.block_device("garage_door_01", self.comp["detector"], reason="Test MQTT block")
                await on_iot_telemetry(
                    "home/garage/sensor",
                    json.dumps({"device_id": "garage_door_01", "state": "OPEN"}),
                    1003.0,
                )
                blk_frame = await asyncio.wait_for(queue.get(), timeout=1.0)
                self.assertIn("event: device_telemetry_blocked", blk_frame)
                self.assertIn("garage_door_01", blk_frame)
                with self.assertRaises(asyncio.TimeoutError):
                    await asyncio.wait_for(queue.get(), timeout=0.15)

    async def test_cowrie_log_tailer_handles_inode_rotation(self) -> None:
        log_path = os.path.join(self.temp_dir.name, "cowrie.json")
        rotated_path = os.path.join(self.temp_dir.name, "cowrie.json.2026-11-10")

        # Start with empty log file so tailer seeks to EOF (0) and awaits new events
        with open(log_path, "w", encoding="utf-8"):
            pass

        received_ips: List[str] = []
        event_arrived = asyncio.Event()

        async def on_event(evt: Any) -> None:
            received_ips.append(evt.src_ip)
            event_arrived.set()

        tailer = HoneypotLogTailer(log_path=log_path, on_event_callback=on_event)
        task = asyncio.create_task(tailer.start())

        try:
            await asyncio.sleep(0.25)

            # Write event #1 before rotation
            with open(log_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps({
                    "eventid": "cowrie.login.failed",
                    "src_ip": "198.51.100.11",
                    "username": "root",
                    "password": "bad",
                }) + "\n")
                fh.flush()

            await asyncio.wait_for(event_arrived.wait(), timeout=2.0)
            self.assertEqual(received_ips, ["198.51.100.11"])

            # Rotate cowrie.json -> cowrie.json.2026-11-10 and create new inode
            event_arrived.clear()
            os.rename(log_path, rotated_path)
            with open(log_path, "w", encoding="utf-8") as fh:
                fh.write(json.dumps({
                    "eventid": "cowrie.login.failed",
                    "src_ip": "203.0.113.22",
                    "username": "admin",
                    "password": "bad",
                }) + "\n")
                fh.flush()

            await asyncio.wait_for(event_arrived.wait(), timeout=2.5)
            self.assertEqual(received_ips, ["198.51.100.11", "203.0.113.22"])
        finally:
            tailer.stop()
            await asyncio.wait_for(task, timeout=2.0)


if __name__ == "__main__":
    unittest.main()
