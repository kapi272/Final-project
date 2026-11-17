"""Multi-Protocol IoT Deception Decoy Engine for Autonomous Cyber Defense.

Provides lightweight asynchronous deception decoy services:
1. CoAP Decoy (RFC 7252 on UDP 5683): Emulates smart IoT environmental sensors
   and actuators, answering /.well-known/core discovery while trapping unauthorized
   probes, resource tampering, and command injections.
2. RTSP Decoy (RFC 2326 on TCP 8554 / 554): Emulates a streaming IP/CCTV camera,
   capturing unauthorized stream reconnaissance, credential brute-forcing, and URI injection.

Zero heavy dependencies (built entirely on Python standard library asyncio).
"""

import asyncio
import base64
import logging
import re
import socket
from typing import Any, Callable, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

COAP_DEFAULT_PORT = 5683
RTSP_DEFAULT_PORT = 8554


class CoAPMessage:
    """Minimal RFC 7252 CoAP Message parser and serializer."""

    def __init__(
        self,
        version: int = 1,
        msg_type: int = 0,  # 0: CON, 1: NON, 2: ACK, 3: RST
        code: int = 1,     # 1: GET, 2: POST, 3: PUT, 4: DELETE (or 69: 2.05 Content)
        msg_id: int = 0,
        token: bytes = b"",
        uri_path: str = "",
        payload: str = "",
    ) -> None:
        self.version = version
        self.msg_type = msg_type
        self.code = code
        self.msg_id = msg_id
        self.token = token
        self.uri_path = uri_path
        self.payload = payload

    @classmethod
    def from_bytes(cls, data: bytes) -> Optional["CoAPMessage"]:
        """Parses raw UDP packet bytes into a CoAP message."""
        if len(data) < 4:
            return None
        first_byte = data[0]
        version = (first_byte >> 6) & 0x03
        msg_type = (first_byte >> 4) & 0x03
        tkl = first_byte & 0x0F

        code = data[1]
        msg_id = (data[2] << 8) | data[3]

        offset = 4
        token = b""
        if tkl > 0 and len(data) >= 4 + tkl:
            token = data[4: 4 + tkl]
            offset += tkl

        # Parse options and payload
        uri_parts = []
        payload_str = ""
        current_opt_num = 0
        while offset < len(data):
            if data[offset] == 0xFF:
                # Payload marker reached
                payload_bytes = data[offset + 1:]
                payload_str = payload_bytes.decode("utf-8", errors="replace")
                break

            opt_byte = data[offset]
            opt_delta = (opt_byte >> 4) & 0x0F
            opt_len = opt_byte & 0x0F
            offset += 1
            current_opt_num += opt_delta

            if current_opt_num == 11 and offset + opt_len <= len(data):
                # Option 11: Uri-Path
                part = data[offset: offset + opt_len].decode("utf-8", errors="replace")
                uri_parts.append(part)
                offset += opt_len
            else:
                offset += opt_len

        uri_path = "/" + "/".join(uri_parts) if uri_parts else "/"
        return cls(
            version=version,
            msg_type=msg_type,
            code=code,
            msg_id=msg_id,
            token=token,
            uri_path=uri_path,
            payload=payload_str,
        )

    def to_bytes(self) -> bytes:
        """Serializes CoAP message into wire bytes."""
        tkl = len(self.token) & 0x0F
        first_byte = ((self.version & 0x03) << 6) | ((self.msg_type & 0x03) << 4) | tkl
        header = bytearray([first_byte, self.code, (self.msg_id >> 8) & 0xFF, self.msg_id & 0xFF])
        header.extend(self.token)

        # Encode Uri-Path options (Option 11)
        if self.uri_path and self.uri_path != "/":
            segments = [s for s in self.uri_path.split("/") if s]
            last_opt = 0
            for seg in segments:
                delta = 11 - last_opt
                seg_bytes = seg.encode("utf-8")
                opt_len = len(seg_bytes)
                header.append(((delta & 0x0F) << 4) | (opt_len & 0x0F))
                header.extend(seg_bytes)
                last_opt = 11

        if self.payload:
            header.append(0xFF)  # Payload marker
            header.extend(self.payload.encode("utf-8"))

        return bytes(header)


class CoAPDecoyProtocol(asyncio.DatagramProtocol):
    """Asynchronous UDP CoAP Honeypot server emulating IoT smart devices."""

    def __init__(self, on_probe_callback: Optional[Callable[[str, str, str], Any]] = None) -> None:
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.on_probe_callback = on_probe_callback

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore

    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        src_ip, src_port = addr
        msg = CoAPMessage.from_bytes(data)
        if not msg:
            logger.debug("Received non-CoAP UDP datagram from %s:%s", src_ip, src_port)
            return

        uri = msg.uri_path
        payload = msg.payload
        logger.info("CoAP Honeypot Hit from %s:%s -> %s (Code: %s)", src_ip, src_port, uri, msg.code)

        # Notify detector of CoAP probe / exploit
        if self.on_probe_callback:
            try:
                self.on_probe_callback(src_ip, uri, payload)
            except Exception as exc:
                logger.error("Error in CoAP probe callback: %s", exc)

        # Emulate authentic RFC 7252 responses
        # Code 69 = 2.05 Content response
        if uri == "/.well-known/core":
            resp_payload = '</sensors/temperature>;rt="temperature-c";if="sensor",</actuators/switch>;rt="switch";if="actuator"'
            resp = CoAPMessage(
                version=1,
                msg_type=2,  # ACK
                code=69,    # 2.05 Content
                msg_id=msg.msg_id,
                token=msg.token,
                payload=resp_payload,
            )
        elif uri.startswith("/sensors/temperature"):
            resp_payload = '{"sensor": "temperature", "value": 23.8, "unit": "C", "status": "nominal"}'
            resp = CoAPMessage(
                version=1,
                msg_type=2,
                code=69,
                msg_id=msg.msg_id,
                token=msg.token,
                payload=resp_payload,
            )
        else:
            # Code 132 = 4.04 Not Found
            resp = CoAPMessage(
                version=1,
                msg_type=2,
                code=132,
                msg_id=msg.msg_id,
                token=msg.token,
                payload="Resource Not Found",
            )

        if self.transport:
            self.transport.sendto(resp.to_bytes(), addr)


class RTSPDecoyProtocol(asyncio.Protocol):
    """Asynchronous TCP RTSP Honeypot server emulating vulnerable IP cameras."""

    def __init__(self, on_rtsp_callback: Optional[Callable[[str, str, str, str], Any]] = None) -> None:
        self.transport: Optional[asyncio.Transport] = None
        self.peer_ip: str = "Unknown"
        self.on_rtsp_callback = on_rtsp_callback
        self.buffer = ""

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore
        peer = transport.get_extra_info("peername")
        self.peer_ip = peer[0] if peer else "Unknown"

    def data_received(self, data: bytes) -> None:
        text = data.decode("utf-8", errors="replace")
        self.buffer += text

        lines = self.buffer.split("\r\n")
        if len(lines) < 2:
            return

        req_line = lines[0]
        parts = req_line.split()
        if len(parts) < 2:
            return

        method = parts[0].upper()
        uri = parts[1]

        # Extract CSeq and Authorization headers
        cseq = "1"
        auth_header = ""
        for line in lines[1:]:
            if line.lower().startswith("cseq:"):
                cseq = line.split(":", 1)[1].strip()
            elif line.lower().startswith("authorization:"):
                auth_header = line.split(":", 1)[1].strip()

        username = ""
        password = ""
        if "basic " in auth_header.lower():
            try:
                b64_val = auth_header.split(None, 1)[1].strip()
                cred_decoded = base64.b64decode(b64_val).decode("utf-8", errors="replace")
                if ":" in cred_decoded:
                    username, password = cred_decoded.split(":", 1)
            except Exception:
                pass

        if self.on_rtsp_callback:
            try:
                self.on_rtsp_callback(self.peer_ip, method, uri, f"User: {username}, Pass: {password}")
            except Exception as exc:
                logger.error("Error in RTSP callback: %s", exc)

        # Emulate authentic camera responses
        if method == "OPTIONS":
            resp = (
                f"RTSP/1.0 200 OK\r\n"
                f"CSeq: {cseq}\r\n"
                f"Public: OPTIONS, DESCRIBE, SETUP, TEARDOWN, PLAY\r\n"
                f"\r\n"
            )
        elif method == "DESCRIBE" and not auth_header:
            resp = (
                f"RTSP/1.0 401 Unauthorized\r\n"
                f"CSeq: {cseq}\r\n"
                f'WWW-Authenticate: Basic realm="IoT IP Camera Deception Decoy"\r\n'
                f"\r\n"
            )
        else:
            resp = (
                f"RTSP/1.0 200 OK\r\n"
                f"CSeq: {cseq}\r\n"
                f"Content-Type: application/sdp\r\n"
                f"Content-Length: 124\r\n"
                f"\r\n"
                f"v=0\r\no=- 1234567 1 IN IP4 0.0.0.0\r\ns=IoT CCTV Decoy Stream\r\nt=0 0\r\nm=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\n"
            )

        if self.transport:
            self.transport.write(resp.encode("utf-8"))
        self.buffer = ""


class DecoyManager:
    """Manages multi-protocol deception decoy listeners."""

    def __init__(
        self,
        coap_port: int = COAP_DEFAULT_PORT,
        rtsp_port: int = RTSP_DEFAULT_PORT,
        on_coap_probe: Optional[Callable[[str, str, str], Any]] = None,
        on_rtsp_probe: Optional[Callable[[str, str, str, str], Any]] = None,
    ) -> None:
        self.coap_port = coap_port
        self.rtsp_port = rtsp_port
        self.on_coap_probe = on_coap_probe
        self.on_rtsp_probe = on_rtsp_probe
        self.coap_transport: Optional[asyncio.DatagramTransport] = None
        self.rtsp_server: Optional[asyncio.Server] = None
        self.is_running = False

    async def start(self) -> None:
        """Launches CoAP and RTSP decoy listeners asynchronously."""
        loop = asyncio.get_running_loop()

        # Start CoAP UDP listener
        try:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: CoAPDecoyProtocol(on_probe_callback=self.on_coap_probe),
                local_addr=("0.0.0.0", self.coap_port),
            )
            self.coap_transport = transport
            logger.info("CoAP IoT Decoy active on UDP port %s", self.coap_port)
        except OSError as exc:
            logger.warning("Could not bind CoAP port %s (skipping CoAP decoy): %s", self.coap_port, exc)

        # Start RTSP TCP listener
        try:
            server = await loop.create_server(
                lambda: RTSPDecoyProtocol(on_rtsp_callback=self.on_rtsp_probe),
                host="0.0.0.0",
                port=self.rtsp_port,
            )
            self.rtsp_server = server
            logger.info("RTSP Camera Decoy active on TCP port %s", self.rtsp_port)
        except OSError as exc:
            logger.warning("Could not bind RTSP port %s (skipping RTSP decoy): %s", self.rtsp_port, exc)

        self.is_running = True

    def stop(self) -> None:
        """Stops active decoy listeners."""
        if self.coap_transport:
            self.coap_transport.close()
            self.coap_transport = None
        if self.rtsp_server:
            self.rtsp_server.close()
            self.rtsp_server = None
        self.is_running = False
        logger.info("IoT Decoy services stopped.")
