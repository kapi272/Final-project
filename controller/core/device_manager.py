import asyncio
import hashlib
import hmac
import ipaddress
import json
import logging
import re
import secrets
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from controller.core.db import DefenseDatabase
from controller.core.models import MitigationRecord

logger = logging.getLogger(__name__)

ALLOWED_DEVICE_TYPES = {"cctv_camera", "iot_sensor", "smart_actuator", "edge_gateway"}
ALLOWED_PROTOCOLS = {"mqtt", "rtsp_http", "http_webhook"}
SIMULATED_DEFAULT_DEVICE_IDS = {"temp_sensor_01", "smart_bulb_01"}
PROTECTED_INFRA_IPS = {
    ipaddress.ip_address("172.20.0.1"),
    ipaddress.ip_address("172.20.0.5"),
    ipaddress.ip_address("172.21.0.1"),
    ipaddress.ip_address("172.21.0.5"),
    ipaddress.ip_address("192.168.65.1"),
}

DEVICE_ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{1,47}$")
MQTT_TOPIC_RE = re.compile(r"^[a-zA-Z0-9_/+.#-]{1,128}$")
MAX_SNAPSHOT_BYTES = 2 * 1024 * 1024


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Blocks HTTP redirects to prevent SSRF bypasses to metadata or internal hosts."""

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        raise ValueError(f"HTTP redirect ({code}) blocked by snapshot security policy.")


def _validate_target_network_ip(ip_obj: ipaddress._BaseAddress) -> None:
    """Rejects loopback, link-local metadata, unspecified, multicast, and controller gateways."""
    if ip_obj.is_loopback:
        raise ValueError(f"Loopback address '{ip_obj}' cannot be registered as an external device.")
    if ip_obj.is_link_local:
        raise ValueError(f"Link-local/metadata address '{ip_obj}' is blocked by SSRF security policy.")
    if ip_obj.is_unspecified:
        raise ValueError(f"Unspecified address '{ip_obj}' is not allowed.")
    if ip_obj.is_multicast:
        raise ValueError(f"Multicast address '{ip_obj}' is not allowed.")
    if ip_obj in PROTECTED_INFRA_IPS:
        raise ValueError(f"Infrastructure gateway/controller IP '{ip_obj}' is reserved and protected.")


def _mask_url_credentials(url_str: str) -> str:
    """Redacts username/password userinfo from snapshot URLs before returning to API clients or logs."""
    if not url_str:
        return ""
    parsed = urllib.parse.urlparse(url_str)
    if not parsed.username and not parsed.password:
        return url_str
    netloc = parsed.hostname or ""
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"
    return urllib.parse.urlunparse((parsed.scheme, f"***:***@{netloc}", parsed.path, parsed.params, parsed.query, ""))


def _detect_image_content_type(raw_bytes: bytes, declared_ct: str) -> Optional[str]:
    """Inspects magic bytes or MJPEG boundaries to ensure payload is a valid raster image."""
    lowered_ct = (declared_ct or "").split(";")[0].strip().lower()
    if raw_bytes.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if raw_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if raw_bytes.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if len(raw_bytes) >= 12 and raw_bytes[:4] == b"RIFF" and raw_bytes[8:12] == b"WEBP":
        return "image/webp"
    if "multipart/x-mixed-replace" in lowered_ct:
        return "multipart/jpeg_stream"
    return None


def _extract_first_jpeg_frame(stream_bytes: bytes) -> Optional[bytes]:
    """Extracts the first complete JPEG SOI..EOI frame from an MJPEG HTTP response."""
    start = stream_bytes.find(b"\xff\xd8\xff")
    if start < 0:
        return None
    end = stream_bytes.find(b"\xff\xd9", start + 3)
    if end < 0:
        return None
    return stream_bytes[start : end + 2]


class RealDeviceManager:
    """Manages persistent real-world IoT & CCTV devices, SSRF-safe checks, and logical quarantine."""

    def __init__(self, db: DefenseDatabase) -> None:
        self.db = db

    @staticmethod
    def validate_device_ip(ip_str: str) -> str:
        """Validates an external/LAN IoT device IP address."""
        if not ip_str or not isinstance(ip_str, str):
            raise ValueError("IP address is required.")
        sanitized = ip_str.strip()
        try:
            ip_obj = ipaddress.ip_address(sanitized)
        except ValueError as exc:
            raise ValueError(f"Invalid IP address '{sanitized}': {exc}") from exc
        _validate_target_network_ip(ip_obj)
        return str(ip_obj)

    @staticmethod
    def validate_snapshot_url(url_str: Optional[str]) -> str:
        """Validates optional HTTP/HTTPS camera snapshot URL against SSRF targets."""
        if not url_str:
            return ""
        cleaned = url_str.strip()
        if not cleaned:
            return ""
        if len(cleaned) > 512:
            raise ValueError("Snapshot URL exceeds 512 characters.")
        parsed = urllib.parse.urlparse(cleaned)
        if parsed.scheme.lower() not in {"http", "https"}:
            raise ValueError("Snapshot URL must use http:// or https:// scheme.")
        if not parsed.hostname:
            raise ValueError("Snapshot URL must contain a valid hostname or IP.")

        host = parsed.hostname
        try:
            addr_info = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise ValueError(f"Snapshot host '{host}' could not be resolved safely.") from exc

        if not addr_info:
            raise ValueError(f"Snapshot host '{host}' resolved to no addresses.")
        for _, _, _, _, sockaddr in addr_info:
            ip_candidate = ipaddress.ip_address(sockaddr[0])
            _validate_target_network_ip(ip_candidate)

        return cleaned

    @staticmethod
    def validate_device_id(device_id: str) -> str:
        """Validates device_id identifier format and protects simulator IDs."""
        cleaned = (device_id or "").strip()
        if not DEVICE_ID_RE.match(cleaned):
            raise ValueError("device_id must be 2-48 alphanumeric/._- characters starting with alphanumeric.")
        if cleaned in SIMULATED_DEFAULT_DEVICE_IDS:
            raise ValueError(f"'{cleaned}' is reserved for simulated virtual containers.")
        return cleaned

    def sanitize_device_for_api(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Returns a safe API representation omitting token hashes and masking URL credentials."""
        sanitized = {k: v for k, v in record.items() if k != "token_hash"}
        sanitized["blocked"] = bool(sanitized.get("blocked", 0))
        sanitized["snapshot_configured"] = bool(sanitized.get("snapshot_url"))
        sanitized["snapshot_url"] = _mask_url_credentials(str(sanitized.get("snapshot_url") or ""))
        return sanitized

    def register_device(
        self,
        device_id: str,
        name: str,
        device_type: str,
        protocol: str,
        ip_address: str,
        port: int,
        mqtt_topic: Optional[str] = None,
        snapshot_url: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Validates and persists a new real-world IoT device with a per-device ingest secret."""
        clean_id = self.validate_device_id(device_id)
        clean_name = (name or "").strip()[:80]
        if not clean_name:
            raise ValueError("Device display name is required.")

        clean_type = (device_type or "").strip().lower()
        if clean_type not in ALLOWED_DEVICE_TYPES:
            raise ValueError(f"Unsupported device_type '{device_type}'. Allowed: {', '.join(sorted(ALLOWED_DEVICE_TYPES))}")

        clean_proto = (protocol or "").strip().lower()
        if clean_proto not in ALLOWED_PROTOCOLS:
            raise ValueError(f"Unsupported protocol '{protocol}'. Allowed: {', '.join(sorted(ALLOWED_PROTOCOLS))}")

        clean_ip = self.validate_device_ip(ip_address)
        clean_port = int(port)
        if not (1 <= clean_port <= 65535):
            raise ValueError("Port must be between 1 and 65535.")

        clean_topic = (mqtt_topic or "").strip()
        if clean_topic:
            if not MQTT_TOPIC_RE.match(clean_topic) or ".." in clean_topic:
                raise ValueError("Invalid MQTT topic format.")
        elif clean_proto == "mqtt":
            clean_topic = f"home/devices/{clean_id}"

        clean_snapshot = self.validate_snapshot_url(snapshot_url)

        # Generate per-device secret token; only SHA-256 hash is stored in SQLite
        raw_token = secrets.token_urlsafe(24)
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        now = time.time()

        record: Dict[str, Any] = {
            "device_id": clean_id,
            "name": clean_name,
            "device_type": clean_type,
            "protocol": clean_proto,
            "ip_address": clean_ip,
            "port": clean_port,
            "mqtt_topic": clean_topic,
            "snapshot_url": clean_snapshot,
            "token_hash": token_hash,
            "blocked": 0,
            "status": "MONITORING",
            "last_seen": None,
            "last_payload": "",
            "created_at": now,
        }
        self.db.upsert_device(record)
        logger.info("Registered real IoT device '%s' (%s @ %s:%d)", clean_id, clean_type, clean_ip, clean_port)

        api_record = self.sanitize_device_for_api(record)
        api_record["ingest_token"] = raw_token
        return api_record

    def list_devices(self) -> List[Dict[str, Any]]:
        return [self.sanitize_device_for_api(dev) for dev in self.db.list_devices()]

    def get_device(self, device_id: str) -> Optional[Dict[str, Any]]:
        rec = self.db.get_device(device_id, include_secret=False)
        return self.sanitize_device_for_api(rec) if rec else None

    def delete_device(self, device_id: str) -> bool:
        return self.db.delete_device(device_id)

    def verify_ingest_token(self, device_id: str, supplied_token: str) -> bool:
        """Constant-time validation of per-device X-Device-Token header."""
        rec = self.db.get_device(device_id, include_secret=True)
        if not rec or not supplied_token:
            return False
        expected_hash = str(rec.get("token_hash") or "")
        supplied_hash = hashlib.sha256(supplied_token.strip().encode("utf-8")).hexdigest()
        return hmac.compare_digest(expected_hash, supplied_hash)

    def record_device_telemetry(self, device_id: str, payload_text: str) -> Optional[Dict[str, Any]]:
        """Updates device last_seen and payload snippet when online telemetry arrives."""
        rec = self.db.get_device(device_id, include_secret=False)
        if not rec:
            return None
        if rec.get("blocked"):
            return self.sanitize_device_for_api(rec)

        now = time.time()
        clipped_payload = (payload_text or "")[:1000]
        self.db.update_device_telemetry(
            device_id=device_id,
            status="ONLINE",
            last_seen=now,
            last_payload=clipped_payload,
        )
        updated = self.db.get_device(device_id, include_secret=False)
        return self.sanitize_device_for_api(updated) if updated else None

    def match_mqtt_message(self, topic: str, raw_payload: str) -> Tuple[Optional[Dict[str, Any]], bool]:
        """
        Inspects an incoming MQTT topic/payload.
        Returns (matched_registered_device_or_None, is_default_simulator_message).
        """
        payload_device_id = ""
        payload_ip = ""
        try:
            parsed = json.loads(raw_payload)
            if isinstance(parsed, dict):
                payload_device_id = str(parsed.get("device_id") or "").strip()
                payload_ip = str(parsed.get("src_ip") or parsed.get("ip_address") or "").strip()
        except (ValueError, TypeError):
            pass

        is_sim_default = payload_device_id in SIMULATED_DEFAULT_DEVICE_IDS

        for dev in self.db.list_devices():
            if payload_device_id and dev["device_id"] == payload_device_id:
                return self.sanitize_device_for_api(dev), False
            if dev.get("mqtt_topic") and dev["mqtt_topic"] == topic and not is_sim_default:
                return self.sanitize_device_for_api(dev), False
            if payload_ip and dev.get("ip_address") == payload_ip and not is_sim_default:
                return self.sanitize_device_for_api(dev), False

        return None, is_sim_default

    async def probe_device(self, device_id: str) -> Optional[Dict[str, Any]]:
        """Performs a non-blocking TCP handshake health check without OS subprocess calls."""
        rec = self.db.get_device(device_id, include_secret=False)
        if not rec:
            return None

        if rec.get("blocked"):
            return self.sanitize_device_for_api(rec)

        ip = str(rec["ip_address"])
        port = int(rec["port"])
        reachable = False
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=1.5)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            reachable = True
        except (OSError, asyncio.TimeoutError):
            reachable = False

        new_status = "ONLINE" if reachable else "UNREACHABLE"
        self.db.update_device_telemetry(
            device_id=device_id,
            status=new_status,
            last_seen=time.time() if reachable else None,
        )
        updated = self.db.get_device(device_id, include_secret=False)
        return self.sanitize_device_for_api(updated) if updated else None

    def fetch_snapshot_sync(self, device_id: str) -> Tuple[bytes, str]:
        """
        Synchronously fetches a bounded HTTP/HTTPS snapshot frame for a registered camera
        using runtime SSRF re-validation, no redirects, size cap, and magic-byte inspection.
        """
        rec = self.db.get_device(device_id, include_secret=False)
        if not rec:
            raise KeyError(f"Device '{device_id}' not found.")
        if rec.get("blocked"):
            raise PermissionError("Device ingestion is currently blocked/quarantined.")

        raw_url = str(rec.get("snapshot_url") or "")
        if not raw_url:
            raise ValueError("No HTTP/HTTPS snapshot URL is configured for this device.")

        # Re-validate resolved host at request time to prevent DNS rebinding SSRF
        validated_url = self.validate_snapshot_url(raw_url)
        parsed = urllib.parse.urlparse(validated_url)

        # Strip embedded userinfo from target URL cleanly before constructing Request
        target_url = validated_url
        auth_header = None
        if parsed.username is not None:
            import base64
            creds = f"{urllib.parse.unquote(parsed.username)}:{urllib.parse.unquote(parsed.password or '')}"
            b64_creds = base64.b64encode(creds.encode("utf-8")).decode("ascii")
            auth_header = f"Basic {b64_creds}"
            netloc = f"{parsed.hostname}:{parsed.port}" if parsed.port else (parsed.hostname or "")
            target_url = urllib.parse.urlunparse((parsed.scheme, netloc, parsed.path, parsed.params, parsed.query, ""))

        req = urllib.request.Request(
            target_url,
            headers={"User-Agent": "IoTDefenseSOC-SnapshotProxy/2.0"},
            method="GET",
        )
        if auth_header:
            req.add_header("Authorization", auth_header)

        opener = urllib.request.build_opener(_NoRedirectHandler())
        try:
            with opener.open(req, timeout=3.0) as resp:
                declared_ct = resp.headers.get("Content-Type", "")
                raw_bytes = resp.read(MAX_SNAPSHOT_BYTES + 1)
                if len(raw_bytes) > MAX_SNAPSHOT_BYTES:
                    raise ValueError("Camera snapshot exceeded maximum 2 MB size limit.")
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Camera snapshot unreachable: {exc.reason}") from exc

        detected = _detect_image_content_type(raw_bytes, declared_ct)
        if detected == "multipart/jpeg_stream":
            frame = _extract_first_jpeg_frame(raw_bytes)
            if not frame:
                raise ValueError("Camera MJPEG stream yielded no complete JPEG frame.")
            return frame, "image/jpeg"
        if not detected:
            raise ValueError("Camera endpoint did not return a valid image (JPEG/PNG/GIF/WEBP).")
        return raw_bytes, detected

    def block_device(self, device_id: str, detector: Any, reason: str = "Operator logical quarantine") -> Dict[str, Any]:
        """Logically quarantines a physical IoT device, drops ingestion, and logs audit history."""
        rec = self.db.get_device(device_id, include_secret=False)
        if not rec:
            raise KeyError(f"Device '{device_id}' not found.")

        self.db.set_device_blocked(device_id, blocked=True, status="QUARANTINED")
        src_ip = str(rec["ip_address"])

        # Apply kernel DROP if non-allowlisted; always record logical quarantine in audit DB
        if not detector.allowlist.is_ip_protected(src_ip):
            detector.firewall.ban_ip(src_ip)

        mit_record = MitigationRecord(
            src_ip=src_ip,
            action="DEVICE_BLOCKED",
            reason=f"{reason} (Device: {rec['name']} [{device_id}])",
            severity="HIGH",
        )
        mit_record.id = self.db.record_mitigation(mit_record)

        updated = self.db.get_device(device_id, include_secret=False)
        return {
            "device": self.sanitize_device_for_api(updated) if updated else self.sanitize_device_for_api(rec),
            "mitigation": mit_record.to_dict(),
        }

    def unblock_device(self, device_id: str, detector: Any, admin_user: str = "soc_admin") -> Dict[str, Any]:
        """Restores ingestion for a logically quarantined physical IoT device."""
        rec = self.db.get_device(device_id, include_secret=False)
        if not rec:
            raise KeyError(f"Device '{device_id}' not found.")

        self.db.set_device_blocked(device_id, blocked=False, status="MONITORING")
        src_ip = str(rec["ip_address"])
        if detector.firewall.is_ip_banned(src_ip):
            detector.firewall.unban_ip(src_ip)

        mit_record = MitigationRecord(
            src_ip=src_ip,
            action="DEVICE_RESTORED",
            reason=f"Restored by {admin_user} (Device: {rec['name']} [{device_id}])",
            severity="LOW",
        )
        mit_record.id = self.db.record_mitigation(mit_record)

        updated = self.db.get_device(device_id, include_secret=False)
        return {
            "device": self.sanitize_device_for_api(updated) if updated else self.sanitize_device_for_api(rec),
            "mitigation": mit_record.to_dict(),
        }
