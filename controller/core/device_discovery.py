import asyncio
import ipaddress
import logging
import os
import re
import socket
import time
import urllib.parse
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# ONVIF WS-Discovery multicast target and default probe
ONVIF_DISCOVERY_ADDR: str = "239.255.255.250"
ONVIF_DISCOVERY_PORT: int = 3702
MDNS_DISCOVERY_ADDR: str = "224.0.0.251"
MDNS_DISCOVERY_PORT: int = 5353

ONVIF_PROBE_XML: str = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<Envelope xmlns="http://www.w3.org/2003/05/soap-envelope" '
    'xmlns:dn="http://www.onvif.org/ver10/network/wsdl" '
    'xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">'
    '<Header>'
    '<wsa:MessageID>uuid:84ede3de-7da5-466e-ae88-92445e35222c</wsa:MessageID>'
    '<wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>'
    '<wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>'
    '</Header>'
    '<Body>'
    '<Probe xmlns="http://schemas.xmlsoap.org/ws/2005/04/discovery">'
    '<Types>dn:NetworkVideoTransmitter</Types>'
    '</Probe>'
    '</Body>'
    '</Envelope>'
)

BLOCKED_SUBNETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("172.20.0.0/16"),
    ipaddress.ip_network("172.21.0.0/16"),
]

PROTECTED_DISCOVERY_IPS = {
    ipaddress.ip_address("172.20.0.1"),
    ipaddress.ip_address("172.20.0.5"),
    ipaddress.ip_address("172.21.0.1"),
    ipaddress.ip_address("172.21.0.5"),
    ipaddress.ip_address("192.168.65.1"),
}

COMMON_IOT_PORTS = [
    (554, "rtsp", "cctv_camera", "rtsp_http"),
    (8080, "http_cam", "cctv_camera", "rtsp_http"),
    (8081, "mjpeg_cam", "cctv_camera", "rtsp_http"),
    (8000, "cctv_web", "cctv_camera", "rtsp_http"),
    (4747, "droidcam", "cctv_camera", "rtsp_http"),
    (8888, "http_cam", "cctv_camera", "rtsp_http"),
    (1883, "mqtt", "iot_sensor", "mqtt"),
    (80, "http_web", "iot_sensor", "http_webhook"),
    (5000, "iot_rest", "iot_sensor", "http_webhook"),
]


def validate_discovery_ip(ip_str: str) -> ipaddress._BaseAddress:
    """Validates an IP address and blocks loopback, cloud metadata, and internal Docker networks."""
    ip_obj = ipaddress.ip_address(ip_str.strip())
    if ip_obj.is_loopback:
        raise ValueError(f"Loopback IP '{ip_obj}' is blocked for LAN discovery.")
    if ip_obj.is_link_local:
        raise ValueError(f"Link-local/metadata IP '{ip_obj}' is blocked by SSRF policy.")
    if ip_obj.is_multicast or ip_obj.is_unspecified:
        raise ValueError(f"Special IP '{ip_obj}' is not a valid target host.")
    if ip_obj in PROTECTED_DISCOVERY_IPS:
        raise ValueError(f"Infrastructure IP '{ip_obj}' is reserved and protected.")
    for blocked in BLOCKED_SUBNETS:
        if ip_obj in blocked:
            raise ValueError(f"IP '{ip_obj}' falls into blocked network '{blocked}'.")
    return ip_obj


def parse_onvif_response(xml_bytes: bytes) -> Optional[Dict[str, Any]]:
    """Parses an ONVIF WS-Discovery ProbeMatches SOAP XML response."""
    try:
        raw_text = xml_bytes.decode("utf-8", errors="replace")
        # Extract XAddrs using regex to handle varying XML namespaces cleanly
        xaddrs_match = re.search(r"<(?:[a-zA-Z0-9_-]+:)?XAddrs>([^<]+)</(?:[a-zA-Z0-9_-]+:)?XAddrs>", raw_text)
        scopes_match = re.search(r"<(?:[a-zA-Z0-9_-]+:)?Scopes>([^<]+)</(?:[a-zA-Z0-9_-]+:)?Scopes>", raw_text)

        if not xaddrs_match:
            return None

        urls = xaddrs_match.group(1).strip().split()
        if not urls:
            return None

        # Pick primary URL
        primary_url = urls[0]
        parsed = urllib.parse.urlparse(primary_url)
        ip_str = parsed.hostname
        if not ip_str:
            return None

        # Validate IP against SSRF policy
        validate_discovery_ip(ip_str)

        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        scopes = scopes_match.group(1).strip() if scopes_match else ""

        # Attempt to extract hardware model / name from ONVIF scopes
        camera_name = f"ONVIF Camera ({ip_str})"
        for item in scopes.split():
            if "name/" in item:
                camera_name = urllib.parse.unquote(item.split("name/")[-1]).replace("_", " ")
                break
            elif "hardware/" in item:
                camera_name = urllib.parse.unquote(item.split("hardware/")[-1]).replace("_", " ")

        device_id = f"cam_{ip_str.replace('.', '_')}"
        snapshot_url = f"http://{ip_str}:{port}/onvif/snapshot"

        return {
            "device_id": device_id,
            "name": camera_name,
            "device_type": "cctv_camera",
            "protocol": "rtsp_http",
            "ip_address": ip_str,
            "port": 554,  # RTSP media port standard for ONVIF cameras
            "snapshot_url": snapshot_url,
            "discovery_method": "onvif_ws_discovery",
            "details": f"ONVIF Service: {primary_url}",
        }
    except Exception as e:
        logger.debug("Failed to parse ONVIF XML response: %s", e)
        return None


async def discover_onvif_cameras(timeout: float = 2.0) -> List[Dict[str, Any]]:
    """Sends ONVIF WS-Discovery probe via UDP multicast and collects camera responses."""
    discovered: List[Dict[str, Any]] = []
    seen_ips: Set[str] = set()

    loop = asyncio.get_running_loop()

    def _sync_onvif_probe() -> List[Dict[str, Any]]:
        results = []
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.settimeout(timeout)
        try:
            # Set TTL for local subnet multicast
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            sock.sendto(ONVIF_PROBE_XML.encode("utf-8"), (ONVIF_DISCOVERY_ADDR, ONVIF_DISCOVERY_PORT))
            start = time.time()
            while time.time() - start < timeout:
                try:
                    data, addr = sock.recvfrom(65535)
                    dev = parse_onvif_response(data)
                    if dev and dev["ip_address"] not in seen_ips:
                        seen_ips.add(dev["ip_address"])
                        results.append(dev)
                except socket.timeout:
                    break
                except Exception:
                    break
        except Exception as e:
            logger.debug("ONVIF multicast discovery error: %s", e)
        finally:
            sock.close()
        return results

    try:
        discovered = await loop.run_in_executor(None, _sync_onvif_probe)
    except Exception as e:
        logger.warning("Async ONVIF discovery failed: %s", e)

    return discovered


async def probe_single_host_port(ip: str, port: int, timeout: float = 0.5) -> bool:
    """Non-blocking TCP handshake check for a single IP and port."""
    try:
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False


class DiscoveredDeviceList(list):
    """List of discovered devices annotated with scanned_subnet."""
    def __init__(self, iterable: Optional[Any] = None, scanned_subnet: str = "") -> None:
        super().__init__(iterable or [])
        self.scanned_subnet = scanned_subnet


def get_local_lan_ip() -> Optional[str]:
    """Determines the primary outbound LAN IPv4 address of the host."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return None


def get_discovery_subnets_info(
    db: Optional[Any] = None,
    client_host: Optional[str] = None,
) -> Tuple[str, List[str]]:
    """
    Returns (default_subnet, candidate_subnets) for LAN device auto-discovery.
    Dynamically identifies valid private LAN subnets while strictly rejecting Docker internal networks.
    """
    candidates: List[str] = []

    def _add_if_valid(subnet_str: Optional[str]) -> None:
        if not subnet_str or not isinstance(subnet_str, str):
            return
        cleaned = subnet_str.strip()
        try:
            net = ipaddress.ip_network(cleaned, strict=False)
            if (
                net.is_private
                and not any(net.overlaps(b) for b in BLOCKED_SUBNETS)
                and not net.overlaps(ipaddress.ip_network("192.168.65.0/24"))
            ):
                net_str = f"{net.network_address}/{net.prefixlen}"
                if net_str not in candidates:
                    candidates.append(net_str)
        except Exception:
            pass

    # 1. Host LAN subnet passed via environment variable (e.g. from docker-compose / host)
    env_sub = os.environ.get("HOST_LAN_SUBNET") or os.environ.get("LAN_SUBNET")
    _add_if_valid(env_sub)

    # 2. Database registered devices (if real hardware was previously registered)
    if db and hasattr(db, "list_devices"):
        try:
            for dev in db.list_devices():
                ip_str = dev.get("ip_address")
                if ip_str:
                    try:
                        ip_obj = ipaddress.ip_address(str(ip_str).strip())
                        if ip_obj.is_private and not any(ip_obj in b for b in BLOCKED_SUBNETS) and not ip_obj.is_loopback:
                            octets = str(ip_obj).split(".")
                            _add_if_valid(f"{octets[0]}.{octets[1]}.{octets[2]}.0/24")
                    except Exception:
                        pass
        except Exception:
            pass

    # 3. Client host IP from HTTP request if connected from real LAN host
    if client_host:
        try:
            ip_obj = ipaddress.ip_address(str(client_host).strip())
            if ip_obj.is_private and not any(ip_obj in b for b in BLOCKED_SUBNETS) and not ip_obj.is_loopback:
                octets = str(ip_obj).split(".")
                _add_if_valid(f"{octets[0]}.{octets[1]}.{octets[2]}.0/24")
        except Exception:
            pass

    # 4. Outbound socket IP (if physical host and not Docker bridge)
    local_ip = get_local_lan_ip()
    if local_ip:
        try:
            ip_obj = ipaddress.ip_address(str(local_ip).strip())
            if ip_obj.is_private and not any(ip_obj in b for b in BLOCKED_SUBNETS) and not ip_obj.is_loopback:
                octets = str(ip_obj).split(".")
                _add_if_valid(f"{octets[0]}.{octets[1]}.{octets[2]}.0/24")
        except Exception:
            pass

    # 5. Standard common RFC 1918 LAN subnets
    for fallback in ["192.168.1.0/24", "192.168.0.0/24", "10.0.0.0/24", "192.168.43.0/24"]:
        if fallback not in candidates:
            candidates.append(fallback)

    default_subnet = candidates[0] if candidates else "192.168.1.0/24"
    return default_subnet, candidates


def get_default_discovery_subnet(db: Optional[Any] = None, client_host: Optional[str] = None) -> str:
    """Returns the default auto-detected LAN subnet string."""
    default_sub, _ = get_discovery_subnets_info(db=db, client_host=client_host)
    return default_sub


async def scan_lan_subnet(
    subnet_cidr: Optional[str] = None,
    timeout: float = 0.35,
    max_hosts: int = 254,
    db: Optional[Any] = None,
    client_host: Optional[str] = None,
) -> Tuple[str, List[Dict[str, Any]]]:
    """
    Performs a fast concurrent TCP sweep across a LAN subnet for open CCTV & IoT ports.
    Respects strict SSRF boundaries. Returns (scanned_subnet_cidr, discovered_devices).
    """
    if not subnet_cidr or not str(subnet_cidr).strip():
        subnet_cidr = get_default_discovery_subnet(db=db, client_host=client_host)

    try:
        net = ipaddress.ip_network(str(subnet_cidr).strip(), strict=False)
    except Exception as e:
        raise ValueError(f"Invalid subnet CIDR '{subnet_cidr}': {e}")

    # Check that subnet is not in blocked ranges
    for blocked in BLOCKED_SUBNETS:
        if net.overlaps(blocked):
            raise ValueError(f"Subnet '{subnet_cidr}' overlaps with blocked network '{blocked}'.")

    resolved_cidr = f"{net.network_address}/{net.prefixlen}"
    hosts = list(net.hosts())[:max_hosts]
    sem = asyncio.Semaphore(100)

    async def _check_host_port(ip_str: str, port_info: Tuple[int, str, str, str]) -> Optional[Dict[str, Any]]:
        port, label, dev_type, proto = port_info
        async with sem:
            is_open = await probe_single_host_port(ip_str, port, timeout=timeout)
        if not is_open:
            return None

        device_id = f"{label}_{ip_str.replace('.', '_')}"
        snapshot_url = ""
        if dev_type == "cctv_camera":
            if port == 8080:
                snapshot_url = f"http://{ip_str}:8080/video"
            elif port == 4747:
                snapshot_url = f"http://{ip_str}:4747/video"
            elif port in (80, 8000, 8081, 8888):
                snapshot_url = f"http://{ip_str}:{port}/snapshot.jpg"

        friendly_name = (
            f"LAN IP Camera ({ip_str}:{port})"
            if dev_type == "cctv_camera"
            else f"Smart IoT Node ({ip_str}:{port})"
        )

        return {
            "device_id": device_id,
            "name": friendly_name,
            "device_type": dev_type,
            "protocol": proto,
            "ip_address": ip_str,
            "port": port,
            "snapshot_url": snapshot_url,
            "discovery_method": f"tcp_{label}_probe",
            "details": f"Discovered open TCP port {port} ({label.upper()})",
        }

    async def _scan_host(host_ip: str) -> List[Dict[str, Any]]:
        ip_str = str(host_ip)
        try:
            validate_discovery_ip(ip_str)
        except ValueError:
            return []

        tasks = [_check_host_port(ip_str, p) for p in COMMON_IOT_PORTS]
        port_results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in port_results if isinstance(r, dict) and r]

    all_tasks = [_scan_host(str(h)) for h in hosts]
    completed_hosts = await asyncio.gather(*all_tasks, return_exceptions=True)

    results: List[Dict[str, Any]] = []
    seen_ips: Set[str] = set()

    for host_res in completed_hosts:
        if isinstance(host_res, list) and host_res:
            cctv_matches = [d for d in host_res if d.get("device_type") == "cctv_camera"]
            best = cctv_matches[0] if cctv_matches else host_res[0]
            if best["ip_address"] not in seen_ips:
                seen_ips.add(best["ip_address"])
                results.append(best)

    return resolved_cidr, results


async def run_lan_discovery(
    subnet_cidr: Optional[str] = None,
    timeout: float = 2.0,
    db: Optional[Any] = None,
    client_host: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Executes a comprehensive multi-protocol LAN device discovery:
    1. ONVIF WS-Discovery (UDP 3702) for real IP/CCTV cameras
    2. Concurrent TCP sweeps for active IoT/CCTV ports on the local network
    De-duplicates and merges all discovered records. Returns list with .scanned_subnet metadata.
    """
    discovered_map: Dict[str, Dict[str, Any]] = {}

    onvif_task = discover_onvif_cameras(timeout=min(timeout, 2.0))
    subnet_task = scan_lan_subnet(
        subnet_cidr=subnet_cidr,
        timeout=0.35,
        max_hosts=254,
        db=db,
        client_host=client_host,
    )

    results = await asyncio.gather(onvif_task, subnet_task, return_exceptions=True)

    if isinstance(results[1], Exception):
        if isinstance(results[1], ValueError):
            raise results[1]
        logger.warning("Subnet scan encountered error: %s", results[1])

    if isinstance(results[0], Exception):
        if isinstance(results[0], ValueError):
            raise results[0]
        logger.warning("ONVIF discovery encountered error: %s", results[0])

    onvif_devices = results[0] if isinstance(results[0], list) else []
    scanned_cidr, subnet_devices = (
        results[1] if (isinstance(results[1], tuple) and len(results[1]) == 2)
        else ("", results[1] if isinstance(results[1], list) else [])
    )

    # Prefer rich ONVIF metadata
    for dev in onvif_devices:
        discovered_map[dev["ip_address"]] = dev

    for dev in subnet_devices:
        ip = dev["ip_address"]
        if ip not in discovered_map:
            discovered_map[ip] = dev

    return DiscoveredDeviceList(discovered_map.values(), scanned_subnet=scanned_cidr)
