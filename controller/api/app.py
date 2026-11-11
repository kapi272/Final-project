import asyncio
from contextlib import asynccontextmanager
import logging
import os
from typing import AsyncGenerator, Optional

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from controller.api.routes import router
from controller.api.sse_broker import SSEBroadcaster
from controller.core.db import DefenseDatabase
from controller.core.device_manager import RealDeviceManager
from controller.core.detector import IntrusionDetector
from controller.core.log_tailer import HoneypotLogTailer
from controller.core.models import CowrieEvent, MitigationRecord
from controller.core.mqtt_listener import IoTTelemetryListener
from controller.mitigation.allowlist import AllowlistManager
from controller.mitigation.firewall import FirewallController
from controller.mitigation.quarantine import QuarantineManager

logger = logging.getLogger(__name__)


def create_app(
    detector: Optional[IntrusionDetector] = None,
    quarantine_manager: Optional[QuarantineManager] = None,
    broadcaster: Optional[SSEBroadcaster] = None,
    enable_tailer: bool = True,
    enable_mqtt: bool = False,
    log_path: Optional[str] = None,
    mqtt_host: Optional[str] = None,
    mqtt_port: Optional[int] = None,
) -> FastAPI:
    """Factory function creating and configuring the FastAPI SOC defense server."""

    # Shared singletons
    sse_broadcaster = broadcaster or SSEBroadcaster()
    allowlist = AllowlistManager()
    firewall = FirewallController(allowlist_manager=allowlist)
    db = DefenseDatabase()

    async def on_mitigation_action(record: MitigationRecord) -> None:
        """Callback invoked when autonomous mitigation triggers a firewall ban."""
        await sse_broadcaster.broadcast("mitigation_alert", record.to_dict())

    detector_instance = detector or IntrusionDetector(
        firewall=firewall,
        db=db,
        allowlist=allowlist,
        on_mitigation_callback=lambda r: asyncio.create_task(on_mitigation_action(r)),
    )

    quarantine_instance = quarantine_manager or QuarantineManager()
    device_manager = RealDeviceManager(db=detector_instance.db)
    saved_mode = detector_instance.db.get_setting("traffic_mode", "simulated")
    initial_mode = saved_mode if saved_mode in {"simulated", "live"} else "simulated"

    async def on_honeypot_event(event: CowrieEvent) -> None:
        """Processes each event from the log tailer and broadcasts raw hit over SSE."""
        await sse_broadcaster.broadcast("honeypot_hit", event.to_dict())
        detector_instance.process_event(event)

    tailer_instance = HoneypotLogTailer(
        log_path=log_path or os.path.join("honeypot", "logs", "cowrie.json"),
        on_event_callback=on_honeypot_event,
    )

    async def on_iot_telemetry(topic: str, payload: str, ts: float) -> None:
        """Broadcasts IoT node sensor and actuator MQTT messages filtered by active traffic mode."""
        mode = getattr(app.state, "traffic_mode", "simulated")
        matched_dev, is_sim_default = device_manager.match_mqtt_message(topic, payload)

        if mode == "simulated":
            # In Simulated Mode, stream virtual mesh telemetry only; ignore live registered devices
            if matched_dev is not None:
                return
        else:
            # Strict Live Mode: silence mock container heartbeats and drop quarantined live devices
            if is_sim_default:
                return
            if matched_dev is not None:
                if matched_dev.get("blocked"):
                    await sse_broadcaster.broadcast("device_telemetry_blocked", {
                        "device_id": matched_dev["device_id"],
                        "name": matched_dev["name"],
                        "ip_address": matched_dev["ip_address"],
                        "topic": topic,
                        "channel": "MQTT",
                    })
                    return
                updated = device_manager.record_device_telemetry(matched_dev["device_id"], payload)
                if updated:
                    await sse_broadcaster.broadcast("device_updated", updated)

        await sse_broadcaster.broadcast("iot_telemetry", {
            "topic": topic,
            "payload": payload,
            "timestamp": ts,
            "device_id": matched_dev["device_id"] if matched_dev else None,
            "device_name": matched_dev["name"] if matched_dev else None,
            "mode": mode,
        })

    mqtt_instance = None
    if enable_mqtt:
        mqtt_instance = IoTTelemetryListener(
            broker_host=mqtt_host or os.getenv("MQTT_BROKER_HOST", "172.20.0.10"),
            broker_port=mqtt_port or int(os.getenv("MQTT_BROKER_PORT", "1883")),
            topic="home/#",
            on_message_callback=on_iot_telemetry,
        )

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
        logger.info("Initializing Autonomous IoT Defense Controller backend...")
        # Initialize netfilter chain
        detector_instance.firewall.initialize_chains()

        loop = asyncio.get_running_loop()
        tailer_task = None
        health_task = None
        if enable_tailer:
            tailer_task = asyncio.create_task(tailer_instance.start())
            logger.info("Honeypot background log tailer task launched.")

        async def poll_live_devices() -> None:
            while True:
                try:
                    await asyncio.sleep(15.0)
                    if getattr(app.state, "traffic_mode", "simulated") != "live":
                        continue
                    for dev in device_manager.list_devices():
                        if dev.get("blocked"):
                            continue
                        prev_status = dev.get("status")
                        updated = await device_manager.probe_device(dev["device_id"])
                        if updated and updated.get("status") != prev_status:
                            await sse_broadcaster.broadcast("device_updated", updated)
                except asyncio.CancelledError:
                    break
                except Exception as exc:
                    logger.warning("Background live device probe cycle encountered error: %s", exc)

        if enable_tailer or enable_mqtt:
            health_task = asyncio.create_task(poll_live_devices())

        if mqtt_instance:
            mqtt_instance.start(loop=loop)

        yield

        logger.info("Shutting down Autonomous IoT Defense Controller backend...")
        tailer_instance.stop()
        if mqtt_instance:
            mqtt_instance.stop()
        for task in (tailer_task, health_task):
            if task:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

    app = FastAPI(
        title="Autonomous IoT Cyber Defense System",
        description="Autonomous Netfilter & Container Quarantine SOC Controller",
        version="2.0.0",
        lifespan=lifespan,
    )

    # Attach shared dependencies to app state for route injection
    app.state.detector = detector_instance
    app.state.quarantine_manager = quarantine_instance
    app.state.sse_broadcaster = sse_broadcaster
    app.state.device_manager = device_manager
    app.state.traffic_mode = initial_mode

    # CORS configuration scoped to local management origins (same-origin UI does not require wildcard)
    # TODO(security): Enforce HTTPS origins and operator authentication before exposing port 8050 externally.
    allowed_origins_env = os.getenv("ALLOWED_ORIGINS", "http://localhost:8050,http://127.0.0.1:8050,http://localhost:8000,http://127.0.0.1:8000")
    allowed_origins = [o.strip() for o in allowed_origins_env.split(",") if o.strip()]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["Content-Type", "X-Device-Token"],
    )

    @app.middleware("http")
    async def disable_ui_caching(request: Request, call_next):
        """Prevents stale browser caching and enforces defensive response headers."""
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        if (
            request.url.path == "/"
            or request.url.path.startswith("/static/")
            or request.url.path.endswith("/snapshot")
        ):
            response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
            response.headers["Pragma"] = "no-cache"
        return response

    # Include API routes
    app.include_router(router)

    # Static files & dashboard template support (for Unit 05)
    static_dir = os.path.join(os.path.dirname(__file__), "..", "static")
    templates_dir = os.path.join(os.path.dirname(__file__), "..", "templates")
    os.makedirs(static_dir, exist_ok=True)
    os.makedirs(templates_dir, exist_ok=True)

    app.mount("/static", StaticFiles(directory=static_dir), name="static")

    @app.get("/", response_class=HTMLResponse)
    async def get_dashboard() -> HTMLResponse:
        index_file = os.path.join(templates_dir, "index.html")
        if os.path.exists(index_file):
            with open(index_file, "r", encoding="utf-8") as f:
                return HTMLResponse(content=f.read())
        return HTMLResponse(content="<h1>Autonomous IoT Defense System</h1><p>Dashboard UI initializing...</p>")

    return app

