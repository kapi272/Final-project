# Unit 04: FastAPI Telemetry Engine & SSE Streaming API

## Goal
Build the asynchronous FastAPI backend server exposing REST control endpoints and a persistent, non-buffering Server-Sent Events (SSE) telemetry stream (`/api/stream`). Wire the background honeypot log tailing loop into the FastAPI lifespan to broadcast intrusions, firewall mitigations, and container quarantine transitions in real time.

## Design & Architecture Invariants
- **Non-Buffering SSE Stream:** Ensure exact headers (`Cache-Control: no-cache`, `Connection: keep-alive`, `X-Accel-Buffering: no`) for sub-second visual updates without chunk buffering.
- **Consistent API Response Shape:** All REST responses must conform to:
  ```json
  {
    "status": "success" | "error",
    "timestamp": 1718000000.0,
    "data": {},
    "message": ""
  }
  ```
- **Unidirectional Telemetry:** Web clients consume `/api/stream` read-only. State mutations are accepted exclusively via authenticated or local REST POST actions (`/api/defense/unban`, `/api/defense/reset-bans`, `/api/simulate/infect/{node_id}`).
- **Asynchronous Lifespan Management:** Background workers (`HoneypotLogTailer`) must start on FastAPI lifespan startup and gracefully cancel on shutdown.

## Implementation

### 1. `controller/api/sse_broker.py`
- Class `SSEBroadcaster`:
  - Maintains client subscriber queues (`asyncio.Queue`).
  - Method `subscribe() -> asyncio.Queue`: registers a new connected web client.
  - Method `unsubscribe(queue: asyncio.Queue)`: removes disconnected client.
  - Method `broadcast(event_type: str, data: Dict[str, Any])`: publishes typed SSE events (`heartbeat`, `honeypot_hit`, `mitigation_alert`, `node_status`).

### 2. `controller/api/routes.py`
- FastAPI APIRouter:
  - `GET /api/health`: system uptime and service statuses.
  - `GET /api/defense/status`: active drop rules, ban counts, recent history, node statuses.
  - `GET /api/stream`: `StreamingResponse` yielding SSE frames (`event: <type>\ndata: <json>\n\n`).
  - `POST /api/defense/unban`: removes specific IP from firewall and database.
  - `POST /api/defense/reset-bans`: flushes all blocklist rules.
  - `POST /api/simulate/infect/{node_id}`: dynamic containment test calling `quarantine_container`.
  - `POST /api/simulate/restore/{node_id}`: restores container to production network.

### 3. `controller/api/app.py`
- Main FastAPI application factory configuring lifespan, CORS, static file mounts, and routers.

## Dependencies
- `fastapi>=0.110.0`
- `uvicorn>=0.28.0`
- `pydantic>=2.0.0`

## Verify when done
- [x] SSE broadcaster registers and unregisters client queues cleanly.
- [x] `/api/stream` outputs proper SSE format with non-buffering headers.
- [x] All REST endpoints return consistent JSON schema `{status, timestamp, data, message}`.
- [x] Unit 04 test suite passes.
