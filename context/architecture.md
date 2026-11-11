# Architecture Context

## Stack

| Layer | Technology | Role |
| :--- | :--- | :--- |
| **Host Virtualization** | Docker Engine & Docker Desktop / Compose | Container orchestration, virtual bridge networking, node isolation |
| **Backend Service** | Python 3.11 + FastAPI + Uvicorn | Async web server, honeypot log streaming, telemetry aggregation, SSE broker |
| **Deception Core** | Cowrie Honeypot (Medium Interaction) | Emulates vulnerable SSH (2222) and Telnet (2223), captures credential attacks |
| **Messaging Bus** | Eclipse Mosquitto (MQTT v2.0) | Pub/sub message broker routing legitimate virtual sensor and actuator traffic |
| **Mitigation & Firewall** | Linux Netfilter (`iptables`) / Alpine Gateway | Drops malicious ingress traffic at container gateway (`DOCKER-USER` / custom chain) |
| **Container Controller** | Docker Python SDK (`docker-py`) | Dynamic network detachment/attachment via `/var/run/docker.sock` |
| **Telemetry UI** | HTML5, Tailwind CSS, Native Vanilla JS | Real-time security dashboard consuming unidirectional Server-Sent Events (SSE) |

## System Boundaries

- `simulators/` — Houses lightweight Python container images simulating legitimate IoT nodes (temperature sensor, smart bulb). They have zero defense logic and only publish standard telemetry to the broker.
- `honeypot/` — Contains Cowrie honeypot configuration (`cowrie.cfg`), download traps, and JSON log volumes shared read-only with the controller.
- `controller/core/` — Contains the internal detection state machine, sliding-window log analysis, `log_tailer.py` (inode/rotation-resilient Cowrie JSONL tailer), `device_manager.py` (`RealDeviceManager` for physical/external IoT & CCTV registration, SSRF-guarded HTTP/MJPEG snapshot proxy, non-shell TCP health probing, and logical device quarantine), safety allowlists, and mitigation rules.
- `controller/mitigation/` — Contains isolated drivers for external execution: `firewall.py` (packet drop rules) and `quarantine.py` (Docker Engine socket network management).
- `controller/api/` — Houses FastAPI router definitions, SSE client subscriber queue pool, and event dispatchers.
- `controller/templates/` & `controller/static/` — Holds the single-page dashboard layout and static styling/scripts.
- `tests/` — Automated adversary test scripts (`attacker_sim.py`) simulating scans and brute-force events.

## Network Topology & Subnets

              [ Host External Interface / Local Attacker ]
                                  │
                                  ▼
                    [ iptables: DOCKER-USER ]
                                  │
          ┌───────────────────────┴───────────────────────┐
          ▼                                               ▼
[ iot_production_net ]                          [ iot_quarantine_net ]
(172.20.0.0/24)                                 (172.21.0.0/24)

Gateway: 172.20.0.1                           - Internal: true (No Gateway)

MQTT Broker:  172.20.0.10                     - Isolated from host and internet

Temp Sensor:  172.20.0.21                     - Destination for compromised nodes

Smart Bulb:   172.20.0.22

Honeypot:     172.20.0.50 (Decoy)


## Storage Model

- **File-Based Telemetry Logs (`honeypot/logs/cowrie.json`)**: Persistent JSON lines appended by Cowrie; consumed via an asynchronous inode-aware file-pointer tailer (`HoneypotLogTailer`) that automatically reopens rotated logs (`cowrie.json.*`).
- **In-Memory Tracking State (`controller/core/state.py`)**: Ephemeral sliding windows (`collections.deque`), active ban set, and runtime node health metrics kept in RAM for sub-millisecond evaluation.
- **Embedded Database (`data/defense_history.db`)**: Lightweight SQLite database tracking persistent mitigation audit logs (`mitigations`), persistent controller mode settings (`system_settings`: `traffic_mode` `"simulated"` | `"live"`), and external physical device definitions (`registered_devices` with SHA-256 `token_hash` and redacted metadata).

## Auth and Access Model

- **Dashboard Access:** Open local binding (`127.0.0.1:8000` / `:8050` or private management LAN) with configurable `ALLOWED_ORIGINS` CORS policy, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and `Cache-Control: no-store` on dynamic/snapshot assets.
- **Real-Device Webhook Authentication (`/api/devices/ingest/{device_id}`):** Per-device 24-byte URL-safe `ingest_token` issued once at registration, stored exclusively as SHA-256 `token_hash`, verified via constant-time `hmac.compare_digest` against the `X-Device-Token` header. Quarantined devices are rejected with HTTP `403`.
- **Honeypot Decoy Authentication:** Intentionally exposes weak/standard IoT credentials (e.g., `root:root`, `admin:admin`, `admin:123456`) to capture credential stuffing.
- **Controller System Privileges:** The `defense_controller` container communicates with the Docker Engine via `/var/run/docker.sock` to orchestrate network attachments and disconnects. Firewall drop enforcement is executed with `NET_ADMIN` capabilities on the gateway interface.
- **Traffic Mode & Simulation Guard (`/api/system/mode`, `/api/simulate/*`):** `traffic_mode` toggles strictly between `"simulated"` (virtual nodes & Red Team toolbar active) and `"live"` (mock node telemetry filtered, simulation endpoints return HTTP `409 Conflict`, Real Device Registry & 15s TCP health poll active). Switching modes broadcasts `mode_changed` over SSE; device lifecycle broadcasts `device_registered`, `device_updated`, `device_deleted`, and `device_telemetry_blocked`.
- **Red-Team Simulation API (`/api/simulate/attack/{type}`, `/api/simulate/attack/pools`):** Accepts single explicit IPs validated via Python's `ipaddress` module, randomized/rotated RFC 5737 TEST-NET pool IPs, or multi-IP distributed swarm bursts (`mode: "swarm"`), while enforcing allowlist rejection on protected addresses.
- **SSRF Protection (`RealDeviceManager`):** Rejects loopback, `169.254.0.0/16` metadata/link-local, multicast, unspecified, and Docker controller/gateway targets (`172.20.0.1`, `172.20.0.5`, `172.21.0.1`, `172.21.0.5`, `192.168.65.1`); resolves hostnames prior to HTTP snapshot fetching; blocks HTTP redirects; enforces a 2 MB byte cap and JPEG/PNG/GIF/WEBP/MJPEG magic-byte verification.

## Invariants

1. **Firewall Chain Isolation:** The controller must never flush or directly alter the primary `INPUT` or `FORWARD` chains. All firewall drop rules must be inserted into the custom sub-chain `IOT_DEFENSE_BLOCKLIST` hooked into `DOCKER-USER`.
2. **Allowlist Non-Negotiable Check:** Under no circumstance can a rule be generated targeting loopback (`127.0.0.1`), subnet gateways (`172.20.0.1`), or configured administrative management IPs.
3. **Decoupled Detection and Mitigation:** The log parser must never synchronously block while executing OS subprocess calls. Mitigations must execute via asynchronous workers or bounded non-blocking calls to prevent queue stalls.
4. **SSE Unidirectional Flow:** The telemetry stream (`/api/stream`) is strictly unidirectional (server-to-client). Web clients cannot mutate firewall state over the stream endpoint.
5. **No Blind Network Disconnects:** Quarantining an infected node must reattach it to `iot_quarantine_net` rather than leaving it networkless, enabling continued forensic inspection while preventing lateral movement.
6. **Cross-Platform Parity:** Core architecture logic must rely on Docker API abstraction and containerized networking so that execution behavior is identical across macOS, Linux, and Windows.

