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
- `controller/core/` — Contains the internal detection state machine, sliding-window log analysis, safety allowlists, and mitigation rules.
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

- **File-Based Telemetry Logs (`honeypot/logs/cowrie.json`)**: Persistent JSON lines appended by Cowrie; consumed via an asynchronous file-pointer tailer in Python.
- **In-Memory Tracking State (`controller/core/state.py`)**: Ephemeral sliding windows (`collections.deque`), active ban set, and runtime node health metrics kept in RAM for sub-millisecond evaluation.
- **Embedded Database (`data/defense_history.db`)**: Lightweight SQLite database tracking persistent mitigation audit logs, banned IPs, timestamps, threat severity levels, and manual unban events.

## Auth and Access Model

- **Dashboard Access:** Open local binding (`127.0.0.1:8000` / `:8050` or private management LAN) without external exposure.
- **Honeypot Decoy Authentication:** Intentionally exposes weak/standard IoT credentials (e.g., `root:root`, `admin:admin`, `admin:123456`) to capture credential stuffing.
- **Controller System Privileges:** The `defense_controller` container communicates with the Docker Engine via `/var/run/docker.sock` to orchestrate network attachments and disconnects. Firewall drop enforcement is executed with `NET_ADMIN` capabilities on the gateway interface.
- **Red-Team Simulation API (`/api/simulate/attack/{type}`, `/api/simulate/attack/pools`):** Accepts single explicit IPs validated via Python's `ipaddress` module, randomized/rotated RFC 5737 TEST-NET pool IPs, or multi-IP distributed swarm bursts (`mode: "swarm"`), while enforcing allowlist rejection on protected addresses.

## Invariants

1. **Firewall Chain Isolation:** The controller must never flush or directly alter the primary `INPUT` or `FORWARD` chains. All firewall drop rules must be inserted into the custom sub-chain `IOT_DEFENSE_BLOCKLIST` hooked into `DOCKER-USER`.
2. **Allowlist Non-Negotiable Check:** Under no circumstance can a rule be generated targeting loopback (`127.0.0.1`), subnet gateways (`172.20.0.1`), or configured administrative management IPs.
3. **Decoupled Detection and Mitigation:** The log parser must never synchronously block while executing OS subprocess calls. Mitigations must execute via asynchronous workers or bounded non-blocking calls to prevent queue stalls.
4. **SSE Unidirectional Flow:** The telemetry stream (`/api/stream`) is strictly unidirectional (server-to-client). Web clients cannot mutate firewall state over the stream endpoint.
5. **No Blind Network Disconnects:** Quarantining an infected node must reattach it to `iot_quarantine_net` rather than leaving it networkless, enabling continued forensic inspection while preventing lateral movement.
6. **Cross-Platform Parity:** Core architecture logic must rely on Docker API abstraction and containerized networking so that execution behavior is identical across macOS, Linux, and Windows.

