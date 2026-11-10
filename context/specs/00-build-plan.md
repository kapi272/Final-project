# 00: Autonomous IoT Cyber Defense System — Build Plan

Following the Six-File Context and Spec-Driven Development Methodology, this document breaks the entire build into specific, scoped, verifiable units. Each unit produces one concrete, verifiable result within its system boundary.

---

## Unit Overview & Dependency Graph

```
[Unit 01: Docker Orchestration & Virtual IoT Network]
                        │
                        ▼
[Unit 02: Mitigation Engine (iptables & Docker Quarantine)]
                        │
                        ▼
[Unit 03: Honeypot Ingestion Engine & Detection Core]
                        │
                        ▼
[Unit 04: FastAPI Telemetry Engine & SSE Streaming API]
                        │
                        ▼
[Unit 05: Single-Page Real-Time SOC Dashboard]
                        │
                        ▼
[Unit 06: Red Team Simulation & End-to-End Autonomous Validation]
```

---

## Unit Breakdown

### Unit 01: Docker Orchestration & Virtual IoT Network
- **System Boundary:** Root config, `simulators/`, `honeypot/`, `config/mosquitto/`
- **Output:** `docker-compose.yml`, dual-bridge subnets (`iot_production_net`, `iot_quarantine_net`), running Mosquitto MQTT broker, synthetic IoT sensor and bulb simulators, and containerized Cowrie honeypot decoy.
- **Dependencies:** Docker Engine / Docker Compose.
- **Verification:** `docker-compose up -d` boots all containers; MQTT telemetry flows over topic `home/sensors/temperature`; Cowrie responds on ports 2222/2223.

### Unit 02: Mitigation Engine (Firewall & Docker Quarantine)
- **System Boundary:** `controller/mitigation/`
- **Output:** Parameterized, injection-safe `firewall.py` (idempotent `IOT_DEFENSE_BLOCKLIST` netfilter management) and `quarantine.py` (Docker Python SDK container network migration). Safety allowlist validation (`ipaddress`).
- **Dependencies:** Unit 01 network subnets.
- **Verification:** Unit test / standalone verification script successfully adds and removes an `iptables` drop rule and safely migrates a container between networks without host disconnect.

### Unit 03: Honeypot Ingestion Engine & Detection Core
- **System Boundary:** `controller/core/`
- **Output:** Non-blocking async file-pointer tailer for `cowrie.json`, sliding-window attack frequency evaluator (`collections.deque`), SQLite audit store (`data/defense_history.db`), and autonomous trigger rules (brute-force threshold -> mitigation hook).
- **Dependencies:** Unit 01 (honeypot log volume) & Unit 02 (mitigation hooks).
- **Verification:** Feeding simulated failed login events triggers sub-second classification, allowlist verification, and dispatches a ban action to SQLite and the firewall.

### Unit 04: FastAPI Telemetry Engine & SSE Streaming API
- **System Boundary:** `controller/api/`
- **Output:** FastAPI backend application, non-buffering Server-Sent Events endpoint (`GET /api/stream`), manual unban endpoints (`POST /api/defense/unban`, `POST /api/defense/reset-bans`), and node infection test endpoint (`POST /api/simulate/infect/{node_id}`).
- **Dependencies:** Units 01, 02, and 03.
- **Verification:** `curl -N http://localhost:8000/api/stream` receives live heartbeat and real-time security events; manual unban removes rules idempotently.

### Unit 05: Single-Page Real-Time SOC Dashboard
- **System Boundary:** `controller/templates/`, `controller/static/`
- **Output:** Dark-themed terminal UI adhering to `context/ui-context.md` (slate-900 surface, emerald healthy pills, amber honeypot hits, rose mitigation badges). Real-time topology nodes, live mitigation audit table, and terminal console feed.
- **Dependencies:** Unit 04 (FastAPI backend & SSE stream).
- **Verification:** Browser displays dashboard at `http://localhost:8000`, establishes SSE connection, and reflects real-time attack events and container status transitions dynamically.

### Unit 06: Red Team Simulation & End-to-End Autonomous Validation
- **System Boundary:** `tests/`
- **Output:** Automated red team adversary script (`attacker_sim.py`) executing reconnaissance port scans, SSH/Telnet brute-force dictionary attacks, and rogue container anomaly generation.
- **Dependencies:** Units 01 through 05.
- **Verification:** Running `python tests/attacker_sim.py` triggers autonomous detection and containment in <1,000 ms, verifiable in iptables, Docker network inspect, and the web dashboard simultaneously.

