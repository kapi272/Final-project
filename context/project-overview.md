# Autonomous IoT Cyber Defense System Using Virtual IoT Nodes and Honeypot Technology

## Overview
**Current Release:** v1.1.0 (SOC Terminal `v1.1-SOC`)

This project is an autonomous, containerized host-level IoT cyber defense system. It simulates an enterprise/smart-home IoT environment (sensors, actuators, MQTT broker) on a single physical workstation using isolated virtual networks. By deploying an instrumented deception layer (Cowrie medium-interaction honeypot) directly alongside virtual IoT nodes, the system attracts and analyzes adversarial reconnaissance, brute-force intrusions, and botnet infections without risking physical hardware. An integrated analytics engine evaluates honeypot events and sniffs subnet traffic to autonomously execute closed-loop mitigations—injecting dynamic kernel firewall (`iptables`) drop rules into Docker routing chains and isolating rogue containers into a quarantine bridge network via the Docker Engine API.

## Goals
1. **Zero Hardware Dependency:** Model a multi-node IoT network (MQTT broker, telemetry sensors, smart bulbs) entirely via lightweight Docker containers on a Linux host.
2. **Deterministic Deception:** Deploy an emulated vulnerable IoT decoy (Cowrie exposing SSH on 2222 and Telnet on 2223) on the same virtual subnet to capture adversarial scans and credential stuffing.
3. **Sub-Second Autonomous Mitigation:** Automatically detect honeypot triggers and baseline network anomalies, executing firewall bans (`DOCKER-USER` chain) and Docker network quarantines without human intervention in under 1,000 ms.
4. **Real-Time Deception Telemetry:** Stream intrusion events, mitigation audit trails, and node lifecycle health states to a single-page web dashboard using Server-Sent Events (SSE).

## Core User Flow
1. **System Initialization:** The administrator starts the stack via `docker-compose up -d`. The network manager provisions `iot_production_net` (172.20.0.0/24) and `iot_quarantine_net` (172.21.0.0/24, internal).
2. **Baseline Operations:** Virtual IoT nodes start transmitting synthetic MQTT telemetry to `iot_mqtt_broker` (172.20.0.10). The Cowrie honeypot arms its SSH/Telnet listener on 172.20.0.50.
3. **Live Telemetry Connection:** The administrator accesses the web dashboard at `http://localhost:8000`. The browser initiates an SSE connection (`/api/stream`), populating topology nodes and firewall status cards.
4. **Threat Engagement:** An adversary or automated test script (`attacker_sim.py`) executes a reconnaissance port sweep or credential brute-force attack against the honeypot ports.
5. **Detection & Autonomous Reaction:**
   - Honeypot trigger daemon identifies repeated authentication failures or critical command executions.
   - The Policy Controller validates the source IP against safety allowlists.
   - The controller executes `iptables -I IOT_DEFENSE_BLOCKLIST 1 -s <IP> -j DROP`.
   - If an internal node exhibits rogue behavior, the controller disconnects it from `iot_production_net` and attaches it to `iot_quarantine_net`.
6. **Telemetry & Visual Feedback:** The dashboard updates instantaneously: the offending IP enters the drop list, the banned counter increments, and quarantined nodes flash red.

## Features

### 1. IoT Network Simulation Layer
- Lightweight containerized publishers generating periodic MQTT JSON telemetry over TCP port 1883.
- Mosquitto message broker managing topics (`home/sensors/temperature`, `home/devices/bulb`).
- Deterministic static IP assignments inside dedicated Docker bridge networks.

### 2. Deception & Honeypot Pipeline
- Containerized Cowrie instance emulating UNIX-based IoT device firmware (e.g., BusyBox router/camera).
- Structured logging parsing `/cowrie/var/log/cowrie/cowrie.json` in real time.
- Attack classification: connection sweeps, brute-force attempts, unauthorized terminal execution, and malicious payload transfers.

### 3. Core Analytics & Autonomous Mitigation Engine
- Sliding-window frequency tracking for IP connection and authentication rates.
- Direct Linux kernel integration hooking a custom `IOT_DEFENSE_BLOCKLIST` chain into Docker's `DOCKER-USER` table.
- Containment manager wrapping Docker Python SDK to dynamically migrate compromised containers to an isolated bridge (`internal: true`).
- Hardcoded management allowlist to prevent administrative lockout (loopback, host gateway, subnets).

### 4. Real-Time Telemetry Dashboard
- Single-page application served via FastAPI.
- Push-based event delivery via SSE (`text/event-stream`).
- Visual status tracking: active nodes, quarantined containers, live defense log table, and active `iptables` drop inventory.

## Scope

### In Scope
- Containerized virtualization of IoT nodes and Mosquitto broker using Docker Compose.
- Low-to-medium interaction honeypot integration (Cowrie).
- Host-level Linux `iptables` manipulation via custom chains for Docker forward traffic.
- Container network dynamic isolation via Docker Engine API (`/var/run/docker.sock`).
- Server-Sent Events (SSE) telemetry delivery and Tailwind-styled dark UI.
- Red-team Python simulation script for automated defense validation.

### Out of Scope
- Physical embedded hardware deployment (Raspberry Pi, ESP32, Arduino).
- Deep reinforcement learning or heavyweight neural network model training on the edge.
- Full layer-7 deep packet inspection (DPI) of encrypted TLS payloads.
- Multi-host Kubernetes orchestration (focused on single-host testbed capstone scope).

## Success Criteria
1. **Container Orchestration:** All 5 core services (`mqtt_broker`, `sensor`, `bulb`, `cowrie`, `defense_controller`) boot cleanly via a single `docker-compose up` command.
2. **Deception Validation:** Attacking port 2222 with bad credentials generates structured JSON entries in `cowrie.json` within 200 ms.
3. **Firewall Ban Execution:** Reaching 5 failed logins within 30 seconds injects a verified `DROP` rule into the Linux kernel `IOT_DEFENSE_BLOCKLIST` chain.
4. **Traffic Dropping:** Subsequent TCP handshakes from the offending attacker IP timeout immediately with 0 bytes returned.
5. **Dashboard Synchronization:** The web client displays the banned IP, rule details, and attack timeline via SSE without requiring manual browser refresh.

