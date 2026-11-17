# Autonomous IoT Cyber Defense System Using Virtual IoT Nodes and Honeypot Technology

## Overview
**Current Release:** v2.5.0 (SOC Terminal `v2.5.0-SOC`)

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
- Visual status tracking: active nodes, quarantined containers, live defense log table, active `iptables` drop inventory, and an integrated **About & Architecture** showcase (`#section-about-system`) detailing educational (`Simulated`) vs real-world (`Live`) usage, differentiation, and visual diagrams.

### 5. Dual Simulated / Live Traffic Mode & Real IoT/CCTV Integration (`v2.0.0`)
- Header traffic mode toggle strictly separating **`Simulated Mode`** (virtual Docker nodes + Red Team simulator) from **`Live Mode`** (pauses mock feeds & returns `409 Conflict` on simulation routes while monitoring physical/external IoT hardware).
- Persistent Real-World Device Registry supporting CCTV cameras (`rtsp_http`), MQTT nodes (`mqtt`), and HTTP webhooks (`http_webhook` with SHA-256 `X-Device-Token` auth).
- Non-shell asyncio TCP reachability polling, SSRF-guarded HTTP/MJPEG snapshot proxy with double-buffered **Live Video** playback (`▶ Live Video` / `⏸ Pause Video`), and logical quarantine (`DEVICE_BLOCKED` / `DEVICE_RESTORED`) with ingestion drop and firewall enforcement.

### 6. MQTT Honey-Topic Deception & Payload Anomaly Engine (`v2.2.0`)
- Deceptive honey-topics (`home/admin/#`, `home/debug/#`, `home/system/firmware_update`, `home/gateway/exec`) capturing unauthorized MQTT reconnaissance.
- Deep payload command injection detection (`curl`, `wget`, `nc -e`, `chmod +x`, `/bin/sh`), buffer overflow caps (32 KB), and publish rate flood anomaly tracking.
- Closed-loop autonomous quarantine of compromised real-world hardware and instant Netfilter drop bans on offending attacker IPs.

### 7. LAN Camera & IoT Node Auto-Discovery (`v2.3.0`)
- 1-click discovery modal scanning physical Wi-Fi/Ethernet subnets using zero third-party dependencies.
- Broadcasts standard ONVIF WS-Discovery SOAP probes over UDP multicast (`239.255.255.250:3702`) to identify IP cameras, parsing service endpoints (`XAddrs`) and hardware models from XML scopes.
- Fast non-blocking concurrent TCP port sweep across common IoT ports (`554` RTSP, `8080` HTTP Cam, `1883` MQTT, `80` HTTP Web).
- Strict SSRF boundary enforcement preventing scans against loopback (`127.0.0.0/8`), cloud metadata (`169.254.0.0/16`), and internal Docker bridge subnets.
- 1-click device onboarding pre-populating the Real-World Device Registry with auto-detected protocols, ports, and snapshot URLs.

### 8. STIX 2.1 Threat Intel & SIEM Webhook Dispatcher (`v2.4.0`)
- Compiles real-time honeypot intrusions and active Netfilter drops into standardized OASIS STIX 2.1 JSON bundles.
- Automatic MITRE ATT&CK mapping: `T1110` (Brute Force), `T1059` (Command Interpreter), `T1046` (Service Discovery), and `T1078` (Valid Accounts/Honey-Topics).
- Multi-format outbound alert webhook forwarder dispatching instant mitigation notifications to Splunk HEC, generic SIEMs, Discord, or Slack.
- DNS-resolved SSRF protection preventing webhook abuse against internal management subnets.

### 9. Multi-Protocol IoT Deception Decoy Engine (`v2.5.0`)
- Lightweight asynchronous Constrained Application Protocol (CoAP RFC 7252 UDP:5683) smart sensor honeypot answering resource discovery (`/.well-known/core`) while capturing unauthorized mutation probes and command injection.
- Real-Time Streaming Protocol (RTSP RFC 2326 TCP:8554) camera honeypot emulating streaming handshakes (`OPTIONS`, `DESCRIBE`) and harvesting credential brute-force attempts.
- Automated closed-loop mitigation executing sub-second kernel Netfilter drop bans against offending attacker IPs with 5th Red Team simulation card.

## Scope

### In Scope
- Containerized virtualization of IoT nodes and Mosquitto broker using Docker Compose.
- Low-to-medium interaction honeypot integration (Cowrie) with log-rotation resilient tailing.
- Host-level Linux `iptables` manipulation via custom chains for Docker forward traffic.
- Container network dynamic isolation via Docker Engine API (`/var/run/docker.sock`).
- Real-world LAN/external IoT device telemetry ingestion (MQTT/authenticated webhook), TCP reachability monitoring, HTTP/MJPEG snapshot proxying, and logical quarantine.
- Server-Sent Events (SSE) telemetry delivery and Tailwind-styled dark UI.
- Red-team Python simulation script and UI toolbar for automated defense validation.

### Out of Scope
- Dedicated live RTSP H.264/H.265 video transcoding pipelines (e.g., FFmpeg / WebRTC media servers).
- Flashing custom controller firmware onto microcontrollers (physical devices integrate via standard MQTT or HTTP webhooks).
- Deep reinforcement learning or heavyweight neural network model training on the edge.
- Full layer-7 deep packet inspection (DPI) of encrypted TLS payloads.
- Multi-host Kubernetes orchestration (focused on single-host testbed capstone scope).

## Success Criteria
1. **Container Orchestration:** All 5 core services (`mqtt_broker`, `sensor`, `bulb`, `cowrie`, `defense_controller`) boot cleanly via a single `docker-compose up` command.
2. **Deception Validation:** Attacking port 2222 with bad credentials generates structured JSON entries in `cowrie.json` within 200 ms.
3. **Firewall Ban Execution:** Reaching 5 failed logins within 30 seconds injects a verified `DROP` rule into the Linux kernel `IOT_DEFENSE_BLOCKLIST` chain.
4. **Traffic Dropping:** Subsequent TCP handshakes from the offending attacker IP timeout immediately with 0 bytes returned.
5. **Dashboard Synchronization:** The web client displays the banned IP, rule details, and attack timeline via SSE without requiring manual browser refresh.

