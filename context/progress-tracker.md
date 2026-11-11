# Progress Tracker

Update this file after every meaningful implementation change.

## Current Phase
Phase 17: Milestone v2.0.0 Completed — Dual Simulated/Live Traffic Mode & Real-World IoT/CCTV Device Onboarding

## Current Goal
Deliver production-verified v2.0.0 release with strict Simulated/Live toggle, SSRF-hardened Real Device Registry, authenticated HTTP/MQTT telemetry ingestion, snapshot proxy, logical device quarantine, and log-rotation resilient Cowrie tailing.

## Completed
- [x] Context foundation files established and verified at root.
- [x] Build plan created (`context/specs/00-build-plan.md`).
- [x] Unit 01: Docker Orchestration & Virtual IoT Network (dual-bridge subnets, Mosquitto, Simulators, Cowrie).
- [x] Unit 02: Mitigation Engine (Netfilter `IOT_DEFENSE_BLOCKLIST` driver, Docker SDK quarantine controller, allowlist protection).
- [x] Unit 03: Honeypot Ingestion Engine & Detection Core (async log tailer, in-memory sliding window, SQLite audit store).
- [x] Unit 04: FastAPI Telemetry Engine & SSE Streaming API (non-buffering SSE stream, REST unban/reset/infect endpoints).
- [x] Unit 05: Single-Page Real-Time SOC Dashboard (Tailwind CSS, dynamic node cards, live ledger, auto-scrolling terminal).
- [x] Unit 06: Red Team Simulation & End-to-End Autonomous Validation (`tests/attacker_sim.py`, latency benchmark 0.56ms < 1000ms SLA).
- [x] Phase 7: Operational Readiness (Containerized controller `controller/Dockerfile`, 5-service `docker-compose.yml`, and live evaluation runbook `docs/EVALUATION_RUNBOOK.md`).
- [x] Live Honeypot Telemetry & Autonomous Mitigation Ledger Synchronization: Fixed Cowrie log path mount, added Docker Desktop gateway allowlist protection (`192.168.65.0/24`), Netfilter fallback to `INPUT`, mounted live `./controller:/app/controller`, and verified real-time drops and ledger population.
- [x] Phase 8: Milestone v1.1.0 — Option A Interactive Adversary Simulation Toolbar added to dashboard with 1-click attack triggers (`/api/simulate/attack/brute-force`, `/api/simulate/attack/exploit`, `/api/simulate/attack/port-sweep`), live SSE feedback, and 32 passing unit tests.
- [x] Phase 9: Milestone v1.2.0 — Threat Intelligence Panel & External Log Analytics Console: Added real-time attack distribution bars, top credential analytics, deception port breakdown, dedicated External Analytics & SIEM Forensics modal (separate button in header), deep IP dossier inspection, and 1-click JSON report export. 35/35 tests passing.
- [x] Phase 10: Milestone v1.3.0 — General Multi-Stream Console & UI De-duplication: Removed redundant "Reset DB" button from ledger header, unified database wipe with console clear, added dedicated manual "Clear" button for the terminal feed, implemented General Activity Logs with category filter tabs (`[ ALL ]`, `[ HONEYPOT ]`, `[ MITIGATION ]`, `[ IOT MESH ]`, `[ SYSTEM ]`), and added background `IoTTelemetryListener` streaming live MQTT mesh telemetry over SSE. 37/37 tests passing.
- [x] Phase 11: Milestone v1.4.0 — Dedicated Quarantine Stream & Structured Console Log Columns: Added dedicated `[ QUARANTINE ]` filter tab in General Activity Logs, aligned terminal feed lines into structured columns (Time, Category Badge, Message Details), and integrated real-time dynamic container isolation and restoration events directly under the quarantine category. 38/38 tests passing.
- [x] Phase 12: Milestone v1.5.0 — SIEM Multi-Column Structured Console & Payload Ingestion: Upgraded the General Activity Logs with Option B (6-column layout: TIME, STREAM, SEVERITY, SOURCE/NODE, PROTOCOL, PAYLOAD & EVENT DATA), rendered an aligned table grid header, and wired all telemetry, honeypot, mitigation, and quarantine events to display their protocol and payload data. 38/38 tests passing.
- [x] Phase 13: Milestone v1.6.0 — Indian Standard Date & Time (IST) Formatting: Configured `formatDateTime` using `Asia/Kolkata` and `en-IN` (`DD/MM/YYYY, HH:mm:ss`), updated the first column of the 6-column SIEM grid and the Autonomous Mitigation Ledger to display the calendar date preceding the time, adjusted the time column width to `w-[145px] shrink-0`, and widened the horizontal scroll wrapper to `min-w-[860px]` for smooth rendering. 38/38 unit tests passing.
- [x] Phase 14: Milestone v1.7.0 — Multi-Format Activity Logs Export Engine: Added dedicated `[ 📥 Export ]` button in the General Activity Logs header opening a modal for selective log export. Operators can filter by scope (ALL, HONEYPOT, MITIGATION, QUARANTINE, IOT MESH, SYSTEM) and choose between industry-standard formats (JSON, CSV, Raw LOG/TXT) with live matching record counters and IST timestamp formatting. 38/38 unit tests passing.
- [x] Phase 15: Milestone v1.8.0 Version Bump — System version incremented to v1.8.0 (SOC Terminal v1.8-SOC) across app, docs, and configurations.
- [x] Phase 15: Multi-IP Adversary Simulation Pools, Custom IP & Swarm Engine: Added curated 5-IP RFC 5737 TEST-NET pools per attack vector (`brute-force`, `exploit`, `port-sweep`), exposed `GET /api/simulate/attack/pools`, updated `POST /api/simulate/attack/{type}` with `ipaddress` boundary validation and `"single"` / `"random"` / `"swarm"` modes, added UI selector dropdowns (`Auto-Rotate IP`, 5 pool IPs, `Swarm Mode`, `Custom IP`) on all 3 Red Team cards, and enforced allowlist safety checks. 40/40 unit tests passing.
- [x] Phase 16: Milestone v1.8.1 — Cache-Busting, Ledger/Console Unban Sync & Red Team Feedback Hardening: Added HTTP `Cache-Control: no-store` middleware (`disable_ui_caching`) on `/` and `/static/*` plus `?v=1.8.1` script cache-buster in `index.html`, added `newly_banned` / `already_banned` tracking in `_build_simulation_result` across all three simulation endpoints, normalized `CRITICAL` -> `CRIT` badge styling in `appendTerminalLog`, added `dataset.srcIp` + authoritative ledger sync (`fetchInitialStatus`) in `unban_alert` and `triggerAttack`, and surfaced idempotent skip messages (`already_banned`) in General Activity Logs. 40/40 unit tests passing.
- [x] Phase 17: Milestone v2.0.0 — Dual Simulated/Live Traffic Mode & Real-World IoT/CCTV Integration: Extended SQLite schema (`system_settings`, `registered_devices`), implemented `RealDeviceManager` (`controller/core/device_manager.py`) with strict SSRF IP/DNS guards, credential masking, SHA-256 webhook token auth, asyncio TCP probe, HTTP/MJPEG snapshot proxy, and logical quarantine (`DEVICE_BLOCKED` / `DEVICE_RESTORED`); added `GET/POST /api/system/mode`, `/api/devices/*`, and `409 Conflict` guard on `/api/simulate/*` in live mode; fixed `HoneypotLogTailer` inode rotation handling; added header Simulated/Live toggle, Real Device Registry panel, safe DOM rendering (removed unsafe `innerHTML`), in-app confirm/snapshot/onboarding modals, and `tests/test_live_mode_and_devices.py`. 47/47 unit tests passing.

## In Progress
- [ ] Live evaluation demonstration and evaluator walkthrough.

## Next Up
- [ ] Run `docker compose up -d` for live multi-container demo whenever evaluator is ready.

## Open Questions & Decisions Needed
1. **Network Packet Sniffing on macOS:** Since macOS Docker Desktop bridges traffic through a lightweight Linux VM, packet sniffing must run inside a container connected to `iot_production_net` rather than directly on the native Darwin macOS network stack.
2. **Persistence Storage Schema:** Confirm whether historical bans and quarantine events should be logged to a local SQLite file (`data/defense_history.db`) or kept purely in memory during viva demonstration sessions.

## Architecture Decisions
- **Permanent Ban Policy (No Auto-TTL Expiry):** 
  - *Decision:* All IP bans remain permanently enforced until an administrator explicitly invokes `POST /api/defense/unban` or clicks "Reset Bans" in the dashboard.
  - *Reason:* Prevents unexpected rule expiration during live evaluator demonstrations and grading presentations.
- **Cross-Platform Compatibility (macOS / Windows / Linux):** 
  - *Decision:* Abstract all host-specific netfilter dependencies. Run the firewall enforcement within an Alpine-based gateway container equipped with `NET_ADMIN` capabilities, while orchestrating container isolation via the Docker Engine API (`/var/run/docker.sock`).
  - *Reason:* Native macOS lacks `iptables` (uses PF) and Docker Desktop runs inside a hypervisor VM; containerizing the network control makes behavior identical across macOS, Windows WSL2, and native Ubuntu.
- **On-Demand Node Compromise Simulation:** 
  - *Decision:* Implemented `POST /api/simulate/infect/{node_id}` to trigger immediate container network quarantine and UI notification.
  - *Reason:* Allows deterministic, repeatable demonstrations of internal threat containment without relying on manual shell access into containers.
- **Custom Netfilter Chain:** Insert rules exclusively into `IOT_DEFENSE_BLOCKLIST` linked to `DOCKER-USER`.
- **Server-Sent Events (SSE) over WebSockets:** Chosen for lightweight, one-way telemetry streaming with built-in client reconnection.
- **Dual Bridge Subnets:** Segregated `iot_production_net` (normal traffic) from `iot_quarantine_net` (`internal: true`) for complete lateral threat containment.

## Session Notes
- When running on macOS via Docker Desktop, ensure the Docker socket path (`/var/run/docker.sock`) is shared and has read/write permissions for the controller container.

