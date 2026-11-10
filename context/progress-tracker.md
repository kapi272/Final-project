# Progress Tracker

Update this file after every meaningful implementation change.

## Current Phase
Phase 13: Milestone v1.6.0 — Indian Standard Date & Time (IST) Real-Time Console

## Current Goal
The Autonomous IoT Cyber Defense Testbed is running on release v1.6.0 (SOC Terminal v1.6-SOC) with full calendar dates before timestamps formatted according to Indian Date and Time Standards (IST / Asia/Kolkata, UTC+05:30) across the 6-column SIEM General Activity Logs, Forensic Sequence Modals, and Autonomous Mitigation Ledger. 38/38 tests passing.

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
- [x] Phase 13: Milestone v1.6.0 Version Bump — System version incremented to v1.6.0 (SOC Terminal v1.6-SOC) across app, docs, and configurations.
- [x] Phase 13: Indian Standard Date and Time (IST) Formatting: Configured `formatDateTime` using `Asia/Kolkata` and `en-IN` (`DD/MM/YYYY, HH:mm:ss`), updated the first column of the 6-column SIEM grid and the Autonomous Mitigation Ledger to display the calendar date preceding the time, adjusted the time column width to `w-[145px] shrink-0`, and widened the horizontal scroll wrapper to `min-w-[860px]` for smooth rendering. 38/38 unit tests passing.

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

