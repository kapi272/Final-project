# Progress Tracker

Update this file after every meaningful implementation change.

## Current Phase
Phase 8: Milestone v1.1.0 — Interactive Adversary Simulation & SOC UX Controls (IN PROGRESS)

## Current Goal
Bumping system release to v1.1.0 (SOC Terminal v1.1-SOC) and introducing interactive on-demand adversary attack triggers (Option A) to enable seamless browser-driven intrusion tests without command-line dependencies.

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

