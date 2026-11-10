# Progress Tracker

Update this file after every meaningful implementation change.

## Current Phase
Phase 6: Red Team Simulation & End-to-End Autonomous Validation

## Current Goal
Implement Unit 06: Build automated adversary red team testing script (`tests/attacker_sim.py`) simulating reconnaissance port sweeps, SSH/Telnet credential brute-force dictionary attacks, and rogue container lateral movement for end-to-end autonomous mitigation validation in <1,000 ms.

## Completed
- [x] Context foundation files established and verified at root.
- [x] Build plan created (`context/specs/00-build-plan.md`).
- [x] Unit 01 specification written (`context/specs/01-docker-network-orchestration.md`).
- [x] Unit 01: Docker Orchestration & Virtual IoT Network (docker-compose, Mosquitto, Simulators, Cowrie).
- [x] Unit 02 specification written (`context/specs/02-mitigation-engine.md`).
- [x] Unit 02: Mitigation Engine (firewall netfilter driver, Docker SDK quarantine controller, allowlist protection, 11 unit tests passing).
- [x] Unit 03 specification written (`context/specs/03-honeypot-ingestion-engine.md`).
- [x] Unit 03: Honeypot Ingestion Engine & Detection Core (async log tailer, in-memory sliding window, SQLite audit store, 7 unit tests passing).
- [x] Unit 04 specification written (`context/specs/04-fastapi-telemetry-engine.md`).
- [x] Unit 04: FastAPI Telemetry Engine & SSE Streaming API (non-buffering SSE stream, REST unban/reset/infect endpoints, 7 unit tests passing).
- [x] Unit 05 specification written (`context/specs/05-soc-dashboard.md`).
- [x] Unit 05: Single-Page Real-Time SOC Dashboard (Tailwind CSS, dynamic node cards, live ledger, auto-scrolling terminal, 2 unit tests passing).

## In Progress
- [ ] Unit 06: Red Team Simulation & End-to-End Autonomous Validation (`tests/attacker_sim.py`).

## Next Up
- [ ] Multi-container Docker Compose live stack validation and viva evaluation runbook.

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

