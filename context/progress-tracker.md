# Progress Tracker

Update this file after every meaningful implementation change.

## Current Phase
Phase 1: Virtual IoT Network & Container Orchestration

## Current Goal
Implement Unit 01: Provision the containerized virtual IoT network infrastructure via Docker Compose (dual-bridge subnets, Mosquitto broker, sensor/bulb simulators, Cowrie honeypot).

## Completed
- [x] Context foundation files established and verified at root.
- [x] Build plan created (`context/specs/00-build-plan.md`).
- [x] Unit 01 specification written (`context/specs/01-docker-network-orchestration.md`).

## In Progress
- [ ] Unit 01: Docker Orchestration & Virtual IoT Network (docker-compose, Mosquitto, Simulators, Cowrie).


## Next Up
- [ ] Wire the frontend "Simulate Infection" button directly to `/api/simulate/infect/{node_id}` and verify container migration to `iot_quarantine_net`.
- [ ] Connect the manual unban button on the dashboard to the `POST /api/defense/unban` endpoint.
- [ ] Implement an automated internal rogue packet generator inside the virtual sensor container for dynamic quarantine verification.

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

