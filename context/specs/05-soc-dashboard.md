# Unit 05: Single-Page Real-Time SOC Dashboard

## Goal
Build a responsive, dark-mode single-page SOC terminal interface served at `/` adhering to `context/ui-context.md`. The frontend connects to `/api/stream` via native EventSource (SSE), dynamically updating live network topology cards, active `iptables` drop inventory, intrusion counters, auto-scrolling terminal logs, and administrative controls (Manual Unban, Reset Bans, Simulate Infection).

## Design & UI Tokens
- **Palette:** Base `bg-[#0b0f19]`, Surface `bg-slate-900`, Border `border-slate-800`.
- **States:**
  - Online/Healthy: `text-emerald-400`, `bg-emerald-950/40 border-emerald-800`
  - Honeypot Decoy: `text-amber-400`, `bg-amber-950/40 border-amber-800`
  - Autonomous Drop: `text-rose-500`, `bg-rose-950/40 border-rose-800`
  - Quarantined Container: `bg-red-950/40 border-red-600 animate-pulse`
- **XSS Prevention:** All dynamic data injection into the DOM (attacker usernames, IPs, shell input strings) must use `textContent` or `document.createTextNode` — zero unsafe `innerHTML` interpolations.

## Implementation

### 1. `controller/templates/index.html`
- Top Header: System status title, pulsing live SSE indicator, connection state badge, Global "Reset Bans" button.
- Metrics Banner:
  - Active Firewall Drops
  - Honeypot Hits Captured
  - Virtual Node Topology Count
  - Lateral Movement Protection Status (`iot_quarantine_net`)
- Node Topology Grid:
  - `iot_sensor_node` (172.20.0.21) + "Infect" / "Restore" trigger buttons.
  - `iot_bulb_node` (172.20.0.22) + "Infect" / "Restore" trigger buttons.
  - `iot_mqtt_broker` (172.20.0.10) - Telemetry broker.
  - `iot_cowrie_honeypot` (172.20.0.50) - Active deception decoy.
- Autonomous Mitigation History Table:
  - Timestamp, Source IP, Netfilter Action (`IPTABLES_DROP`), Severity Badge, Reason, Actions (Unban button).
- Honeypot Event Terminal Console:
  - Dark monospace terminal (`text-[11px] font-mono bg-slate-950`) auto-scrolling in real time.

### 2. `controller/static/app.js`
- Native ES6 module:
  - `initSSE()`: connects to `/api/stream` and handles events (`connected`, `heartbeat`, `honeypot_hit`, `mitigation_alert`, `node_quarantined`, `node_restored`, `unban_alert`, `reset_alert`).
  - `fetchInitialState()`: calls `GET /api/defense/status` to pre-populate inventory on page load.
  - `handleUnban(ip)`: sends `POST /api/defense/unban`.
  - `handleResetBans()`: sends `POST /api/defense/reset-bans`.
  - `handleInfect(nodeId)`: sends `POST /api/simulate/infect/{node_id}`.
  - `handleRestore(nodeId)`: sends `POST /api/simulate/restore/{node_id}`.

## Dependencies
- Tailwind CSS via official script CDN (`https://cdn.tailwindcss.com`)
- Native browser Web APIs (`EventSource`, `fetch`, DOM)

## Verify when done
- [x] Dashboard loads at `http://localhost:8000/` with status 200 and dark SOC terminal styling.
- [x] SSE handshake establishes and renders glowing green "CONNECTED" badge.
- [x] Simulated attacks increment metrics and append table rows dynamically without page reload.
- [x] XSS sanitization verified (raw script strings render as safe text).
- [x] Unit 05 verification test passes.
