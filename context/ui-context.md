# UI Context

## Theme & Layout Architecture
Dual-theme SOC interface supporting persistent **Dark Mode** (`html.dark`, default obsidian terminal theme) and **Light Mode** (`html.light`, crisp Slate-50/White editorial operations view persisted in `localStorage` under `soc_theme`).

Top navigation houses global toggles (`Simulated | Live` traffic switch, `Dark | Light` theme switch, and `#sse-status-pill`). Below the header, `#workspace-subnav` cleanly separates four full-width workspace tabs (**Live Operations** `#tab-btn-soc`, **Mitigation Ledger** `#tab-btn-mitigations` with `#tab-badge-mitigations`, **Activity Logs** `#tab-btn-logs` with `#tab-badge-logs`, and **About & Architecture** `#btn-open-about`) from utility actions (**Analytics & Forensics**, **Reset All Bans**, **Reset Database**).

- **Live Operations Workspace (`#workspace-panel-soc`):** Focused dashboard view ordered by KPI cards → Active Asset Mesh (`#section-simulated-topology` in Simulated / `#section-live-devices` in Live) → **Adversary Intrusion Simulation** (`#section-simulated-redteam`) → **Honeypot Threat Intelligence & Log Analytics** (`#section-threat-intel`).
- **Mitigation Ledger Workspace (`#workspace-panel-mitigations`):** Dedicated full-width Netfilter blocklist & quarantined hardware audit table (`#mitigation-table-body`, up to `600px` scrollable table body) eliminating horizontal crowding.
- **Activity Logs Workspace (`#workspace-panel-logs`):** Dedicated full-width 6-column SIEM console (`#terminal-feed`, `540px` height) with stream filter pills (`ALL`, `HONEYPOT`, `MITIGATION`, `QUARANTINE`, `IOT MESH`, `SYSTEM`) and selective export triggers.
- **About & Architecture Workspace (`#workspace-panel-about`):** Chapter-filtered documentation tabs (`#about-chapter-tabs`: Full Guide, How It Works, Simulated vs Live, Differences & Advantages) with `.diagram-showcase-frame` containers preserving obsidian framing around dark-HUD diagrams across themes.

## Colors

| Role | Dark Mode (`html.dark`) | Light Mode (`html.light`) | Usage |
| :--- | :--- | :--- | :--- |
| **Page Base** | `#0b0f19` (`bg-darkBase`) | `#f8fafc` (`Slate 50`) | Application background |
| **Surface Card** | `#0f172a` (`bg-slate-900`) | `#ffffff` (`White`) | Panels, card containers, widgets |
| **Sub-Card / Well** | `#020617` (`bg-slate-950`) | `#f8fafc` (`Slate 50`) | Nested cards, SIEM feed, inputs |
| **Border Default** | `#1e293b` (`border-slate-800`) | `#e2e8f0` (`Slate 200`) | Structural dividers, panel borders |
| **Text Primary** | `#f1f5f9` (`text-slate-100` / `#ffffff`) | `#0f172a` (`Slate 900`) | Primary headings and metric values |
| **Text Muted** | `#94a3b8` (`text-slate-400`) | `#475569` (`Slate 600`) | Metadata labels, descriptions, subheaders |
| **Text Monospace** | `#cbd5e1` (`text-slate-300`) | `#334155` (`Slate 700`) | IP addresses, ports, timestamps |
| **State Healthy** | `#34d399` (`text-emerald-400`) | `#047857` (`Emerald 700`) | Online stream, normal node status |
| **State Warning** | `#fbbf24` (`text-amber-400`) | `#b45309` (`Amber 700`) | Honeypot hits, recon probes detected |
| **State Threat** | `#f43f5e` (`text-rose-500`) | `#be123c` (`Rose 700`) | iptables DROP rules, quarantined nodes |
| **Accent Primary** | `#38bdf8` (`text-sky-400`) | `#0369a1` (`Sky 700`) | Network topology labels, active selections |

## Typography

| Role | Font Family | Tailwind Class | Notes |
| :--- | :--- | :--- | :--- |
| **UI Sans** | Inter / System UI Sans | `font-sans` | Used for cards, headers, navigation, badges |
| **Telemetry Mono**| JetBrains Mono / Courier / ui-monospace | `font-mono` | Used for logs, IPs, rules, timestamps, raw feed |

## Border Radius

| Context | Tailwind Class |
| :--- | :--- |
| Badges & Status Pills | `rounded-full` |
| Node Topology Boxes | `rounded-lg` |
| Metrics & Table Cards | `rounded-lg` |
| Terminal Console Feed | `rounded` |

## Component Specifications

### 1. Header & Live Connection Status Pill
- Displays the system title with a pulsing green indicator.
- Houses a dynamic pill showing SSE connection health:
  - Connected: `bg-emerald-950/40 border-emerald-800 text-emerald-400`
  - Reconnecting/Disconnected: `bg-rose-950/40 border-rose-800 text-rose-400`

### 2. Node Status Card
- Visual box representing each virtual container.
- Normal state: `bg-slate-950/60 border-slate-800`.
- Quarantined state: `bg-red-950/40 border-red-600 animate-pulse`.

### 3. Live Mitigation Table
- Fixed-header, scrollable body displaying historical autonomous actions.
- Columns: Timestamp, Offender IP, Action Executed (Badge: `IPTABLES_DROP`), Trigger Reason.

### 4. Raw Honeypot Feed Console
- Terminal-styled window (`bg-slate-950 border-slate-800 font-mono text-[11px]`).
- Auto-scrolls in reverse or sticks to bottom showing raw JSON-line parsed events.

