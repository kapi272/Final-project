# UI Context

## Theme & Layout Architecture
Dual-theme SOC interface supporting persistent **Dark Mode** (`html.dark`, default obsidian terminal theme) and **Light Mode** (`html.light`, crisp Slate-50/White editorial operations view persisted in `localStorage` under `soc_theme`).

Top navigation houses global toggles (`Simulated | Live` traffic switch, `Dark | Light` theme switch, and `#sse-status-pill`). Below the header, `#workspace-subnav` cleanly separates four full-width workspace tabs (**Live Operations** `#tab-btn-soc`, **Mitigation Ledger** `#tab-btn-mitigations` with `#tab-badge-mitigations`, **Activity Logs** `#tab-btn-logs` with `#tab-badge-logs`, and **About & Architecture** `#btn-open-about`) from utility actions (**Analytics & Forensics**, **Reset All Bans**, **Reset Database**).

- **Live Operations Workspace (`#workspace-panel-soc`):** Focused dashboard view ordered by KPI cards → Active Asset Mesh (`#section-simulated-topology` in Simulated / `#section-live-devices` in Live) → **Adversary Intrusion Simulation** (`#section-simulated-redteam`) → **Honeypot Threat Intelligence & Log Analytics** (`#section-threat-intel`).
- **Mitigation Ledger Workspace (`#workspace-panel-mitigations`):** Dedicated full-width Netfilter blocklist & quarantined hardware audit table (`#mitigation-table-body`, up to `600px` scrollable table body) eliminating horizontal crowding.
- **Activity Logs Workspace (`#workspace-panel-logs`):** Dedicated full-width 6-column SIEM console (`#terminal-feed`, `540px` height) with stream filter pills (`ALL`, `HONEYPOT`, `MITIGATION`, `QUARANTINE`, `IOT MESH`, `SYSTEM`) and selective export triggers.
- **About & Architecture Workspace (`#workspace-panel-about`):** Chapter-filtered documentation tabs (`#about-chapter-tabs`: Full Guide, How It Works, Simulated vs Live, Differences & Advantages) with `.diagram-showcase-frame` containers preserving obsidian framing around dark-HUD diagrams across themes.

## Colors (Executive Cyber SOC Palette)

A bespoke, high-contrast, human-crafted cybersecurity visual system avoiding flat AI-generated aesthetics. Built on an atmospheric midnight-obsidian foundation in Dark Mode and a crisp editorial slate-50 in Light Mode:

| Role | Dark Mode (`html.dark`) | Light Mode (`html.light`) | Usage & Semantics |
| :--- | :--- | :--- | :--- |
| **Page Base** | `#080c15` (Deep Obsidian Midnight) | `#f8fafc` (Slate 50) | Full-viewport canvas, prevents harsh glare |
| **Surface Card** | `#0e1626` (Elevated Panel) | `#ffffff` (Pure White) | Workspaces, KPI widgets, card frames |
| **Sub-Card / Well** | `#050811` (Deep Well) | `#f1f5f9` (Slate 100) | Console feed, data tables, input backgrounds |
| **Border Default** | `#1e293b` (Slate 800) | `#e2e8f0` (Slate 200) | Structural dividers and cards (WCAG 3:1 non-text) |
| **Border Subtle** | `#162032` (Slate 850) | `#cbd5e1` (Slate 300) | Secondary dividers, table row borders |
| **Text Primary** | `#f8fafc` (Slate 50) | `#0f172a` (Slate 900) | Primary titles, critical metric values |
| **Text Muted** | `#94a3b8` (Slate 400) | `#475569` (Slate 600) | Subheaders, descriptions, labels |
| **Text Monospace** | `#cbd5e1` (Slate 300) | `#334155` (Slate 700) | IP addresses, timestamps, terminal logs |
| **Primary Accent / Brand** | `#0284c7` / `#38bdf8` (Cyber Azure) | `#0284c7` / `#2563eb` | Active tabs, primary CTAs (`solid-accent-btn`) |
| **State Healthy / Armed** | `#10b981` / `#34d399` (Precision Emerald) | `#047857` / `#059669` | Production nodes, online SSE, verified status |
| **State Warning / Trap** | `#f59e0b` / `#fbbf24` (Tactical Amber) | `#b45309` / `#d97706` | Honeypot captures, port sweeps, caution alerts |
| **State Threat / Containment**| `#f43f5e` / `#fb7185` (Cyber Crimson) | `#be123c` / `#e11d48` | Netfilter drops, quarantined hardware, exploits |
| **Protocol / Telemetry** | `#818cf8` / `#6366f1` (Cyber Indigo) | `#4338ca` (Deep Indigo) | Users & Sessions, operator pills, protocol chips |

### Contrast & Ergonomic Rules
- **Solid Action Buttons (`.solid-accent-btn`):** Use saturated Cyber Azure (`#0284c7` hover `#0369a1`) with crisp `#ffffff` text, 600 font weight, and subtle depth shadow (`shadow-md shadow-sky-950/40`), giving tactile realism across both themes.
- **Micro-Badges & Status Chips:** Use low-opacity alpha tints (`rgba(16, 185, 129, 0.12)`, `rgba(244, 63, 94, 0.12)`, `rgba(245, 158, 11, 0.12)`) bounded by matching 1px saturated borders (`rgba(..., 0.45)`), preventing visual vibration.
- **Accessible Text Contrast:** All primary text exceeds WCAG 4.5:1; component boundaries satisfy WCAG 1.4.11 (3:1 minimum).

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

