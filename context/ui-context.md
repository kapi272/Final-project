# UI Context

## Theme & Layout Architecture
Dual-theme SOC interface supporting persistent **Dark Mode** (`html.dark`, default obsidian terminal theme) and **Light Mode** (`html.light`, crisp Slate-50/White editorial operations view persisted in `localStorage` under `soc_theme`).

Top navigation houses global toggles (`Simulated | Live` traffic switch, `Dark | Light` theme switch, and `#sse-status-pill`). Below the header, `#workspace-subnav` cleanly separates four full-width workspace tabs (**Live Operations** `#tab-btn-soc`, **Mitigation Ledger** `#tab-btn-mitigations` with `#tab-badge-mitigations`, **Activity Logs** `#tab-btn-logs` with `#tab-badge-logs`, and **About & Architecture** `#btn-open-about`) from utility actions (**Analytics & Forensics**, **Reset All Bans**, **Reset Database**).

- **Live Operations Workspace (`#workspace-panel-soc`):** Focused dashboard view ordered by KPI cards → Active Asset Mesh (`#section-simulated-topology` in Simulated / `#section-live-devices` in Live) → **Adversary Intrusion Simulation** (`#section-simulated-redteam`) → **Honeypot Threat Intelligence & Log Analytics** (`#section-threat-intel`).
- **Mitigation Ledger Workspace (`#workspace-panel-mitigations`):** Dedicated full-width Netfilter blocklist & quarantined hardware audit table (`#mitigation-table-body`, up to `600px` scrollable table body) eliminating horizontal crowding.
- **Activity Logs Workspace (`#workspace-panel-logs`):** Dedicated full-width 6-column SIEM console (`#terminal-feed`, `540px` height) with stream filter pills (`ALL`, `HONEYPOT`, `MITIGATION`, `QUARANTINE`, `IOT MESH`, `SYSTEM`) and selective export triggers.
- **About & Architecture Workspace (`#workspace-panel-about`):** Chapter-filtered documentation tabs (`#about-chapter-tabs`: Full Guide, How It Works, Simulated vs Live, Differences & Advantages) with `.diagram-showcase-frame` containers preserving obsidian framing around dark-HUD diagrams across themes.

## Colors (Neo-Pastel Cyber Palette on Pure Black)

The design system adopts a 5-tone pastel accent palette paired with high-contrast `#000000` (Pure Black) foundations:

| Role | Tone / Hex | Dark Mode (`html.dark`) | Light Mode (`html.light`) | Usage & Contrast Rules |
| :--- | :--- | :--- | :--- | :--- |
| **Page Base** | `#000000` (`darkBase`) | `#000000` (Pure Black Canvas) | `#f8fafc` (`Slate 50`) | Deep obsidian terminal background |
| **Surface Card** | Deep Void | `#0a0d14` / `#000000` | `#ffffff` (`White`) | Panels, card containers, widgets with fine borders |
| **Sub-Card / Well** | Pure Black | `#000000` | `#f1f5f9` (`Slate 100`) | Nested cards, SIEM feed, form inputs |
| **Border Default** | High-Contrast Charcoal | `#1a202c` / `#2d3748` | `#e2e8f0` (`Slate 200`) | Structural dividers, panel borders |
| **Text Primary** | High-Contrast White | `#ffffff` / `#f8fafc` | `#000000` / `#0f172a` | Primary headings and vital metrics |
| **Text Muted** | Slate Gray | `#94a3b8` | `#475569` | Metadata labels, descriptions, subheaders |
| **Text Monospace** | Crisp Ice Slate | `#cbd5e1` | `#1e293b` | IP addresses, ports, timestamps |
| **State Healthy (Primary)** | `#b9e192` (Pistachio Green) | `#b9e192` (paired with `#000000`) | `#2e6309` / `#b9e192` | Online stream, normal node status, healthy KPIs |
| **State Healthy (Secondary)** | `#cfebb6` (Tea Green / Mint) | `#cfebb6` (paired with `#000000`) | `#3b7512` / `#cfebb6` | Verified badges, secondary healthy glows, safe pills |
| **Accent Primary / Active** | `#b3c7f7` (Periwinkle Blue) | `#b3c7f7` (paired with `#000000`) | `#1d4ed8` / `#b3c7f7` | Active tabs, primary CTAs (`solid-accent-btn`), brand accents |
| **State Warning / Trap** | `#f8b8d0` (Pastel Rose) | `#f8b8d0` (paired with `#000000`) | `#9d174d` / `#f8b8d0` | Honeypot traps captured, recon sweeps, caution badges |
| **State Threat / Quarantine** | `#f194b8` (Raspberry Pink) | `#f194b8` (paired with `#000000`) | `#be185d` / `#f194b8` | Netfilter drops, quarantined hardware, exploit triggers |

### Contrast & Typography Pairing Rules
- **Solid Pastel Badges & Action Buttons:** Whenever a component uses a solid fill from the 5 pastel tones (`#b9e192`, `#cfebb6`, `#b3c7f7`, `#f8b8d0`, `#f194b8`), the foreground text and icon color MUST be `#000000` (Pure Black, bold font weight) for maximum legibility.
- **Glass / Tinted Containers:** Container backgrounds use low-opacity alpha tints (`rgba(179, 199, 247, 0.12)`, `rgba(185, 225, 146, 0.12)`, `rgba(241, 148, 184, 0.12)`) bounded by matching saturated borders.

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

