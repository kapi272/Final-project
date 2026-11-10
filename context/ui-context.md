# UI Context

## Theme
Dark mode only. The visual language represents a security operations center (SOC) terminal: near-black, low-saturation slate backgrounds, layered card surfaces, high-contrast monospace typography for network telemetry, and vivid status-indicator states (emerald for normal, amber for deception traps, rose/red for autonomous mitigation and quarantined assets).

## Colors

| Role | CSS Variable / Tailwind | Hex / Token | Usage |
| :--- | :--- | :--- | :--- |
| **Page Base** | `bg-[#0b0f19]` | `#0b0f19` | Application background |
| **Surface Card** | `bg-slate-900` | `#0f172a` | Panels, card containers, widgets |
| **Border Default** | `border-slate-800` | `#1e293b` | Structural dividers, panel borders |
| **Text Primary** | `text-slate-100` | `#f1f5f9` | Primary headings and metric values |
| **Text Muted** | `text-slate-400` | `#94a3b8` | Metadata labels, descriptions, subheaders |
| **Text Monospace**| `text-slate-300` | `#cbd5e1` | IP addresses, ports, timestamps |
| **State Healthy** | `text-emerald-400` | `#34d399` | Online stream, normal node status |
| **State Warning** | `text-amber-400` | `#fbbf24` | Honeypot hits, recon probes detected |
| **State Threat** | `text-rose-500` | `#f43f5e` | iptables DROP rules, quarantined nodes |
| **Accent Primary**| `text-sky-400` | `#38bdf8` | Network topology labels, active selections |

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

