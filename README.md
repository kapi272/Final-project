# Autonomous IoT Cyber Defense System

An autonomous, containerized host-level IoT cyber defense testbed and SOC platform combining virtual IoT nodes, Cowrie deception honeypots, closed-loop Netfilter mitigation, and real-world LAN hardware/CCTV monitoring.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Docker Compose](https://img.shields.io/badge/Docker-Compose%20v2+-2496ED?logo=docker&logoColor=white)](https://www.docker.com/)
[![Release: v2.0.0](https://img.shields.io/badge/Release-v2.0.0-blue)](./)
[![Reaction SLA](https://img.shields.io/badge/Mitigation%20Latency-0.65%20ms-emerald)](./context/specs/06-red-team-simulation.md)
[![Tests Passing](https://img.shields.io/badge/Tests-47%2F47%20Passing-brightgreen)](./tests/)

---

## Overview

This project unifies an educational cyber-range simulator and a live local-perimeter IoT defense monitor behind dual **`Simulated` / `Live`** operating modes:

- **`Simulated Mode` (Educational Cyber Range):** Runs virtual Mosquitto/MQTT sensor and smart-bulb containers inside isolated Docker subnets (`172.20.0.0/24` / `172.21.0.0/24`) alongside a 1-click Red Team simulation toolbar and scripted CLI adversary runner (`tests/attacker_sim.py`).
- **`Live Mode` (Real-World IoT & CCTV Shield):** Mutes synthetic demo traffic and onboards real physical LAN IoT sensors (ESP32, Raspberry Pi) and IP/CCTV cameras via MQTT (`home/#`), SHA-256 token-authenticated HTTP webhooks, periodic TCP health probes, and an SSRF-guarded HTTP/MJPEG live camera viewer.
- **SOC Dashboard (`http://localhost:8050`):** Tabbed single-page console organized into **Live Operations**, full-width **Mitigation Ledger**, 6-column IST **Activity Logs**, and **About & Architecture**, with a persistent **Dark / Light Mode** switcher (`soc_theme`).

Built following the **Six-File Context Methodology** for spec-driven development.

---

## Prerequisites

Make sure the following requirements are met before setting up the project on any operating system:

### 1. Required Software
| Component | Requirement | Purpose |
| :--- | :--- | :--- |
| **Git** | Any modern version | Clone repository and track updates |
| **Docker Engine & Compose v2** | `docker compose version` (`v2.x+`) | Build and run the 5-container stack (`mosquitto`, `sensor_node`, `bulb_node`, `cowrie`, `defense_controller`) |
| **Docker Socket (`/var/run/docker.sock`)** | Shared/mounted with controller | Required for autonomous Docker dual-bridge container quarantine |
| **Linux Capabilities (`NET_ADMIN`)** | Provided via `docker-compose.yml` | Allows `iot_defense_controller` to manage the `IOT_DEFENSE_BLOCKLIST` `iptables` chain inside the controller container (host OS does **not** need native `iptables`) |
| **Web Browser & Network** | Modern Chromium/Firefox/Safari + Internet on first boot | First build pulls base Docker images (~2 GB disk free); browser loads Tailwind CSS CDN (`https://cdn.tailwindcss.com`) |

### 2. Optional Host Python (Only for CLI Attacks or Running Tests Outside Docker)
- **Python 3.11+ (stdlib only):** Enough to run `python3 tests/attacker_sim.py --all` against the running containers.
- **Python 3.11+ with Virtual Environment (`controller/requirements.txt` + `httpx`):** Required only if you want to run the 47-test `unittest` suite natively on your host machine or run `controller/main.py` in hybrid local development mode (`httpx` is needed by FastAPI/Starlette's `TestClient`).

### 3. Required Free Host Ports
Ensure these ports are not already bound by another service on your machine:

| Port | Protocol | Service | External LAN Firewall Note (`Live Mode`) |
| :--- | :--- | :--- | :--- |
| **`8050`** | TCP / HTTP | SOC Dashboard, REST API, SSE Stream & Device Webhooks | Must be allowed inbound if physical devices push webhooks |
| **`1883`** | TCP / MQTT | Eclipse Mosquitto Broker (`home/#`) | Must be allowed inbound if ESP32/RPi devices publish telemetry |
| **`2222`** | TCP / SSH | Cowrie Deception Honeypot (SSH Decoy) | Must be allowed inbound to capture live LAN/external probes |
| **`2223`** | TCP / Telnet | Cowrie Deception Honeypot (Telnet Decoy) | Must be allowed inbound for Telnet deception capture |

---

## Cross-Platform Setup Guide (macOS, Windows, Linux)

Start by cloning the repository on your chosen OS:
```bash
git clone https://github.com/kapi272/Final-project.git
cd Final-project
```

### Option A: macOS (Apple Silicon & Intel)

1. **Install Docker Desktop for Mac:** Download from [docker.com](https://www.docker.com/products/docker-desktop/) or run `brew install --cask docker`, then launch **Docker Desktop** until the whale icon shows Engine running.
2. **Verify Docker Socket & File Sharing:**
   - Open **Docker Desktop → Settings → Advanced** and make sure **"Allow the default Docker socket to be used"** is enabled (`/var/run/docker.sock`).
   - Open **Docker Desktop → Settings → Resources → File Sharing** and verify your project parent folder (e.g., `/Users/<your-user>`) is shared so `./controller`, `./data`, and `./honeypot/logs` mount properly.
3. **Start the 5-Container Stack:**
   ```bash
   docker compose up -d --build
   docker compose ps
   ```
4. **Open the Dashboard:** Visit **`http://localhost:8050`**.
5. **macOS Note for `Live Mode` Real Hardware:**
   - Find your Mac's Wi-Fi IP (`ipconfig getifaddr en0`) so real cameras/ESP32 nodes on the same Wi-Fi network can reach `http://<MAC_LAN_IP>:8050` and `mqtt://<MAC_LAN_IP>:1883`.
   - If the macOS Application Firewall prompts to allow incoming connections for Docker, click **Allow**.

---

### Option B: Windows 10 / 11 (WSL 2 + Docker Desktop)

1. **Enable WSL 2 (Recommended):** Open **PowerShell as Administrator** and run:
   ```powershell
   wsl --install
   ```
   Reboot if prompted, then complete your Ubuntu Linux username/password setup.
2. **Install Docker Desktop for Windows:** Download from [docker.com](https://www.docker.com/products/docker-desktop/), install, and confirm:
   - **Settings → General → "Use the WSL 2 based engine"** is checked.
   - **Settings → Resources → WSL Integration → Enable integration with my default WSL distro** (if cloning/running inside Ubuntu WSL2).
3. **Clone & Boot Stack:**
   > **Tip:** Cloning inside your WSL 2 Linux filesystem (`~/Final-project` inside Ubuntu terminal) avoids Windows CRLF line-ending and volume-permission issues on `./honeypot/logs` and `./data`. If cloning in PowerShell, keep `git config --global core.autocrlf input`.
   ```bash
   # Inside WSL 2 Ubuntu terminal (or Git Bash / PowerShell inside project folder)
   docker compose up -d --build
   docker compose ps
   ```
4. **Open the Dashboard:** Visit **`http://localhost:8050`**.
5. **Windows Note for `Live Mode` Real Hardware:**
   - Ensure Windows Defender Firewall permits inbound TCP on ports `8050`, `1883`, `2222`, and `2223` on your **Private** Wi-Fi profile so physical IoT devices/cameras on your LAN can reach the host.
   - If LAN IoT hardware needs to reach containers hosted inside WSL 2, enable **Mirrored networking mode** in `.wslconfig` (`networkingMode=mirrored` on Windows 11 22H2+) or forward ports from your Windows LAN IP using `netsh interface portproxy`.

---

### Option C: Linux (Ubuntu / Debian / Fedora)

1. **Install Docker Engine & Compose Plugin v2:**
   ```bash
   # Ubuntu / Debian example
   sudo apt-get update
   sudo apt-get install -y git ca-certificates curl docker.io docker-compose-plugin python3 python3-venv
   sudo systemctl enable --now docker
   ```
   *(On Fedora/RHEL, install `docker-ce docker-ce-cli containerd.io docker-compose-plugin` via Docker's official repository.)*
2. **Configure Non-Root Docker Access:**
   ```bash
   sudo usermod -aG docker "$USER"
   newgrp docker
   docker compose version
   ```
   *(If `newgrp docker` isn't picked up immediately, log out and log back in.)*
3. **Verify Permissions on Mounted Folders & Boot Stack:**
   ```bash
   mkdir -p data honeypot/logs
   docker compose up -d --build
   docker compose ps
   ```
4. **Open the Dashboard:** Visit **`http://localhost:8050`**.
5. **Linux Host Firewall Note (`Live Mode`):**
   If `ufw` or `firewalld` is active and external IoT/CCTV devices will connect over LAN:
   ```bash
   # Example with ufw
   sudo ufw allow 8050,1883,2222,2223/tcp
   ```

---

## Network Architecture & Dual-Bridge Topology

```
                  [ External Attacker / Local Machine ]
                                    │
                                    ▼
                [ Netfilter Sub-Chain: IOT_DEFENSE_BLOCKLIST ]
                                    │
            ┌───────────────────────┴───────────────────────┐
            ▼                                               ▼
  [ iot_production_net ]                          [ iot_quarantine_net ]
  Subnet: 172.20.0.0/24                           Subnet: 172.21.0.0/24
  Gateway: 172.20.0.1                             Mode: internal (No Gateway)
  ├── Mosquitto Broker (172.20.0.10:1883)         └── Compromised Containers
  ├── Temp Sensor      (172.20.0.21)                  (Isolated from internet
  ├── Smart Bulb       (172.20.0.22)                   & production MQTT broker)
  ├── Cowrie Decoy     (172.20.0.50:2222/2223)
  └── SOC Controller   (172.20.0.5:8000 -> Host :8050)
```

---

## Quick Start & Daily Commands

### 1. Start or Rebuild All 5 Services
```bash
docker compose up -d
```

### 2. Access the SOC Terminal Dashboard
Open **`http://localhost:8050`** in your browser:
- Use **`🧪 Simulated | 📡 Live`** in the top bar to switch between cyber-range training and physical IoT/CCTV monitoring.
- Use **`🌙 Dark | ☀️ Light`** in the top bar to toggle themes (`localStorage` persisted).
- Navigate across **`Live Operations`**, **`Mitigation Ledger`**, **`Activity Logs`**, and **`About & Architecture`**.

### 3. Trigger Red Team Simulations (UI or CLI)
- **Web UI:** In **`Simulated Mode`**, use **Adversary Intrusion Simulation (Red Team Controls)** for Brute-Force, Terminal Exploit, Port Sweep, Swarm, or Custom IP drills.
- **Terminal CLI** (in a separate terminal while containers are running):
  ```bash
  python3 tests/attacker_sim.py --all
  ```

### 4. Stop Containers (Preserves `./data/defense_history.db`)
```bash
docker compose down
```

---

## Automated Test Suite

The automated suite contains **47 unit/integration tests** across detection, SQLite persistence, SSRF/device management, mitigation drivers, FastAPI routes, SSE streaming, UI markup, and sub-second latency benchmarks.

**macOS / Linux (`bash` / `zsh`):**
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r controller/requirements.txt httpx
python3 -m unittest discover -s tests -v
```

**Windows (PowerShell):**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r controller\requirements.txt httpx
python -m unittest discover -s tests -v
```

---

## Specifications & Documentation

All architectural decisions, invariants, and build plans are organized in [`context/`](./context/) and [`docs/`](./docs/):

| Document | Purpose |
| :--- | :--- |
| **[`docs/EVALUATION_RUNBOOK.md`](./docs/EVALUATION_RUNBOOK.md)** | **Live demonstration script, evaluator Q&A, and viva walkthrough** |
| **[`context/specs/00-build-plan.md`](./context/specs/00-build-plan.md)** | Unit breakdown, dependency graph, and implementation order |
| **[`context/project-overview.md`](./context/project-overview.md)** | Core user flow, operating modes, goals, and feature scope |
| **[`context/architecture.md`](./context/architecture.md)** | Network topology, system boundaries, storage & security invariants |
| **[`context/code-standards.md`](./context/code-standards.md)** | Python type safety, FastAPI conventions, error handling |
| **[`context/ai-workflow-rules.md`](./context/ai-workflow-rules.md)** | Spec-driven workflow, verification criteria, change protocol |
| **[`context/ui-context.md`](./context/ui-context.md)** | Dual Dark/Light theme tokens, tabbed workspace layout & Tailwind conventions |
| **[`context/progress-tracker.md`](./context/progress-tracker.md)** | Real-time project phase, completed milestones, and history |

### Unit Build Specifications
1. **[`Unit 01: Docker Orchestration & Virtual IoT Network`](./context/specs/01-docker-network-orchestration.md)**
2. **[`Unit 02: Mitigation Engine (iptables & Docker Quarantine)`](./context/specs/02-mitigation-engine.md)**
3. **[`Unit 03: Honeypot Ingestion Engine & Detection Core`](./context/specs/03-honeypot-ingestion-engine.md)**
4. **[`Unit 04: FastAPI Telemetry Engine & SSE Streaming API`](./context/specs/04-fastapi-telemetry-engine.md)**
5. **[`Unit 05: Single-Page Real-Time SOC Dashboard`](./context/specs/05-soc-dashboard.md)**
6. **[`Unit 06: Red Team Simulation & End-to-End Validation`](./context/specs/06-red-team-simulation.md)**

---

## Directory Structure

```text
.
├── .gitignore                              # Ignores Python caches, venvs, SQLite DBs, and live Cowrie logs
├── AGENTS.md                               # Universal AI agent context & workflow instructions
├── CLAUDE.md                               # Claude Code entry point referencing AGENTS.md
├── README.md                               # Setup guide, prerequisites, architecture & repo map
├── docker-compose.yml                      # 5-service orchestration (iot_production_net + iot_quarantine_net)
├── config/
│   └── mosquitto/
│       └── mosquitto.conf                  # Eclipse Mosquitto listener (:1883) & stdout logging config
├── context/
│   ├── ai-workflow-rules.md                # Scoping & verification workflow rules
│   ├── architecture.md                     # Subnets, security invariants & API architecture
│   ├── code-standards.md                   # Coding, typing & security rules
│   ├── progress-tracker.md                 # Completed milestones & current status
│   ├── project-overview.md                 # Product scope & feature definitions
│   ├── ui-context.md                       # Dark/Light theme tokens & tabbed layout specs
│   └── specs/
│       ├── 00-build-plan.md                # Master build sequence
│       ├── 01-docker-network-orchestration.md
│       ├── 02-mitigation-engine.md
│       ├── 03-honeypot-ingestion-engine.md
│       ├── 04-fastapi-telemetry-engine.md
│       ├── 05-soc-dashboard.md
│       └── 06-red-team-simulation.md
├── controller/                             # FastAPI SOC backend, detector & Netfilter/Docker controller
│   ├── Dockerfile                          # Python 3.11-slim + iptables + curl container image
│   ├── main.py                             # Uvicorn server entrypoint
│   ├── requirements.txt                    # Controller Python dependencies (fastapi, uvicorn, docker, paho-mqtt)
│   ├── api/
│   │   ├── __init__.py
│   │   ├── app.py                          # App factory, cache-control headers, tailer & MQTT lifecycle
│   │   ├── routes.py                       # REST endpoints (status, simulate, forensics, modes, devices)
│   │   └── sse_broker.py                   # Real-time Server-Sent Events broadcaster
│   ├── core/
│   │   ├── __init__.py
│   │   ├── db.py                           # SQLite schema & persistence (bans, settings, real devices)
│   │   ├── detector.py                     # In-memory sliding-window Cowrie threat detector
│   │   ├── device_manager.py               # Real hardware registry, SSRF guard, webhook auth & MJPEG proxy
│   │   ├── log_tailer.py                   # Async Cowrie JSON tailer with log-rotation/inode handling
│   │   ├── models.py                       # Structured dataclasses (CowrieEvent, MitigationRecord)
│   │   └── mqtt_listener.py                # Mosquitto home/# MQTT subscriber feeding SSE stream
│   ├── mitigation/
│   │   ├── __init__.py
│   │   ├── allowlist.py                    # Protected IP / gateway validation & spoofing guard
│   │   ├── firewall.py                     # Netfilter iptables IOT_DEFENSE_BLOCKLIST driver
│   │   └── quarantine.py                   # Docker SDK bridge isolation driver
│   ├── static/
│   │   ├── app.js                          # Vanilla ES6+ SOC dashboard client (SSE, Live/Sim, Dark/Light tabs)
│   │   └── images/
│   │       ├── architecture_overview.jpg   # Closed-loop defense pipeline illustration
│   │       └── dual_mode_comparison.jpg    # Simulated vs Live operating modes illustration
│   └── templates/
│       └── index.html                      # Multi-tab SOC terminal & documentation UI
├── data/                                   # Persistent SQLite store created at runtime (defense_history.db)
├── docs/
│   └── EVALUATION_RUNBOOK.md               # Step-by-step live demo script & evaluator Q&A
├── honeypot/
│   └── logs/                               # Shared Cowrie JSON log mount (cowrie.json written at runtime; .gitkeep tracked)
├── simulators/
│   ├── bulb/
│   │   ├── Dockerfile
│   │   ├── bulb.py                         # Virtual smart-bulb MQTT actuator node
│   │   └── requirements.txt
│   └── sensor/
│       ├── Dockerfile
│       ├── requirements.txt
│       └── sensor.py                       # Virtual temperature-sensor MQTT publisher node
└── tests/
    ├── attacker_sim.py                     # CLI Red Team adversary test script
    ├── test_api_endpoints.py               # REST & SSE API route unit tests
    ├── test_dashboard_ui.py                # Dashboard HTML/JS/CSS & asset serving tests
    ├── test_detection_engine.py            # Sliding-window detector & SQLite unit tests
    ├── test_end_to_end_pipeline.py         # Sub-second mitigation latency benchmark tests
    ├── test_live_mode_and_devices.py       # Simulated/Live toggle, SSRF guard, MQTT & log-rotation tests
    └── test_mitigation_drivers.py          # Allowlist, Netfilter & Docker quarantine driver tests
```
