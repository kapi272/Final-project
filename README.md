# Autonomous IoT Cyber Defense System

An autonomous, containerized host-level IoT cyber defense testbed using virtual IoT nodes, Cowrie honeypot deception, and closed-loop automated mitigation.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Docker Compose](https://img.shields.io/badge/Docker-Compose%20v2+-2496ED?logo=docker&logoColor=white)](https://www.docker.com/)
[![Release: v1.8.0](https://img.shields.io/badge/Release-v1.8.0-blue)](./)
[![Reaction SLA](https://img.shields.io/badge/Mitigation%20Latency-0.65%20ms-emerald)](./context/specs/06-red-team-simulation.md)
[![Tests Passing](https://img.shields.io/badge/Tests-38%2F38%20Passing-brightgreen)](./tests/)

---

## Overview

This project simulates an enterprise and smart-home IoT ecosystem entirely within Docker containers. By embedding an instrumented deception layer alongside virtual IoT nodes, the system captures adversarial reconnaissance and credential brute-force attacks in real time. An integrated analytics engine evaluates honeypot triggers and dynamically executes kernel firewall (`iptables`) drop rules and Docker network quarantines in sub-second response times (< 1,000 ms).

Built following the **Six-File Context Methodology** for spec-driven, predictable AI-assisted development.

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

## Quick Start

### 1. Boot the Entire Testbed (5 Containers)
```bash
docker compose up -d
```

### 2. Access the SOC Terminal Dashboard
Open your browser at:
👉 **`http://localhost:8050`**

### 3. Launch the Automated Red Team Attack Simulation
In a separate terminal window:
```bash
python3 tests/attacker_sim.py --all
```

---

## Specifications & Documentation

All architectural decisions, invariants, and build plans are organized in [`context/`](./context/):

| Document | Purpose |
| :--- | :--- |
| **[`docs/EVALUATION_RUNBOOK.md`](./docs/EVALUATION_RUNBOOK.md)** | **Live demonstration script, evaluator Q&A, and viva walkthrough** |
| **[`context/specs/00-build-plan.md`](./context/specs/00-build-plan.md)** | Unit breakdown, dependency graph, and implementation order |
| **[`context/project-overview.md`](./context/project-overview.md)** | Core user flow, goals, in-scope & out-of-scope features |
| **[`context/architecture.md`](./context/architecture.md)** | Network topology, system boundaries, storage & security invariants |
| **[`context/code-standards.md`](./context/code-standards.md)** | Python type safety, FastAPI conventions, error handling |
| **[`context/ai-workflow-rules.md`](./context/ai-workflow-rules.md)** | Spec-driven workflow, verification criteria, change protocol |
| **[`context/ui-context.md`](./context/ui-context.md)** | Dark SOC terminal design tokens, Tailwind palette |
| **[`context/progress-tracker.md`](./context/progress-tracker.md)** | Real-time project phase, completed items, next units |

---

## Unit Build Specifications

1. **[`Unit 01: Docker Orchestration & Virtual IoT Network`](./context/specs/01-docker-network-orchestration.md)**
2. **[`Unit 02: Mitigation Engine (iptables & Docker Quarantine)`](./context/specs/02-mitigation-engine.md)**
3. **[`Unit 03: Honeypot Ingestion Engine & Detection Core`](./context/specs/03-honeypot-ingestion-engine.md)**
4. **[`Unit 04: FastAPI Telemetry Engine & SSE Streaming API`](./context/specs/04-fastapi-telemetry-engine.md)**
5. **[`Unit 05: Single-Page Real-Time SOC Dashboard`](./context/specs/05-soc-dashboard.md)**
6. **[`Unit 06: Red Team Simulation & End-to-End Validation`](./context/specs/06-red-team-simulation.md)**

---

## Automated Test Suite

Run the full automated test suite (35 tests across all units):
```bash
python3 -m unittest discover -s tests
```

---

## Directory Structure

```
.
├── AGENTS.md                  # Universal AI agent instructions
├── CLAUDE.md                  # Claude Code entry point
├── docker-compose.yml         # 5-service container orchestration
├── config/
│   └── mosquitto/             # Mosquitto MQTT broker configuration
├── context/                   # Six-File Context methodology documents
│   └── specs/                 # Feature unit specifications and build plan
├── controller/                # FastAPI controller, Netfilter driver & SSE engine
│   ├── api/                   # REST endpoints and SSE event broadcaster
│   ├── core/                  # Honeypot log tailer, sliding window & SQLite DB
│   ├── mitigation/            # iptables blocklist & Docker quarantine drivers
│   ├── static/                # Vanilla ES6 SOC dashboard scripts
│   └── templates/             # Single-page SOC HTML interface
├── docs/                      # Evaluation runbook & presentation guide
├── simulators/                # Virtual IoT devices (sensor, smart bulb)
├── honeypot/                  # Cowrie decoy configuration & shared logs
└── tests/                     # Automated adversary testing scripts & benchmarks
```
