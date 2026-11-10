# Autonomous IoT Cyber Defense System

An autonomous, containerized host-level IoT cyber defense testbed using virtual IoT nodes, Cowrie honeypot deception, and closed-loop automated mitigation.

---

## Overview

This project simulates an enterprise and smart-home IoT ecosystem entirely within Docker containers. By embedding a deception layer alongside virtual IoT nodes, the system captures adversarial reconnaissance and credential brute-force attacks in real time. An analytics controller evaluates honeypot triggers and dynamically executes kernel firewall (`iptables`) drop rules and Docker network quarantines in under 1,000 ms.

Built following the **Six-File Context Methodology** for spec-driven, predictable AI-assisted development.

---

## Architecture & Specifications

All system architecture, design rules, and build specifications are documented under [`context/`](./context/):

| Document | Purpose |
| :--- | :--- |
| **[`context/project-overview.md`](./context/project-overview.md)** | Core user flow, goals, in-scope & out-of-scope features |
| **[`context/architecture.md`](./context/architecture.md)** | Network topology, system boundaries, storage & security invariants |
| **[`context/code-standards.md`](./context/code-standards.md)** | Python type safety, FastAPI conventions, error handling |
| **[`context/ai-workflow-rules.md`](./context/ai-workflow-rules.md)** | Spec-driven workflow, verification criteria, change protocol |
| **[`context/ui-context.md`](./context/ui-context.md)** | Dark SOC terminal design tokens, Tailwind palette |
| **[`context/progress-tracker.md`](./context/progress-tracker.md)** | Real-time project phase, completed items, next units |

### Build Plan
The project is built unit-by-unit according to **[`context/specs/00-build-plan.md`](./context/specs/00-build-plan.md)**:
1. **Unit 01:** Docker Orchestration & Virtual IoT Network
2. **Unit 02:** Mitigation Engine (`iptables` & Docker Quarantine)
3. **Unit 03:** Honeypot Ingestion Engine & Detection Core
4. **Unit 04:** FastAPI Telemetry Engine & SSE Streaming API
5. **Unit 05:** Single-Page Real-Time SOC Dashboard
6. **Unit 06:** Red Team Simulation & End-to-End Validation

---

## Directory Structure

```
.
├── AGENTS.md                  # Universal AI agent instructions
├── CLAUDE.md                  # Claude Code entry point
├── config/
│   └── mosquitto/             # Mosquitto MQTT broker configuration
├── context/                   # Six-File Context methodology documents
│   └── specs/                 # Feature unit specifications and build plan
├── simulators/                # Virtual IoT devices (sensor, smart bulb)
├── controller/                # Defense controller, detection core & mitigation (Units 2-4)
├── honeypot/                  # Cowrie decoy configuration & logs
└── tests/                     # Automated adversary testing scripts (Unit 6)
```
