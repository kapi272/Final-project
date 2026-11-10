# Unit 06: Red Team Simulation & End-to-End Autonomous Validation

## Goal
Build an automated adversary test script (`tests/attacker_sim.py`) that simulates real-world attack vectors against the virtual IoT network (reconnaissance port sweeps, SSH/Telnet credential brute-forcing, and rogue container lateral compromise). The script measures closed-loop defense reaction latency, verifying sub-second (<1,000 ms) autonomous detection, Netfilter firewall drop enforcement, and dynamic container quarantine.

## Design & Verification Invariants
- **Non-Destructive Simulation:** Target only the virtual subnet (`172.20.0.0/24`) or local Docker exposed ports (`2222`, `2223`, `1883`, `8000`). Never target host production interfaces or loopback critical services.
- **Deterministic Latency Measurement:** Measure elapsed time between the threshold-breaching attack packet and the appearance of the offending IP in the active firewall drop inventory.
- **Automated Validation:** Provide both a CLI executable script and an automated unit test suite verifying each attack phase.

## Implementation

### 1. `tests/attacker_sim.py`
- Modes:
  - `--port-sweep`: Scans ports 21 (FTP), 1883 (MQTT), 2222 (Cowrie SSH), 2223 (Cowrie Telnet), 8000 (Controller API).
  - `--brute-force`: Sends rapid authentication attempts against Cowrie honeypot ports with dictionary credentials.
  - `--exploit`: Injects terminal commands into the honeypot trap to trigger critical exploit mitigations.
  - `--infect`: Calls `/api/simulate/infect/iot_sensor_node` to trigger dynamic container quarantine.
  - `--all`: Runs the full end-to-end adversary test sequence and outputs a summary latency scorecard.

### 2. `tests/test_end_to_end_pipeline.py`
- Automated test mocking the end-to-end pipeline:
  - Injects synthetic Cowrie attack events into `IntrusionDetector`.
  - Verifies firewall `IOT_DEFENSE_BLOCKLIST` drops offending IP within sub-millisecond in-memory time.
  - Verifies SQLite audit record reflects the event.
  - Verifies SSE broadcaster distributes alert.

## Dependencies
- Standard library: `socket`, `time`, `urllib.request`, `argparse`, `json`
- Python unit test runner

## Verify when done
- [x] `attacker_sim.py` executes without uncaught exceptions and supports `--dry-run` or live mode.
- [x] Brute-force simulation triggers sub-second autonomous mitigation response.
- [x] Latency scorecard reports response time under 1,000 ms.
- [x] Full end-to-end pipeline test suite passes.
