# Unit 01: Docker Orchestration & Virtual IoT Network

## Goal
Provision the containerized virtual IoT network infrastructure via Docker Compose, including isolated dual-bridge subnets (`iot_production_net` and `iot_quarantine_net`), an Eclipse Mosquitto MQTT broker, synthetic IoT sensor/actuator simulator containers, and a Cowrie honeypot decoy instance.

## Design
- **Subnet Configuration:**
  - `iot_production_net`: `172.20.0.0/24`, Gateway: `172.20.0.1` (normal communication)
  - `iot_quarantine_net`: `172.21.0.0/24`, `internal: true` (strictly isolated, zero external routing)
- **Static IP Allocations:**
  - Mosquitto Broker: `172.20.0.10`
  - Temperature Sensor: `172.20.0.21`
  - Smart Bulb: `172.20.0.22`
  - Cowrie Honeypot: `172.20.0.50`
- **Volume Shares:**
  - `./honeypot/logs:/cowrie/var/log/cowrie`: allows host and controller to inspect `cowrie.json` in real time.
  - `./config/mosquitto/mosquitto.conf:/mosquitto/config/mosquitto.conf`: custom broker listener config.

## Implementation

### 1. Broker Configuration (`config/mosquitto/mosquitto.conf`)
- Listen on standard port `1883` on all interfaces (`0.0.0.0`).
- Allow anonymous connections for synthetic internal IoT devices (`allow_anonymous true`).
- Enable standard stdout logging.

### 2. IoT Simulators (`simulators/`)
- `simulators/sensor/sensor.py`: Lightweight Python client using `paho-mqtt` to publish JSON telemetry (`{"device_id": "temp_sensor_01", "temperature": 22.5, "unit": "C", "timestamp": ...}`) to `home/sensors/temperature` every 2 seconds. Includes a lightweight `Dockerfile`.
- `simulators/bulb/bulb.py`: Lightweight Python client subscribing to `home/devices/bulb/set` and publishing state updates to `home/devices/bulb/status`. Includes a lightweight `Dockerfile`.

### 3. Honeypot Configuration (`honeypot/`)
- Standard Cowrie Docker deployment mapping ports `2222:2222` (SSH) and `2223:2223` (Telnet).
- Shared directory for live JSON telemetry streaming (`./honeypot/logs`).

### 4. Docker Compose Orchestration (`docker-compose.yml`)
- Define networks `iot_production_net` and `iot_quarantine_net`.
- Services: `mqtt_broker`, `sensor_node`, `bulb_node`, `cowrie_honeypot`.

## Dependencies
- Docker Engine & Docker Compose
- Python 3.11-slim (for simulator containers)
- `paho-mqtt` (for simulators)

## Verify when done
- [ ] `docker-compose config` validates without syntax or network errors.
- [ ] `config/mosquitto/mosquitto.conf` is present with anonymous access enabled.
- [ ] `simulators/sensor/` and `simulators/bulb/` contain runnable code and Dockerfiles.
- [ ] Directory `honeypot/logs/` is initialized and volume-mounted.

