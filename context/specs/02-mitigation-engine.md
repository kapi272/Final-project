# Unit 02: Mitigation Engine & Container Quarantine

## Goal
Implement isolated, injection-safe mitigation drivers for external system execution:
1. `allowlist.py`: Validates IP addresses against non-negotiable management allowlists using Python's standard `ipaddress` library.
2. `firewall.py`: Idempotent Netfilter/`iptables` driver managing the custom `IOT_DEFENSE_BLOCKLIST` chain linked to `DOCKER-USER` with parameterized execution.
3. `quarantine.py`: Dynamic container containment driver wrapping Docker Python SDK (`docker-py`) to migrate compromised containers from `iot_production_net` to `iot_quarantine_net`.

## Design & Architecture Invariants
- **Command Injection Protection:** Never construct shell commands via string concatenation or f-strings. All OS subprocess executions must pass explicit argument lists to `subprocess.run()`.
- **Chain Isolation:** Only manipulate `IOT_DEFENSE_BLOCKLIST`. Never flush or directly mutate the system `INPUT` or `FORWARD` chains.
- **Rule Idempotency:** Check if a rule exists (`iptables -C`) before attempting insertion (`iptables -I`) or deletion (`iptables -D`).
- **Strict Allowlist:** Reject any ban operation targeting `127.0.0.1`, `::1`, docker subnet gateways (`172.20.0.1`), or local LAN management CIDRs (`192.168.0.0/16`, `10.0.0.0/8`).
- **No Blind Disconnects:** Container quarantine must disconnect from `iot_production_net` and immediately connect to `iot_quarantine_net` (`internal: true`) for forensic retention without lateral spread.

## Implementation

### 1. `controller/mitigation/allowlist.py`
- Define default protected subnets and host IPs.
- Method `is_ip_protected(ip_str: str) -> bool`: parses and tests whether an IP falls into loopback, private gateway, or admin allowlists.
- Method `validate_target_ip(ip_str: str) -> str`: validates syntactic IPv4/IPv6 format and raises `ValueError` if invalid or protected.

### 2. `controller/mitigation/firewall.py`
- Class `FirewallController`:
  - `initialize_chains()`: ensures `IOT_DEFENSE_BLOCKLIST` exists and is referenced in `DOCKER-USER`.
  - `ban_ip(ip: str) -> bool`: verifies allowlist, checks idempotency via `-C`, inserts rule via `-I IOT_DEFENSE_BLOCKLIST 1 -s <IP> -j DROP`.
  - `unban_ip(ip: str) -> bool`: checks if rule exists, removes rule via `-D IOT_DEFENSE_BLOCKLIST -s <IP> -j DROP`.
  - `list_banned_ips() -> List[str]`: queries `iptables -S IOT_DEFENSE_BLOCKLIST` and returns active drop IPs.
  - `flush_blocklist() -> bool`: flushes `IOT_DEFENSE_BLOCKLIST` only.

### 3. `controller/mitigation/quarantine.py`
- Class `QuarantineManager`:
  - `quarantine_container(container_name_or_id: str) -> Dict[str, Any]`: connects to Docker API via `/var/run/docker.sock`, detaches from `iot_production_net`, attaches to `iot_quarantine_net`.
  - `restore_container(container_name_or_id: str) -> Dict[str, Any]`: detaches from `iot_quarantine_net`, reattaches to `iot_production_net`.
  - `get_container_network_status(container_name_or_id: str) -> str`: returns `"production"`, `"quarantined"`, or `"unknown"`.

## Dependencies
- `docker>=7.0.0`
- Python standard library (`subprocess`, `ipaddress`, `typing`, `logging`)

## Verify when done
- [x] Allowlist rejects loopback, gateway, and invalid IPs with explicit errors.
- [x] Firewall driver methods use parameterized arguments (no raw shell string execution).
- [x] Quarantine driver handles missing containers and network transitions cleanly.
- [x] All Unit 02 driver unit tests pass.

