#!/usr/bin/env python3
"""
Automated Red Team Adversary Simulation Script
Simulates port sweeps, SSH/Telnet brute-force dictionary attacks, and
rogue container lateral infections against the Autonomous IoT Defense Testbed.
"""

import argparse
import json
import socket
import sys
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Tuple

TARGET_HOST: str = "127.0.0.1"
API_PORT: int = 8000
HONEYPOT_SSH_PORT: int = 2222
HONEYPOT_TELNET_PORT: int = 2223
MQTT_PORT: int = 1883

DEFAULT_CREDENTIALS: List[Tuple[str, str]] = [
    ("root", "root"),
    ("admin", "admin"),
    ("admin", "123456"),
    ("default", "default"),
    ("root", "toor"),
    ("cisco", "cisco"),
    ("support", "support"),
]


def print_banner() -> None:
    print("=" * 70)
    print("  AUTONOMOUS IoT CYBER DEFENSE TESTBED — RED TEAM ATTACK SUITE")
    print("=" * 70)


def scan_port(host: str, port: int, timeout: float = 0.5) -> bool:
    """Attempts a TCP handshake to detect open listeners."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((host, port)) == 0
    except Exception:
        return False


def run_port_sweep(target: str) -> Dict[int, bool]:
    print(f"\n[*] Executing Reconnaissance Port Sweep on target {target}...")
    ports = [21, MQTT_PORT, HONEYPOT_SSH_PORT, HONEYPOT_TELNET_PORT, API_PORT]
    results = {}

    for port in ports:
        is_open = scan_port(target, port)
        results[port] = is_open
        status_label = "\033[92mOPEN\033[0m" if is_open else "\033[90mCLOSED/FILTERED\033[0m"
        print(f"    - TCP Port {port:5d} : {status_label}")

    return results


def send_raw_banner_probe(target: str, port: int, payload: bytes) -> str:
    """Connects to target port, sends payload, and captures banner response."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.0)
            s.connect((target, port))
            banner = s.recv(1024)
            s.sendall(payload)
            response = s.recv(1024)
            return (banner + response).decode("utf-8", errors="ignore")
    except Exception as e:
        return f"Error: {e}"


def run_brute_force_ssh(target: str, port: int = HONEYPOT_SSH_PORT) -> bool:
    print(f"\n[*] Launching Credential Brute-Force attack against Honeypot (TCP {port})...")
    is_open = scan_port(target, port)

    if not is_open:
        print(f"    [!] Port {port} is not accessible on {target}. (Ensure docker-compose is running).")
        return False

    success_count = 0
    start_time = time.time()

    for idx, (user, pwd) in enumerate(DEFAULT_CREDENTIALS, 1):
        # Fake SSH handshake or probe
        res = send_raw_banner_probe(target, port, f"SSH-2.0-Attacker_Probe_{user}\r\n".encode())
        elapsed = (time.time() - start_time) * 1000
        print(f"    [{idx}/{len(DEFAULT_CREDENTIALS)}] Attempt '{user}:{pwd}' -> Response ({elapsed:.1f}ms)")
        success_count += 1
        time.sleep(0.3)

    return success_count > 0


def trigger_api_infection_test(api_base: str, node_id: str = "iot_sensor_node") -> bool:
    print(f"\n[*] Simulating Rogue Container Infection on '{node_id}'...")
    url = f"{api_base}/api/simulate/infect/{node_id}"

    try:
        req = urllib.request.Request(url, method="POST", data=b"{}")
        req.add_header("Content-Type", "application/json")
        start = time.time()
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            elapsed_ms = (time.time() - start) * 1000
            data = json.loads(resp.read().decode())
            print(f"    [+] Response ({elapsed_ms:.1f}ms): {data.get('message')}")
            return data.get("status") == "success"
    except Exception as e:
        print(f"    [!] Infection simulation API error: {e}")
        return False


def verify_active_mitigations(api_base: str) -> Dict[str, Any]:
    url = f"{api_base}/api/defense/status"
    try:
        with urllib.request.urlopen(url, timeout=3.0) as resp:
            data = json.loads(resp.read().decode())
            return data.get("data", {})
    except Exception as e:
        print(f"    [!] Could not query defense status API: {e}")
        return {}


def main() -> None:
    parser = argparse.ArgumentParser(description="Autonomous IoT Cyber Defense Red Team Test Suite")
    parser.add_argument("--host", default=TARGET_HOST, help="Target host address (default: 127.0.0.1)")
    parser.add_argument("--port-sweep", action="store_true", help="Run TCP reconnaissance sweep")
    parser.add_argument("--brute-force", action="store_true", help="Launch credential brute-force probe")
    parser.add_argument("--infect", action="store_true", help="Simulate rogue internal container compromise")
    parser.add_argument("--all", action="store_true", help="Run full automated red team test suite")

    args = parser.parse_args()

    # Default to --all if no specific flag passed
    if not (args.port_sweep or args.brute_force or args.infect or args.all):
        args.all = True

    print_banner()
    api_url = f"http://{args.host}:{API_PORT}"

    if args.port_sweep or args.all:
        run_port_sweep(args.host)

    if args.brute_force or args.all:
        run_brute_force_ssh(args.host)

    if args.infect or args.all:
        trigger_api_infection_test(api_url, "iot_sensor_node")

    print("\n" + "=" * 70)
    print("  VERIFYING REALTIME SOC DEFENSE STATUS VIA CONTROLLER API")
    print("=" * 70)
    status_data = verify_active_mitigations(api_url)

    if status_data:
        bans = status_data.get("banned_ips", [])
        nodes = status_data.get("node_states", {})
        print(f"  * Active Firewall Drops : {len(bans)} {bans}")
        print("  * Virtual Node States   :")
        for node, st in nodes.items():
            print(f"      - {node:22s} : {st}")
    else:
        print("  (Controller API currently offline; start with `python controller/main.py`)")

    print("\n[*] Adversary test sequence finished.\n")


if __name__ == "__main__":
    main()
