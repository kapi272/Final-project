# Code Standards

## General
- Keep modules small and single-purpose: separate detection logic, OS-level mitigations, and API handlers.
- Fix root causes in network, process, and concurrency handling; do not layer arbitrary `time.sleep()` workarounds.
- Do not mix unrelated concerns in one component, route, or service module.
- Clean up system state on teardown: unhook custom firewall chains and restore quarantined containers during testing and session resets.

## Python

### Type Hinting & Safety
- Enforce explicit type annotations (`typing.Optional`, `typing.List`, `typing.Dict`, `typing.Set`, `typing.Tuple`, `collections.deque`) across all module functions and class methods.
- Avoid untyped dynamic mappings or arbitrary dict mutations where structured models or named dataclasses can be defined.
- Validate all external network inputs (IP addresses, CIDR blocks, port ranges) at system boundaries using Python's standard `ipaddress` module before trusting them.
- Never construct shell commands via string concatenation or f-strings (e.g., `f"iptables -A ... {user_ip}"`). Always use parameterized argument lists via `subprocess.run(["iptables", ...])` to prevent command-injection vulnerabilities.

### Concurrency & Error Handling
- Never use bare `except:` blocks; always catch narrow, explicit exceptions (`subprocess.CalledProcessError`, `docker.errors.APIError`, `docker.errors.NotFound`, `json.JSONDecodeError`, `ValueError`).
- Background workers (such as the honeypot file-tailing loop) must run via asynchronous tasks (`asyncio.create_task`) or non-blocking daemon threads guarded by explicit cancellation signals.
- Log all operational exceptions with contextual metadata using Python's built-in `logging` module rather than raw `print()` statements.

## API Routes & Telemetry (FastAPI)

- Validate and parse request input before any business or mitigation logic runs.
- Keep route handlers focused on a single responsibility; delegate Docker operations and firewall mutations to dedicated controllers.
- Return consistent, predictable response shapes across all endpoints:
  ```json
  {
    "status": "success",
    "timestamp": 1718000000.0,
    "data": {}
  }
  ```
- SSE streaming routes (`/api/stream`) must enforce exact non-buffering headers:
  - `Cache-Control: no-cache`
  - `Connection: keep-alive`
  - `X-Accel-Buffering: no`

## System Calls (iptables & Docker Engine SDK)

- Enforce rule idempotency: test if a firewall rule exists (`iptables -C`) before attempting to insert (`iptables -I`).
- Isolate all OS subshell calls inside `controller/mitigation/` — no system calls are permitted directly from API route handlers or frontend endpoints.
- Docker SDK operations must gracefully handle missing containers (`docker.errors.NotFound`) and manage reconnections to `/var/run/docker.sock` across host restarts.

## Styling & Frontend (Dashboard)

- Zero heavy frontend build chains: use Tailwind CSS via CDN and native ES6+ vanilla JavaScript.
- Maintain consistent visual tokens: dark theme background (`#0b0f19`), surface cards (`#0f172a`), emerald for healthy nodes, amber for honeypot traps, and rose/red for threat mitigations.
- Sanitize external input: never interpolate raw attacker-supplied strings (such as shell commands or usernames) using `innerHTML`; use `innerText` or `textContent` to prevent DOM XSS.

## Data and Storage

- Ephemeral runtime counters and sliding-window event queues belong in memory (`collections.deque`, sets) for sub-millisecond evaluation.
- Structured mitigation records, attack timestamps, and ban audit trails belong in the local embedded database (`data/defense_history.db`).
- Large raw payload captures or downloaded honeypot binaries belong in persistent file storage (`honeypot/downloads/`), not inside the database.

## File Organization

- `simulators/` — Lightweight Docker containers and Python scripts for simulated IoT devices (sensor, smart bulb).
- `honeypot/` — Cowrie configuration files (`cowrie.cfg`), download traps, and JSON event logs.
- `controller/core/` — Detection state machine, sliding-window log parser, and IP allowlist logic.
- `controller/mitigation/` — Isolated drivers for iptables execution and Docker SDK container quarantine.
- `controller/api/` — FastAPI application definitions, REST routes, and SSE queue dispatcher.
- `controller/templates/` — HTML dashboard layouts (`index.html`).
- `tests/` — Automated adversary test scripts (`attacker_sim.py`).

