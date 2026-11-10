# Unit 03: Honeypot Ingestion Engine & Detection Core

## Goal
Build the core ingestion and detection engine that continuously monitors honeypot event logs (`honeypot/logs/cowrie.json`), tracks attack patterns using in-memory sliding windows (`collections.deque`), enforces autonomous mitigation policies (triggering Unit 02 firewall bans upon threshold breaches), and persists mitigation audit trails in an embedded SQLite database (`data/defense_history.db`).

## Design & Architecture Invariants
- **Non-blocking Log Consumption:** The log tailer must use asynchronous file-pointer tracking (`seek` + `readline`) to prevent blocking the event loop or web server.
- **Sub-Second Evaluation:** Sliding-window frequency checks must execute in memory via double-ended queues (`collections.deque`) with `O(1)` pops for expired timestamps.
- **Persistent Audit Logging:** Every intrusion event classification, ban enforcement, and unban action must be recorded with UTC timestamps, threat severity (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), source IP, and trigger reason in `data/defense_history.db`.
- **Decoupled Architecture:** The detector triggers callbacks without hardcoupling to network protocols, allowing seamless connection to SSE broadcast queues in Unit 04.

## Implementation

### 1. `controller/core/models.py`
- Structured dataclasses for:
  - `CowrieEvent`: parsed raw JSON event fields (eventid, src_ip, timestamp, username, password, command, etc.)
  - `AttackClassification`: categorized attack type (`BRUTE_FORCE`, `PORT_SWEEP`, `COMMAND_INJECTION`, `UNKNOWN`)
  - `MitigationRecord`: persistent database model (id, timestamp, src_ip, action, reason, severity)

### 2. `controller/core/db.py`
- Class `DefenseDatabase`:
  - `init_db()`: provisions tables `defense_history` and `active_bans`.
  - `record_mitigation(...)`: inserts ban/unban event into history table.
  - `get_history(limit: int = 50)`: fetches recent audit events.
  - `get_active_bans()`: returns currently active banned records.
  - `remove_active_ban(src_ip: str)`: updates ban status upon manual unban.

### 3. `controller/core/detector.py`
- Class `IntrusionDetector`:
  - Configurable thresholds: `failed_login_threshold=5`, `time_window_seconds=30.0`.
  - In-memory state: `Dict[str, deque]` tracking event timestamps per source IP.
  - `process_event(event: CowrieEvent) -> Optional[MitigationRecord]`:
    - Filters allowlisted IPs.
    - Increments frequency counter.
    - If threshold exceeded, calls `FirewallController.ban_ip(src_ip)`, records to DB, and returns `MitigationRecord`.

### 4. `controller/core/log_tailer.py`
- Class `HoneypotLogTailer`:
  - Asynchronous tailer that tails `honeypot/logs/cowrie.json`.
  - Gracefully handles file creation latency (file not existing at startup).
  - Yields or dispatches parsed `CowrieEvent` instances to detector.

## Dependencies
- Standard library: `sqlite3`, `collections`, `asyncio`, `json`, `dataclasses`, `time`
- Unit 02 mitigation driver (`FirewallController`, `AllowlistManager`)

## Verify when done
- [x] Database provisions tables and handles concurrent transactions cleanly.
- [x] Log tailer parses malformed lines without crashing and tails active appends.
- [x] Detector accurately triggers ban and records audit row when 5 failed logins occur within 30s.
- [x] Protected allowlist IPs are never banned even if threshold is exceeded.
- [x] Unit 03 test suite passes.

