# AI Workflow Rules

## Approach
Build this project incrementally using a spec-driven, test-verifiable workflow. The six context files (`project-overview.md`, `architecture.md`, `code-standards.md`, `ui-context.md`, `progress-tracker.md`, and `ai-workflow-rules.md`) define exact system behavior, technical constraints, and development status. 
Always implement against these specifications. Never invent redundant helper methods, arbitrary utility abstractions, or unapproved architectural frameworks.

## Scoping Rules
- Work on exactly one feature unit at a time (e.g., Honeypot Log Parser -> Firewall Controller -> SSE Broadcaster -> UI Integration).
- Every feature increment must be end-to-end verifiable using an executable command or script (e.g., running `attacker_sim.py` to verify an `iptables` entry).
- Never combine unrelated boundaries in a single turn (do not mix UI template updates with kernel firewall command refactoring).

## When to Split Work
Split an implementation step if it combines:
- OS-level kernel/Docker SDK manipulation and web frontend styling.
- Honeypot log parsing and MQTT message broker subscription logic.
- Threat detection threshold tuning and SQLite schema migrations.

If a proposed change cannot be tested and verified in isolation within 2 minutes, the scope is too broad—break it down.

## Handling Missing Requirements & Ambiguities
- Do not make speculative assumptions about security thresholds, network subnets, or honeypot credentials not documented in `architecture.md` or `project-overview.md`.
- If an operational parameter (e.g., failed login ban threshold, ban TTL duration) is ambiguous, stop and record it as an open question in `progress-tracker.md` before writing code.
- If an architectural choice requires trade-offs (e.g., raw sockets vs. Scapy for traffic sniffing), present the technical options and await confirmation before implementing.

## Protected Files & Directories
Do not rewrite or modify these assets unless specifically directed:
- `honeypot/cowrie.cfg` — Cowrie operational configuration; changes risk breaking honeypot emulation.
- `config/mosquitto.conf` — Core broker listener definitions.
- `static/` — Vendor assets and base third-party styling tokens.

## Keeping Docs in Sync
Update the relevant context file immediately whenever implementation changes:
- If a new Docker container or network bridge is introduced -> Update `architecture.md`.
- If an anomaly detection rule or threshold is calibrated -> Update `project-overview.md`.
- If a new SSE event or API endpoint is exposed -> Update `architecture.md` and `code-standards.md`.
- After every completed milestone or newly uncovered technical gap -> Update `progress-tracker.md`.

## Before Moving to the Next Unit
Verify the following checklist before considering any feature unit complete:
1. The code runs without unhandled exceptions and accomplishes its targeted task end-to-end.
2. Invariants in `architecture.md` are completely respected (allowlist verified, no direct `INPUT` table pollution).
3. Code conforms to type-hinting and parameterization standards in `code-standards.md`.
4. `progress-tracker.md` is updated to mark the item completed and set the next goal.

