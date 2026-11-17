from collections import deque
import logging
import time
from typing import Any, Callable, Dict, List, Optional

from controller.core.db import DefenseDatabase
from controller.core.models import CowrieEvent, MitigationRecord
from controller.mitigation.allowlist import AllowlistManager
from controller.mitigation.firewall import FirewallController

logger = logging.getLogger(__name__)

DEFAULT_FAILED_LOGIN_THRESHOLD: int = 5
DEFAULT_TIME_WINDOW_SECONDS: float = 30.0

CRITICAL_COMMAND_PATTERNS: List[str] = [
    "wget ",
    "curl ",
    "chmod +x",
    "rm -rf",
    "nc -e",
    "/bin/sh",
    "/bin/bash",
    "cat /etc/passwd",
    "cat /etc/shadow",
]

MQTT_HONEY_TOPIC_PREFIXES: List[str] = [
    "home/admin/",
    "home/debug/",
    "home/system/",
    "home/gateway/",
]

MQTT_HONEY_TOPIC_EXACT: List[str] = [
    "home/admin/config",
    "home/admin/credentials",
    "home/debug/shell",
    "home/system/firmware_update",
    "home/gateway/exec",
]

MAX_MQTT_PAYLOAD_BYTES: int = 32 * 1024  # 32 KB
DEFAULT_MQTT_RATE_LIMIT: int = 20  # Max 20 msgs in 5s
DEFAULT_MQTT_RATE_WINDOW: float = 5.0


class IntrusionDetector:
    """
    Evaluates honeypot telemetry in real time using in-memory sliding windows.
    Autonomously executes kernel firewall bans and logs audit trails upon policy breaches.
    """

    def __init__(
        self,
        firewall: Optional[FirewallController] = None,
        db: Optional[DefenseDatabase] = None,
        allowlist: Optional[AllowlistManager] = None,
        failed_login_threshold: int = DEFAULT_FAILED_LOGIN_THRESHOLD,
        time_window_seconds: float = DEFAULT_TIME_WINDOW_SECONDS,
        on_mitigation_callback: Optional[Callable[[MitigationRecord], Any]] = None,
    ) -> None:
        self.firewall: FirewallController = firewall or FirewallController(dry_run=True)
        self.db: DefenseDatabase = db or DefenseDatabase()
        self.allowlist: AllowlistManager = allowlist or AllowlistManager()
        self.failed_login_threshold: int = failed_login_threshold
        self.time_window_seconds: float = time_window_seconds
        self.on_mitigation_callback = on_mitigation_callback

        # In-memory sliding window: IP -> deque of timestamps
        self._failed_attempts: Dict[str, deque] = {}
        # In-memory sliding window for MQTT publish rates: tracking_key -> deque of timestamps
        self._mqtt_publish_times: Dict[str, deque] = {}

        # Telemetry analytics counters
        self._attack_counts: Dict[str, int] = {"brute_force": 0, "exploit": 0, "probe": 0}
        self._username_counts: Dict[str, int] = {}
        self._password_counts: Dict[str, int] = {}
        self._port_counts: Dict[str, int] = {"2222": 0, "2223": 0, "1883": 0}
        self._events_history: List[Dict[str, Any]] = []

        # Hydrate threat analytics and recent event history from persistent storage
        self._hydrate_analytics_from_db()

    def _hydrate_analytics_from_db(self) -> None:
        """Hydrates in-memory threat counters and event history from SQLite."""
        try:
            persisted = self.db.get_persisted_threat_analytics()
            if persisted.get("total_threat_events", 0) > 0:
                self._attack_counts.update(persisted.get("attack_breakdown", {}))
                self._username_counts = dict(persisted.get("top_usernames", []))
                self._password_counts = dict(persisted.get("top_passwords", []))
                self._port_counts.update(persisted.get("target_ports", {}))

            recent = self.db.get_recent_threat_events(limit=500)
            if recent:
                self._events_history = recent
            logger.info("IntrusionDetector analytics hydrated from database (%d events).", len(recent))
        except Exception as e:
            logger.warning("Could not hydrate IntrusionDetector analytics from database: %s", e)

    def _prune_expired_attempts(self, ip: str, now: float) -> None:
        """Removes timestamps outside the rolling time window."""
        queue = self._failed_attempts.get(ip)
        if not queue:
            return
        cutoff = now - self.time_window_seconds
        while queue and queue[0] < cutoff:
            queue.popleft()
        if not queue:
            self._failed_attempts.pop(ip, None)

    def process_event(self, event: CowrieEvent) -> Optional[MitigationRecord]:
        """
        Analyzes an incoming CowrieEvent and returns a MitigationRecord if autonomous
        action was triggered.
        """
        src_ip = event.src_ip.strip()

        # Update telemetry analytics counters
        if event.dst_port:
            port_key = str(event.dst_port)
            self._port_counts[port_key] = self._port_counts.get(port_key, 0) + 1
        elif event.eventid.startswith("cowrie"):
            self._port_counts["2222"] = self._port_counts.get("2222", 0) + 1

        if event.username:
            self._username_counts[event.username] = self._username_counts.get(event.username, 0) + 1
        if event.password:
            self._password_counts[event.password] = self._password_counts.get(event.password, 0) + 1

        attack_type = "probe"
        if event.eventid == "cowrie.login.failed":
            self._attack_counts["brute_force"] = self._attack_counts.get("brute_force", 0) + 1
            attack_type = "brute_force"
        elif event.eventid in ["cowrie.client.version", "cowrie.session.connect"]:
            self._attack_counts["probe"] = self._attack_counts.get("probe", 0) + 1
            attack_type = "probe"
        elif event.eventid == "cowrie.command.input":
            self._attack_counts["exploit"] = self._attack_counts.get("exploit", 0) + 1
            attack_type = "exploit"

        event_record = {
            "timestamp": event.timestamp,
            "src_ip": src_ip,
            "dst_port": event.dst_port or 2222,
            "eventid": event.eventid,
            "attack_type": attack_type,
            "username": event.username or "",
            "password": event.password or "",
            "input_command": event.input_command or "",
            "message": event.message or "",
        }
        self._events_history.append(event_record)
        if len(self._events_history) > 500:
            self._events_history = self._events_history[-500:]

        try:
            self.db.record_threat_event(event_record)
        except Exception as e:
            logger.error("Failed to persist threat event to database: %s", e)

        # Invariant check: Allowlisted and management IPs are never banned
        if self.allowlist.is_ip_protected(src_ip):
            logger.debug("Source IP %s is protected by allowlist; skipping policy evaluation.", src_ip)
            return None

        now = time.time()
        mitigation: Optional[MitigationRecord] = None

        # 1. Evaluate Failed Logins & Rapid Reconnaissance Probes
        if event.eventid in ["cowrie.login.failed", "cowrie.client.version", "cowrie.session.connect"]:
            if src_ip not in self._failed_attempts:
                self._failed_attempts[src_ip] = deque()

            self._failed_attempts[src_ip].append(now)
            self._prune_expired_attempts(src_ip, now)

            attempts_count = len(self._failed_attempts.get(src_ip, []))
            is_login = event.eventid == "cowrie.login.failed"
            label = "authentication failure" if is_login else "reconnaissance probe"

            logger.info(
                "Honeypot %s from %s (attempt %d/%d in window).",
                label,
                src_ip,
                attempts_count,
                self.failed_login_threshold,
            )

            if attempts_count >= self.failed_login_threshold:
                if not self.firewall.is_ip_banned(src_ip):
                    if is_login:
                        reason = f"Brute-force attack: {attempts_count} failed logins in {self.time_window_seconds:.0f}s"
                    else:
                        reason = f"Reconnaissance sweep: {attempts_count} rapid probes in {self.time_window_seconds:.0f}s"
                    mitigation = self._execute_ban(src_ip, reason=reason, severity="HIGH")

        # 2. Evaluate Command Execution (Exploitation & Payload Ingestion)
        elif event.eventid == "cowrie.command.input" and event.input_command:
            cmd = event.input_command.lower()
            for pattern in CRITICAL_COMMAND_PATTERNS:
                if pattern in cmd:
                    logger.warning("Critical exploit command detected from %s: '%s'", src_ip, event.input_command)
                    if not self.firewall.is_ip_banned(src_ip):
                        reason = f"Critical terminal exploit execution: '{event.input_command[:40]}'"
                        mitigation = self._execute_ban(src_ip, reason=reason, severity="CRITICAL")
                    break

        return mitigation

    def is_honey_topic(self, topic: str) -> bool:
        """Determines if an MQTT topic belongs to a deceptive honey-topic namespace."""
        clean_topic = topic.strip().lower()
        if clean_topic in MQTT_HONEY_TOPIC_EXACT:
            return True
        for prefix in MQTT_HONEY_TOPIC_PREFIXES:
            if clean_topic.startswith(prefix):
                return True
        return False

    def evaluate_mqtt_message(
        self,
        topic: str,
        payload: str,
        src_ip: Optional[str] = None,
        device_id: Optional[str] = None,
    ) -> Optional[MitigationRecord]:
        """
        Inspects an incoming MQTT message for deceptive honey-topic breaches, command injections,
        oversized buffer anomalies, and publish rate flooding.
        """
        now = time.time()
        clean_topic = topic.strip()
        effective_ip = (src_ip or "").strip()
        tracking_key = effective_ip or device_id or clean_topic

        # Update target port analytics counter for 1883
        self._port_counts["1883"] = self._port_counts.get("1883", 0) + 1

        # Track publish rate in sliding window
        if tracking_key:
            if tracking_key not in self._mqtt_publish_times:
                self._mqtt_publish_times[tracking_key] = deque()
            queue = self._mqtt_publish_times[tracking_key]
            queue.append(now)
            cutoff = now - DEFAULT_MQTT_RATE_WINDOW
            while queue and queue[0] < cutoff:
                queue.popleft()

        reason: Optional[str] = None
        severity = "HIGH"
        attack_type = "mqtt_exploit"

        # 1. Check Deceptive Honey-Topic Access
        if self.is_honey_topic(clean_topic):
            reason = f"MQTT honey-topic breach on '{clean_topic}'"
            severity = "CRITICAL"
            attack_type = "mqtt_trap"

        # 2. Check Payload Command Injection Patterns
        if not reason and payload:
            lowered_payload = payload.lower()
            for pattern in CRITICAL_COMMAND_PATTERNS:
                if pattern in lowered_payload:
                    reason = f"MQTT payload exploit command detected: '{pattern.strip()}' in '{clean_topic}'"
                    severity = "CRITICAL"
                    attack_type = "mqtt_exploit"
                    break

        # 3. Check Buffer Overflow / Oversized Payload Anomaly
        if not reason and len(payload.encode("utf-8", errors="replace")) > MAX_MQTT_PAYLOAD_BYTES:
            reason = f"MQTT oversized payload anomaly ({len(payload)} bytes) on '{clean_topic}'"
            severity = "HIGH"
            attack_type = "mqtt_exploit"

        # 4. Check Publish Rate Flooding
        if not reason and tracking_key:
            rate_count = len(self._mqtt_publish_times.get(tracking_key, []))
            if rate_count > DEFAULT_MQTT_RATE_LIMIT:
                reason = f"MQTT publish rate anomaly: {rate_count} msgs in {DEFAULT_MQTT_RATE_WINDOW:.0f}s on '{clean_topic}'"
                severity = "HIGH"
                attack_type = "mqtt_flood"

        if not reason:
            return None

        # Record threat analytics
        self._attack_counts["exploit"] = self._attack_counts.get("exploit", 0) + 1
        event_record = {
            "timestamp": now,
            "src_ip": effective_ip or f"mqtt:{device_id or clean_topic}",
            "dst_port": 1883,
            "eventid": f"mqtt.{attack_type}",
            "attack_type": attack_type,
            "username": device_id or "",
            "password": "",
            "input_command": payload[:80] if payload else "",
            "message": reason,
        }
        self._events_history.append(event_record)
        if len(self._events_history) > 500:
            self._events_history = self._events_history[-500:]

        try:
            self.db.record_threat_event(event_record)
        except Exception as e:
            logger.error("Failed to record MQTT threat event: %s", e)

        # Invariant check: Allowlisted and management IPs are never banned
        if effective_ip and self.allowlist.is_ip_protected(effective_ip):
            logger.debug("MQTT source IP %s is protected by allowlist; skipping firewall ban.", effective_ip)
            return None

        if effective_ip:
            if not self.firewall.is_ip_banned(effective_ip):
                return self._execute_ban(effective_ip, reason=reason, severity=severity)

        record = MitigationRecord(
            src_ip=effective_ip or f"mqtt:{device_id or clean_topic}",
            action="MQTT_ISOLATE" if device_id else "IPTABLES_DROP",
            reason=reason,
            severity=severity,
            timestamp=now,
        )
        return record

    def _execute_ban(self, ip: str, reason: str, severity: str) -> MitigationRecord:
        """Executes firewall drop rule, records audit log in SQLite, and invokes listeners."""
        logger.warning("AUTONOMOUS MITIGATION TRIGGERED -> Target: %s | Reason: %s", ip, reason)

        # Enforce kernel firewall drop
        self.firewall.ban_ip(ip)

        # Persist audit record to SQLite database
        record = MitigationRecord(
            src_ip=ip,
            action="IPTABLES_DROP",
            reason=reason,
            severity=severity,
            timestamp=time.time(),
        )
        record_id = self.db.record_mitigation(record)
        record.id = record_id

        # Dispatch to callback (e.g., SSE event broadcast pool)
        if self.on_mitigation_callback:
            try:
                self.on_mitigation_callback(record)
            except Exception as e:
                logger.error("Error executing mitigation callback: %s", e)

        return record

    def manual_unban(self, ip: str, admin_user: str = "admin") -> bool:
        """Manually unbans an IP, removing firewall drop rule and recording audit trail."""
        sanitized_ip = ip.strip()
        success = self.firewall.unban_ip(sanitized_ip)
        if success:
            record = MitigationRecord(
                src_ip=sanitized_ip,
                action="UNBAN",
                reason=f"Manual unban executed by {admin_user}",
                severity="LOW",
                timestamp=time.time(),
            )
            self.db.record_mitigation(record)
            # Clear in-memory attempt window
            self._failed_attempts.pop(sanitized_ip, None)
            logger.info("Manual unban completed for %s.", sanitized_ip)
        return success

    def reset_all_bans(self, admin_user: str = "admin") -> bool:
        """Clears all firewall drop rules and updates database records."""
        success = self.firewall.flush_blocklist()
        if success:
            self.db.clear_all_bans()
            self._failed_attempts.clear()
            record = MitigationRecord(
                src_ip="0.0.0.0/0",
                action="RESET_ALL_BANS",
                reason=f"Global firewall reset executed by {admin_user}",
                severity="LOW",
                timestamp=time.time(),
            )
            self.db.record_mitigation(record)
            logger.info("Global firewall reset completed.")
        return success

    def reset_full_database(self) -> bool:
        """Completely purges database history, active bans, and in-memory analytics."""
        self.firewall.flush_blocklist()
        self.db.reset_database()
        self._failed_attempts.clear()
        self._mqtt_publish_times.clear()
        self._attack_counts = {"brute_force": 0, "exploit": 0, "probe": 0}
        self._username_counts.clear()
        self._password_counts.clear()
        self._port_counts = {"2222": 0, "2223": 0, "1883": 0}
        self._events_history.clear()
        logger.info("Complete system reset: Netfilter rules flushed, database wiped, in-memory analytics cleared.")
        return True

    def get_analytics(self) -> Dict[str, Any]:
        """Returns aggregated threat intelligence and log analytics statistics."""
        sorted_users = sorted(self._username_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        sorted_passwords = sorted(self._password_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        total_threats = sum(self._attack_counts.values())

        return {
            "total_threat_events": total_threats,
            "attack_breakdown": self._attack_counts,
            "top_usernames": sorted_users,
            "top_passwords": sorted_passwords,
            "target_ports": self._port_counts,
            "recent_events_count": len(self._events_history),
        }

    def get_ip_forensics(self, ip: str) -> Dict[str, Any]:
        """Returns deep forensic timeline and event history for a specific offending IP."""
        sanitized_ip = ip.strip()
        try:
            matched_events = self.db.get_threat_events_by_ip(sanitized_ip, limit=50)
            if not matched_events:
                matched_events = [ev for ev in self._events_history if ev.get("src_ip") == sanitized_ip]
        except Exception as e:
            logger.warning("Falling back to in-memory events for IP forensics (%s): %s", sanitized_ip, e)
            matched_events = [ev for ev in self._events_history if ev.get("src_ip") == sanitized_ip]

        is_banned = self.firewall.is_ip_banned(sanitized_ip)

        history = self.db.get_history(limit=50)
        ip_mitigations = [m for m in history if m.get("src_ip") == sanitized_ip]

        return {
            "src_ip": sanitized_ip,
            "is_banned": is_banned,
            "total_events": len(matched_events),
            "events": matched_events[-25:],
            "mitigations": ip_mitigations,
        }

