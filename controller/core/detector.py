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

        # Invariant check: Allowlisted and management IPs are never banned
        if self.allowlist.is_ip_protected(src_ip):
            logger.debug("Source IP %s is protected by allowlist; skipping policy evaluation.", src_ip)
            return None

        now = time.time()
        mitigation: Optional[MitigationRecord] = None

        # 1. Evaluate Failed Logins (Brute-Force Detection)
        if event.eventid == "cowrie.login.failed":
            if src_ip not in self._failed_attempts:
                self._failed_attempts[src_ip] = deque()

            self._failed_attempts[src_ip].append(now)
            self._prune_expired_attempts(src_ip, now)

            attempts_count = len(self._failed_attempts.get(src_ip, []))
            logger.info(
                "Failed authentication from %s (user: '%s', attempt %d/%d in window).",
                src_ip,
                event.username or "unknown",
                attempts_count,
                self.failed_login_threshold,
            )

            if attempts_count >= self.failed_login_threshold:
                if not self.firewall.is_ip_banned(src_ip):
                    reason = f"Brute-force attack: {attempts_count} failed logins in {self.time_window_seconds:.0f}s"
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
