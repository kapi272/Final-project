import logging
import re
import shutil
import subprocess
from typing import List, Optional, Set

from controller.mitigation.allowlist import AllowlistManager

logger = logging.getLogger(__name__)

CHAIN_NAME: str = "IOT_DEFENSE_BLOCKLIST"
PARENT_CHAIN: str = "DOCKER-USER"


class FirewallController:
    """
    Injection-safe Netfilter/iptables controller managing the IOT_DEFENSE_BLOCKLIST
    sub-chain attached to Docker's DOCKER-USER routing table.
    """

    def __init__(
        self,
        allowlist_manager: Optional[AllowlistManager] = None,
        dry_run: bool = False,
    ) -> None:
        self.allowlist: AllowlistManager = allowlist_manager or AllowlistManager()
        self._has_iptables: bool = shutil.which("iptables") is not None
        self.dry_run: bool = dry_run or not self._has_iptables

        # In-memory tracking cache for active drop rules (especially helpful in dry-run/Darwin mode)
        self._active_bans: Set[str] = set()

        if self.dry_run:
            logger.info("FirewallController initialized in DRY-RUN mode (iptables unavailable or requested).")
        else:
            logger.info("FirewallController initialized with native Linux iptables binary.")

    def _run_cmd(self, args: List[str]) -> subprocess.CompletedProcess:
        """Executes a parameterized system command without shell interpolation."""
        if self.dry_run:
            logger.debug("[DRY RUN CMD] %s", " ".join(args))
            return subprocess.CompletedProcess(args=args, returncode=0, stdout="", stderr="")

        try:
            return subprocess.run(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
        except OSError as e:
            logger.error("OS execution error running command %s: %s", args, e)
            return subprocess.CompletedProcess(args=args, returncode=1, stdout="", stderr=str(e))

    def initialize_chains(self) -> bool:
        """
        Ensures IOT_DEFENSE_BLOCKLIST chain exists and is hooked into DOCKER-USER.
        Never touches system INPUT or FORWARD root chains.
        """
        if self.dry_run:
            logger.info("[DRY RUN] Initialized custom chain '%s' hooked to '%s'", CHAIN_NAME, PARENT_CHAIN)
            return True

        # 1. Create custom blocklist chain if it doesn't already exist
        check_chain = self._run_cmd(["iptables", "-N", CHAIN_NAME])
        if check_chain.returncode == 0:
            logger.info("Created custom Netfilter chain '%s'.", CHAIN_NAME)
        else:
            logger.debug("Netfilter chain '%s' already exists or creation returned: %s", CHAIN_NAME, check_chain.stderr.strip())

        # 2. Check if custom chain is jumped to from DOCKER-USER
        check_jump = self._run_cmd(["iptables", "-C", PARENT_CHAIN, "-j", CHAIN_NAME])
        if check_jump.returncode != 0:
            # Insert jump at position 1 in DOCKER-USER
            insert_jump = self._run_cmd(["iptables", "-I", PARENT_CHAIN, "1", "-j", CHAIN_NAME])
            if insert_jump.returncode == 0:
                logger.info("Hooked '%s' into '%s' at position 1.", CHAIN_NAME, PARENT_CHAIN)
            else:
                logger.error("Failed to hook '%s' into '%s': %s", CHAIN_NAME, PARENT_CHAIN, insert_jump.stderr.strip())
                return False
        else:
            logger.debug("Jump from '%s' to '%s' already exists.", PARENT_CHAIN, CHAIN_NAME)

        return True

    def is_ip_banned(self, ip: str) -> bool:
        """Checks if a specific IP currently has an active DROP rule in the custom chain."""
        sanitized_ip = ip.strip()
        if self.dry_run:
            return sanitized_ip in self._active_bans

        check = self._run_cmd(["iptables", "-C", CHAIN_NAME, "-s", sanitized_ip, "-j", "DROP"])
        return check.returncode == 0

    def ban_ip(self, ip: str) -> bool:
        """
        Idempotently inserts a DROP rule for the target IP in IOT_DEFENSE_BLOCKLIST.
        Rejects protected IPs and prevents duplicates.
        """
        try:
            target_ip = self.allowlist.validate_target_ip(ip)
        except ValueError as err:
            logger.warning("Ban operation rejected: %s", err)
            return False

        if self.is_ip_banned(target_ip):
            logger.info("Target IP %s is already blocked in %s (idempotent no-op).", target_ip, CHAIN_NAME)
            self._active_bans.add(target_ip)
            return True

        logger.info("Enforcing firewall DROP for offending IP: %s", target_ip)
        res = self._run_cmd(["iptables", "-I", CHAIN_NAME, "1", "-s", target_ip, "-j", "DROP"])

        if res.returncode == 0:
            self._active_bans.add(target_ip)
            logger.info("Successfully banned IP: %s", target_ip)
            return True
        else:
            logger.error("Failed to insert iptables DROP rule for %s: %s", target_ip, res.stderr.strip())
            return False

    def unban_ip(self, ip: str) -> bool:
        """
        Idempotently removes a DROP rule for the specified IP from IOT_DEFENSE_BLOCKLIST.
        """
        sanitized_ip = ip.strip()
        if not self.is_ip_banned(sanitized_ip):
            logger.info("Target IP %s is not currently banned (idempotent no-op).", sanitized_ip)
            self._active_bans.discard(sanitized_ip)
            return True

        logger.info("Removing firewall DROP for IP: %s", sanitized_ip)
        res = self._run_cmd(["iptables", "-D", CHAIN_NAME, "-s", sanitized_ip, "-j", "DROP"])

        if res.returncode == 0:
            self._active_bans.discard(sanitized_ip)
            logger.info("Successfully unbanned IP: %s", sanitized_ip)
            return True
        else:
            logger.error("Failed to remove iptables DROP rule for %s: %s", sanitized_ip, res.stderr.strip())
            return False

    def list_banned_ips(self) -> List[str]:
        """Queries and returns the current list of blocked IPs from IOT_DEFENSE_BLOCKLIST."""
        if self.dry_run:
            return sorted(list(self._active_bans))

        res = self._run_cmd(["iptables", "-S", CHAIN_NAME])
        if res.returncode != 0:
            logger.error("Failed to query %s rules: %s", CHAIN_NAME, res.stderr.strip())
            return list(self._active_bans)

        found_ips: Set[str] = set()
        # Parse output format: -A IOT_DEFENSE_BLOCKLIST -s 192.0.2.1/32 -j DROP
        for line in res.stdout.splitlines():
            match = re.search(r"-s\s+([0-9a-fA-F\.:]+)(?:/\d+)?\s+-j\s+DROP", line)
            if match:
                found_ips.add(match.group(1))

        self._active_bans = found_ips
        return sorted(list(found_ips))

    def flush_blocklist(self) -> bool:
        """Flushes all rules inside IOT_DEFENSE_BLOCKLIST only."""
        logger.warning("Flushing all rules in Netfilter chain '%s'...", CHAIN_NAME)
        res = self._run_cmd(["iptables", "-F", CHAIN_NAME])
        if res.returncode == 0:
            self._active_bans.clear()
            logger.info("Netfilter chain '%s' cleared successfully.", CHAIN_NAME)
            return True
        else:
            logger.error("Failed to flush chain '%s': %s", CHAIN_NAME, res.stderr.strip())
            return False

