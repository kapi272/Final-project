import ipaddress
import logging
from typing import List, Union

logger = logging.getLogger(__name__)

# Default critical networks and host addresses that must never be blocked
DEFAULT_PROTECTED_NETWORKS: List[str] = [
    "127.0.0.0/8",       # Loopback
    "::1/128",           # IPv6 Loopback
    "172.20.0.1/32",     # IoT Production Network Gateway
    "172.21.0.1/32",     # IoT Quarantine Network Gateway
    "169.254.0.0/16",    # Link-local
]

DEFAULT_PROTECTED_IPS: List[str] = [
    "127.0.0.1",
    "::1",
    "172.20.0.1",
    "172.21.0.1",
]


class AllowlistManager:
    """Validates target IPs against critical infrastructure safety allowlists."""

    def __init__(
        self,
        protected_networks: Union[List[str], None] = None,
        protected_ips: Union[List[str], None] = None,
    ) -> None:
        raw_networks = protected_networks or DEFAULT_PROTECTED_NETWORKS
        raw_ips = protected_ips or DEFAULT_PROTECTED_IPS

        self._protected_networks: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []
        for net_str in raw_networks:
            try:
                self._protected_networks.append(ipaddress.ip_network(net_str, strict=False))
            except ValueError as e:
                logger.warning("Invalid network in allowlist configuration '%s': %s", net_str, e)

        self._protected_ips: List[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]] = []
        for ip_str in raw_ips:
            try:
                self._protected_ips.append(ipaddress.ip_address(ip_str))
            except ValueError as e:
                logger.warning("Invalid IP in allowlist configuration '%s': %s", ip_str, e)

    def is_ip_protected(self, ip_str: str) -> bool:
        """Returns True if the IP is valid and falls within a protected allowlist."""
        try:
            target_ip = ipaddress.ip_address(ip_str.strip())
        except ValueError:
            logger.error("Allowlist validation received syntactically invalid IP: '%s'", ip_str)
            return True  # Fail-safe: do not allow banning invalid strings

        # Check explicit IP list
        if target_ip in self._protected_ips:
            return True

        # Check network CIDR ranges
        for net in self._protected_networks:
            if target_ip in net:
                return True

        return False

    def validate_target_ip(self, ip_str: str) -> str:
        """
        Validates that ip_str is a valid IP and not protected.
        Returns the sanitized canonical IP string.
        Raises ValueError if invalid or protected.
        """
        if not ip_str or not isinstance(ip_str, str):
            raise ValueError("Target IP must be a non-empty string.")

        sanitized = ip_str.strip()
        try:
            parsed_ip = ipaddress.ip_address(sanitized)
        except ValueError as e:
            raise ValueError(f"Invalid IP address format '{sanitized}': {e}") from e

        if self.is_ip_protected(sanitized):
            raise ValueError(f"Target IP '{sanitized}' is protected by the management safety allowlist.")

        return str(parsed_ip)

