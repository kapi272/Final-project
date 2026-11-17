"""Outbound SIEM and Alert Webhook Notifier for Autonomous IoT Cyber Defense.

Dispatches real-time structured mitigation alerts to external SIEM collectors,
Splunk HTTP Event Collectors (HEC), Elastic, Discord, or Slack webhooks.
Enforces strict SSRF protection on destination targets and runs asynchronously
without blocking the core autonomous reaction pipeline.
"""

import asyncio
import json
import logging
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional

from controller.core.db import DefenseDatabase
from controller.core.device_discovery import validate_discovery_ip

logger = logging.getLogger(__name__)


def validate_webhook_url(url_str: str) -> str:
    """
    Validates the destination webhook URL and enforces SSRF protection.
    Rejects loopback, link-local / cloud metadata, and internal Docker networks.
    """
    url = url_str.strip()
    if not url:
        raise ValueError("Webhook URL cannot be empty.")

    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Webhook URL must use http or https scheme (got '{parsed.scheme}').")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Webhook URL is missing a valid destination hostname.")

    # Resolve hostname to IPv4/IPv6 and validate all resolved addresses
    try:
        addr_info = socket.getaddrinfo(hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
    except Exception as exc:
        raise ValueError(f"Failed to resolve webhook destination hostname '{hostname}': {exc}") from exc

    if not addr_info:
        raise ValueError(f"No IP addresses resolved for hostname '{hostname}'.")

    # Validate each resolved IP address against our SSRF firewall policy
    for entry in addr_info:
        sockaddr = entry[4]
        ip_str = sockaddr[0]
        validate_discovery_ip(ip_str)

    return url


class WebhookNotifier:
    """Manages outbound SIEM and chat alert webhook dispatching."""

    def __init__(self, db: DefenseDatabase) -> None:
        self.db = db

    def get_config(self) -> Dict[str, Any]:
        """Retrieves persistent webhook configuration from SQLite system_settings."""
        url = self.db.get_setting("webhook_url", "")
        enabled_str = self.db.get_setting("webhook_enabled", "false")
        webhook_format = self.db.get_setting("webhook_format", "generic")
        return {
            "url": url,
            "enabled": enabled_str.lower() in ("true", "1", "yes"),
            "format": webhook_format if webhook_format in ("generic", "slack", "discord") else "generic",
        }

    def update_config(self, url: str, enabled: bool, webhook_format: str = "generic") -> Dict[str, Any]:
        """Validates and persists updated webhook configuration."""
        clean_url = url.strip()
        if enabled and clean_url:
            validate_webhook_url(clean_url)

        valid_format = webhook_format if webhook_format in ("generic", "slack", "discord") else "generic"

        self.db.set_setting("webhook_url", clean_url)
        self.db.set_setting("webhook_enabled", "true" if enabled else "false")
        self.db.set_setting("webhook_format", valid_format)

        return {
            "url": clean_url,
            "enabled": enabled,
            "format": valid_format,
        }

    def format_payload(self, event_data: Dict[str, Any], webhook_format: str) -> Dict[str, Any]:
        """Formats alert payload according to target SIEM or notification service."""
        target_ip = event_data.get("src_ip") or event_data.get("target_ip") or "Unknown"
        reason = event_data.get("reason", "Autonomous Mitigation Triggered")
        action = event_data.get("action", "IPTABLES_DROP")
        severity = event_data.get("severity", "HIGH")
        ts = event_data.get("timestamp", time.time())

        if webhook_format == "slack":
            return {
                "text": f"🚨 *[AUTONOMOUS IOT CYBER DEFENSE]*\n"
                        f"• *Target IP:* `{target_ip}`\n"
                        f"• *Mitigation Action:* `{action}`\n"
                        f"• *Trigger Reason:* {reason}\n"
                        f"• *Severity:* *{severity}*\n"
                        f"• *System:* Autonomous IoT SOC Controller",
            }
        elif webhook_format == "discord":
            return {
                "content": f"🚨 **[AUTONOMOUS IOT CYBER DEFENSE]**\n"
                           f"**Target IP:** `{target_ip}`\n"
                           f"**Mitigation Action:** `{action}`\n"
                           f"**Trigger Reason:** {reason}\n"
                           f"**Severity:** **{severity}**\n"
                           f"**System:** Autonomous IoT SOC Controller",
            }
        else:
            # Generic SIEM / Splunk / Elastic JSON payload
            return {
                "event": "autonomous_mitigation_alert",
                "timestamp": ts,
                "target_ip": target_ip,
                "action": action,
                "reason": reason,
                "severity": severity,
                "system": "Autonomous IoT Cyber Defense Controller",
                "platform": "Linux Netfilter / Docker Engine API",
            }

    async def _post_json(self, url: str, payload: Dict[str, Any], timeout: float = 3.0) -> Dict[str, Any]:
        """Executes an asynchronous non-blocking HTTP POST request."""
        # Double-check SSRF target before dispatch
        validate_webhook_url(url)

        body_bytes = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body_bytes,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "Autonomous-IoT-Defense-SIEM-Webhook/2.3.0",
            },
            method="POST",
        )

        def _blocking_post() -> Dict[str, Any]:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                status_code = response.getcode()
                response_body = response.read(1024).decode("utf-8", errors="replace")
                return {"status_code": status_code, "body": response_body}

        return await asyncio.to_thread(_blocking_post)

    async def send_test_webhook(self) -> Dict[str, Any]:
        """Sends a verification probe payload to the configured webhook URL."""
        cfg = self.get_config()
        if not cfg["url"]:
            raise ValueError("No webhook URL configured.")

        test_event = {
            "src_ip": "198.51.100.99",
            "action": "TEST_ALERT",
            "reason": "Operator initiated SIEM webhook connectivity test probe",
            "severity": "INFO",
            "timestamp": time.time(),
        }
        payload = self.format_payload(test_event, cfg["format"])
        return await self._post_json(cfg["url"], payload, timeout=4.0)

    async def dispatch_mitigation_alert(self, record: Any) -> bool:
        """Dispatches an autonomous mitigation alert if webhook is enabled."""
        cfg = self.get_config()
        if not cfg["enabled"] or not cfg["url"]:
            return False

        event_data = {
            "src_ip": getattr(record, "src_ip", str(record)),
            "action": getattr(record, "action", "IPTABLES_DROP"),
            "reason": getattr(record, "reason", "Autonomous Mitigation Triggered"),
            "severity": getattr(record, "severity", "HIGH"),
            "timestamp": getattr(record, "timestamp", time.time()),
        }
        payload = self.format_payload(event_data, cfg["format"])

        try:
            await self._post_json(cfg["url"], payload, timeout=3.0)
            logger.info("Successfully dispatched SIEM webhook alert for %s", event_data["src_ip"])
            return True
        except Exception as exc:
            logger.warning("Failed to dispatch SIEM webhook alert to %s: %s", cfg["url"], exc)
            return False
