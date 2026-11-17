"""STIX 2.1 Cyber Threat Intelligence Exporter for Autonomous IoT Cyber Defense.

Generates standard OASIS STIX 2.1 JSON bundles representing honeypot intrusions,
adversary techniques mapped to MITRE ATT&CK, observed indicator IPs, and autonomous
mitigation courses of action (Netfilter kernel drops and Docker container quarantines).
Zero third-party library dependencies (pure Python standard library).
"""

from datetime import datetime, timezone
import ipaddress
import logging
from typing import Any, Dict, List, Optional, Set
import uuid

logger = logging.getLogger(__name__)

# Deterministic namespace for reproducible STIX IDs
DNS_NAMESPACE = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
DEFENSE_NAMESPACE = uuid.uuid5(DNS_NAMESPACE, "autonomous-iot-defense.local")

# MITRE ATT&CK Technique Mappings
MITRE_ATTACK_PATTERNS = {
    "brute_force": {
        "id": f"attack-pattern--{uuid.uuid5(DEFENSE_NAMESPACE, 'T1110')}",
        "name": "Brute Force",
        "description": "Adversaries attempt credential guessing against SSH/Telnet IoT honeypot interfaces.",
        "external_id": "T1110",
        "url": "https://attack.mitre.org/techniques/T1110/",
    },
    "exploit": {
        "id": f"attack-pattern--{uuid.uuid5(DEFENSE_NAMESPACE, 'T1059')}",
        "name": "Command and Scripting Interpreter",
        "description": "Adversaries execute malicious shell commands or automated botnet dropper scripts.",
        "external_id": "T1059",
        "url": "https://attack.mitre.org/techniques/T1059/",
    },
    "port_sweep": {
        "id": f"attack-pattern--{uuid.uuid5(DEFENSE_NAMESPACE, 'T1046')}",
        "name": "Network Service Discovery",
        "description": "Adversaries scan host subnets and probe open IoT mesh and honeypot decoy ports.",
        "external_id": "T1046",
        "url": "https://attack.mitre.org/techniques/T1046/",
    },
    "mqtt_anomaly": {
        "id": f"attack-pattern--{uuid.uuid5(DEFENSE_NAMESPACE, 'T1078')}",
        "name": "Valid Accounts / Protocol Deception",
        "description": "Adversaries publish to unauthorized administrative honey-topics (home/admin/#) or inject command strings.",
        "external_id": "T1078",
        "url": "https://attack.mitre.org/techniques/T1078/",
    },
}


def _iso_format(ts: Optional[float] = None) -> str:
    """Formats a POSIX timestamp into ISO 8601 UTC with milliseconds and Z suffix."""
    dt = datetime.fromtimestamp(ts, tz=timezone.utc) if ts else datetime.now(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _classify_attack_pattern(reason: str) -> str:
    """Categorizes mitigation reason into a MITRE ATT&CK key."""
    lowered = reason.lower()
    if "brute" in lowered or "failed login" in lowered:
        return "brute_force"
    if "exploit" in lowered or "command" in lowered or "terminal" in lowered or "botnet" in lowered:
        return "exploit"
    if "sweep" in lowered or "recon" in lowered or "probe" in lowered or "port" in lowered:
        return "port_sweep"
    if "mqtt" in lowered or "honey-topic" in lowered or "payload" in lowered:
        return "mqtt_anomaly"
    return "brute_force"


def generate_stix_bundle(
    history: List[Dict[str, Any]],
    threat_events: Optional[List[Dict[str, Any]]] = None,
    active_bans: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Compiles autonomous defense history, threat events, and active bans into
    a standard OASIS STIX 2.1 JSON bundle.
    """
    bundle_id = f"bundle--{uuid.uuid4()}"
    now_iso = _iso_format()

    # 1. Identity SDO: The Autonomous IoT Defense System
    identity_id = f"identity--{uuid.uuid5(DEFENSE_NAMESPACE, 'controller-identity')}"
    identity_obj: Dict[str, Any] = {
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": now_iso,
        "modified": now_iso,
        "name": "Autonomous IoT Cyber Defense Controller",
        "description": "Host-level autonomous IoT intrusion detection, deception, and mitigation SOC system.",
        "identity_class": "system",
        "sectors": ["defense", "technology"],
        "confidence": 95,
    }

    stix_objects: List[Dict[str, Any]] = [identity_obj]

    # 2. Attack Pattern SDOs (MITRE ATT&CK)
    ap_objects_map: Dict[str, Dict[str, Any]] = {}
    for ap_key, meta in MITRE_ATTACK_PATTERNS.items():
        ap_obj = {
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": meta["id"],
            "created": "2020-01-01T00:00:00.000Z",
            "modified": "2020-01-01T00:00:00.000Z",
            "name": meta["name"],
            "description": meta["description"],
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": meta["external_id"],
                    "url": meta["url"],
                }
            ],
        }
        stix_objects.append(ap_obj)
        ap_objects_map[ap_key] = ap_obj

    # 3. Course of Action SDOs
    coa_firewall_id = f"course-of-action--{uuid.uuid5(DEFENSE_NAMESPACE, 'coa-iptables-drop')}"
    coa_firewall: Dict[str, Any] = {
        "type": "course-of-action",
        "spec_version": "2.1",
        "id": coa_firewall_id,
        "created": now_iso,
        "modified": now_iso,
        "name": "Netfilter Autonomous DROP Ban",
        "description": "Autonomous injection of kernel iptables DROP rule into the IOT_DEFENSE_BLOCKLIST chain.",
        "action_type": "blocking",
    }

    coa_quarantine_id = f"course-of-action--{uuid.uuid5(DEFENSE_NAMESPACE, 'coa-docker-quarantine')}"
    coa_quarantine: Dict[str, Any] = {
        "type": "course-of-action",
        "spec_version": "2.1",
        "id": coa_quarantine_id,
        "created": now_iso,
        "modified": now_iso,
        "name": "Docker Network Lateral Containment",
        "description": "Dynamic isolation of compromised IoT container/device to internal quarantine bridge.",
        "action_type": "isolation",
    }
    stix_objects.extend([coa_firewall, coa_quarantine])

    # 4. Relationships between Course of Action and Attack Patterns
    for ap_key, ap_obj in ap_objects_map.items():
        ap_id = ap_obj["id"]
        rel_seed = f"mitigates-{coa_firewall_id}-{ap_id}"
        rel_coa_ap = {
            "type": "relationship",
            "spec_version": "2.1",
            "id": f"relationship--{uuid.uuid5(DEFENSE_NAMESPACE, rel_seed)}",
            "created": now_iso,
            "modified": now_iso,
            "relationship_type": "mitigates",
            "source_ref": coa_firewall_id,
            "target_ref": ap_id,
        }
        stix_objects.append(rel_coa_ap)

    # 5. Extract Unique Attacker IPs and create Indicator SDOs + Relationships
    processed_ips: Set[str] = set()

    # Aggregate records from history and active bans
    all_records: List[Dict[str, Any]] = []
    if history:
        all_records.extend(history)
    if active_bans:
        all_records.extend(active_bans)

    for item in all_records:
        ip = item.get("src_ip", "").strip()
        if not ip or ip in processed_ips:
            continue

        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue

        processed_ips.add(ip)
        reason = item.get("reason", "Malicious activity detected")
        action = item.get("action", "IPTABLES_DROP")
        ts = item.get("timestamp") or item.get("banned_at")
        event_time_iso = _iso_format(ts)
        ap_key = _classify_attack_pattern(reason)
        target_ap = ap_objects_map[ap_key]

        indicator_id = f"indicator--{uuid.uuid5(DEFENSE_NAMESPACE, f'indicator-ip-{ip}')}"
        indicator_obj: Dict[str, Any] = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": event_time_iso,
            "modified": now_iso,
            "name": f"Malicious IoT Adversary: {ip}",
            "description": f"Triggered autonomous mitigation. Reason: {reason} (Action: {action})",
            "pattern": f"[ipv4-addr:value = '{ip}']",
            "pattern_type": "stix",
            "valid_from": event_time_iso,
            "indicator_types": ["malicious-activity", "anonymization"],
            "created_by_ref": identity_id,
            "confidence": 90,
        }
        stix_objects.append(indicator_obj)

        # Relationship: Indicator indicates Attack Pattern
        target_ap_id = target_ap["id"]
        rel_indicates_seed = f"indicates-{indicator_id}-{target_ap_id}"
        rel_indicates = {
            "type": "relationship",
            "spec_version": "2.1",
            "id": f"relationship--{uuid.uuid5(DEFENSE_NAMESPACE, rel_indicates_seed)}",
            "created": event_time_iso,
            "modified": now_iso,
            "relationship_type": "indicates",
            "source_ref": indicator_id,
            "target_ref": target_ap_id,
        }
        stix_objects.append(rel_indicates)

    return {
        "type": "bundle",
        "id": bundle_id,
        "spec_version": "2.1",
        "objects": stix_objects,
    }
