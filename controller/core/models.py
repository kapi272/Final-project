from dataclasses import asdict, dataclass, field
import time
from typing import Any, Dict, Optional


@dataclass
class CowrieEvent:
    """Represents a structured intrusion event parsed from Cowrie JSON logs."""
    eventid: str
    src_ip: str
    timestamp: float = field(default_factory=time.time)
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    session: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    input_command: Optional[str] = None
    message: Optional[str] = None
    raw_data: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_cowrie_json(cls, data: Dict[str, Any]) -> "CowrieEvent":
        """Instantiates a CowrieEvent from raw parsed JSON line."""
        eventid = data.get("eventid", "cowrie.unknown")
        src_ip = data.get("src_ip", "0.0.0.0")
        src_port = data.get("src_port")
        dst_port = data.get("dst_port")
        session = data.get("session")
        username = data.get("username")
        password = data.get("password")
        input_cmd = data.get("input")
        message = data.get("message")

        return cls(
            eventid=eventid,
            src_ip=src_ip,
            timestamp=time.time(),
            src_port=int(src_port) if src_port is not None else None,
            dst_port=int(dst_port) if dst_port is not None else None,
            session=str(session) if session else None,
            username=str(username) if username else None,
            password=str(password) if password else None,
            input_command=str(input_cmd) if input_cmd else None,
            message=str(message) if message else None,
            raw_data=data,
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class MitigationRecord:
    """Persistent audit model tracking an autonomous defense mitigation action."""
    src_ip: str
    action: str  # e.g., 'IPTABLES_DROP', 'UNBAN', 'QUARANTINE'
    reason: str
    severity: str = "HIGH"  # LOW, MEDIUM, HIGH, CRITICAL
    timestamp: float = field(default_factory=time.time)
    id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

