from contextlib import contextmanager
import logging
import os
import sqlite3
import time
from typing import Any, Dict, Generator, List, Optional

from controller.core.models import MitigationRecord

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH: str = os.path.join("data", "defense_history.db")


class DefenseDatabase:
    """SQLite embedded database manager for persistent defense audit trails."""

    def __init__(self, db_path: str = DEFAULT_DB_PATH) -> None:
        self.db_path = db_path
        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        self.init_db()

    @contextmanager
    def _get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def init_db(self) -> None:
        """Provisions tables and indexes if they do not exist."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS mitigation_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    src_ip TEXT NOT NULL,
                    action TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    severity TEXT NOT NULL
                )
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_history_timestamp
                ON mitigation_history (timestamp DESC)
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS active_bans (
                    src_ip TEXT PRIMARY KEY,
                    banned_at REAL NOT NULL,
                    reason TEXT NOT NULL,
                    severity TEXT NOT NULL
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS system_settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS registered_devices (
                    device_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    device_type TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    ip_address TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    mqtt_topic TEXT NOT NULL,
                    snapshot_url TEXT NOT NULL,
                    token_hash TEXT NOT NULL,
                    blocked INTEGER NOT NULL DEFAULT 0,
                    status TEXT NOT NULL DEFAULT 'MONITORING',
                    last_seen REAL,
                    last_payload TEXT NOT NULL DEFAULT '',
                    created_at REAL NOT NULL
                )
            """)
            conn.commit()
            logger.info("DefenseDatabase initialized at %s", self.db_path)

    def record_mitigation(self, record: MitigationRecord) -> int:
        """Records an autonomous mitigation action in history and updates active_bans."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO mitigation_history (timestamp, src_ip, action, reason, severity)
                VALUES (?, ?, ?, ?, ?)
            """, (record.timestamp, record.src_ip, record.action, record.reason, record.severity))
            record_id = cursor.lastrowid or 0

            if record.action == "IPTABLES_DROP":
                cursor.execute("""
                    INSERT OR REPLACE INTO active_bans (src_ip, banned_at, reason, severity)
                    VALUES (?, ?, ?, ?)
                """, (record.src_ip, record.timestamp, record.reason, record.severity))
            elif record.action == "UNBAN":
                cursor.execute("DELETE FROM active_bans WHERE src_ip = ?", (record.src_ip,))

            conn.commit()
            return record_id

    def get_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieves recent mitigation history rows ordered by timestamp descending."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, timestamp, src_ip, action, reason, severity
                FROM mitigation_history
                ORDER BY timestamp DESC
                LIMIT ?
            """, (limit,))
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    def get_active_bans(self) -> List[Dict[str, Any]]:
        """Retrieves currently active banned IPs."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT src_ip, banned_at, reason, severity
                FROM active_bans
                ORDER BY banned_at DESC
            """)
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    def remove_active_ban(self, src_ip: str) -> bool:
        """Removes a specific IP from active_bans."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM active_bans WHERE src_ip = ?", (src_ip.strip(),))
            conn.commit()
            return cursor.rowcount > 0

    def clear_all_bans(self) -> bool:
        """Clears all entries from active_bans."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM active_bans")
            conn.commit()
            return True

    def reset_database(self) -> bool:
        """Completely purges all historical mitigation records, active bans, and autoincrement sequences."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM mitigation_history")
            cursor.execute("DELETE FROM active_bans")
            cursor.execute("UPDATE registered_devices SET blocked = 0, status = 'MONITORING' WHERE blocked = 1")
            try:
                cursor.execute("DELETE FROM sqlite_sequence WHERE name IN ('mitigation_history')")
            except Exception:
                pass
            conn.commit()
            logger.info("Database reset: All mitigation history and active bans cleared.")
            return True

    def get_setting(self, key: str, default: str = "") -> str:
        """Retrieves a persisted configuration value by key."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT value FROM system_settings WHERE key = ?", (key,))
            row = cursor.fetchone()
            return str(row["value"]) if row else default

    def set_setting(self, key: str, value: str) -> None:
        """Persists a configuration setting using parameterized SQL."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO system_settings (key, value) VALUES (?, ?)",
                (key, value),
            )
            conn.commit()

    def upsert_device(self, device: Dict[str, Any]) -> None:
        """Inserts or updates a real-world registered IoT device."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO registered_devices (
                    device_id, name, device_type, protocol, ip_address, port,
                    mqtt_topic, snapshot_url, token_hash, blocked, status,
                    last_seen, last_payload, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(device_id) DO UPDATE SET
                    name = excluded.name,
                    device_type = excluded.device_type,
                    protocol = excluded.protocol,
                    ip_address = excluded.ip_address,
                    port = excluded.port,
                    mqtt_topic = excluded.mqtt_topic,
                    snapshot_url = excluded.snapshot_url,
                    status = excluded.status
                """,
                (
                    device["device_id"],
                    device["name"],
                    device["device_type"],
                    device["protocol"],
                    device["ip_address"],
                    int(device["port"]),
                    device["mqtt_topic"],
                    device["snapshot_url"],
                    device["token_hash"],
                    int(bool(device.get("blocked", False))),
                    device.get("status", "MONITORING"),
                    device.get("last_seen"),
                    device.get("last_payload", ""),
                    float(device.get("created_at", time.time())),
                ),
            )
            conn.commit()

    def list_devices(self) -> List[Dict[str, Any]]:
        """Lists registered real-world IoT devices ordered by creation time descending."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT device_id, name, device_type, protocol, ip_address, port,
                       mqtt_topic, snapshot_url, blocked, status, last_seen,
                       last_payload, created_at
                FROM registered_devices
                ORDER BY created_at DESC
                """
            )
            return [dict(row) for row in cursor.fetchall()]

    def get_device(self, device_id: str, include_secret: bool = False) -> Optional[Dict[str, Any]]:
        """Retrieves a registered IoT device record."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT device_id, name, device_type, protocol, ip_address, port,
                       mqtt_topic, snapshot_url, token_hash, blocked, status, last_seen,
                       last_payload, created_at
                FROM registered_devices
                WHERE device_id = ?
                """,
                (device_id,),
            )
            row = cursor.fetchone()
            if not row:
                return None
            rec = dict(row)
            if not include_secret:
                rec.pop("token_hash", None)
            return rec

    def update_device_telemetry(
        self,
        device_id: str,
        status: Optional[str] = None,
        last_seen: Optional[float] = None,
        last_payload: Optional[str] = None,
    ) -> bool:
        """Updates runtime health status and latest telemetry metadata for a device."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE registered_devices
                SET status = COALESCE(?, status),
                    last_seen = COALESCE(?, last_seen),
                    last_payload = COALESCE(?, last_payload)
                WHERE device_id = ?
                """,
                (status, last_seen, last_payload, device_id),
            )
            conn.commit()
            return cursor.rowcount > 0

    def set_device_blocked(self, device_id: str, blocked: bool, status: str) -> bool:
        """Updates the logical quarantine flag and operational status for a device."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE registered_devices SET blocked = ?, status = ? WHERE device_id = ?",
                (1 if blocked else 0, status, device_id),
            )
            conn.commit()
            return cursor.rowcount > 0

    def delete_device(self, device_id: str) -> bool:
        """Deletes a registered IoT device record."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM registered_devices WHERE device_id = ?", (device_id,))
            conn.commit()
            return cursor.rowcount > 0

