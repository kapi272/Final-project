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

