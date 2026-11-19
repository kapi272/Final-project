from contextlib import contextmanager
import logging
import os
import sqlite3
import time
from typing import Any, Dict, Generator, List, Optional

from controller.core.models import MitigationRecord

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH: str = os.environ.get("DEFENSE_DB_PATH", os.path.join("data", "defense_history.db"))


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
        # Concurrency & WAL mode pragmas
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA busy_timeout=5000;")
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
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS threat_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    src_ip TEXT NOT NULL,
                    dst_port INTEGER NOT NULL DEFAULT 2222,
                    eventid TEXT NOT NULL,
                    attack_type TEXT NOT NULL DEFAULT 'probe',
                    username TEXT NOT NULL DEFAULT '',
                    password TEXT NOT NULL DEFAULT '',
                    input_command TEXT NOT NULL DEFAULT '',
                    message TEXT NOT NULL DEFAULT ''
                )
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_threat_events_timestamp
                ON threat_events (timestamp DESC)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_threat_events_src_ip
                ON threat_events (src_ip)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_threat_events_type
                ON threat_events (attack_type)
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'operator',
                    full_name TEXT NOT NULL DEFAULT '',
                    email TEXT NOT NULL DEFAULT '',
                    is_active INTEGER NOT NULL DEFAULT 1,
                    last_login REAL,
                    created_at REAL NOT NULL
                )
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_users_username
                ON users (username)
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS user_sessions (
                    session_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    last_activity REAL NOT NULL,
                    ip_address TEXT NOT NULL DEFAULT '',
                    user_agent TEXT NOT NULL DEFAULT ''
                )
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_sessions_user_id
                ON user_sessions (user_id)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_sessions_expires_at
                ON user_sessions (expires_at)
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
        """Completely purges all historical mitigation records, active bans, threat events, and autoincrement sequences."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM threat_events")
            cursor.execute("DELETE FROM mitigation_history")
            cursor.execute("DELETE FROM active_bans")
            cursor.execute("UPDATE registered_devices SET blocked = 0, status = 'MONITORING' WHERE blocked = 1")
            try:
                cursor.execute("DELETE FROM sqlite_sequence WHERE name IN ('mitigation_history', 'threat_events')")
            except Exception:
                pass
            conn.commit()
            logger.info("Database reset: All mitigation history, active bans, and threat events cleared.")
            return True

    def record_threat_event(self, event_data: Dict[str, Any]) -> int:
        """Records a parsed honeypot threat event into persistent storage."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO threat_events (
                    timestamp, src_ip, dst_port, eventid, attack_type,
                    username, password, input_command, message
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                float(event_data.get("timestamp", time.time())),
                str(event_data.get("src_ip", "")).strip(),
                int(event_data.get("dst_port") or 2222),
                str(event_data.get("eventid", "")),
                str(event_data.get("attack_type", "probe")),
                str(event_data.get("username", "") or ""),
                str(event_data.get("password", "") or ""),
                str(event_data.get("input_command", "") or ""),
                str(event_data.get("message", "") or ""),
            ))
            conn.commit()
            return cursor.lastrowid or 0

    def get_persisted_threat_analytics(self) -> Dict[str, Any]:
        """Computes aggregated threat intelligence statistics directly from SQLite."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) as total FROM threat_events")
            total = int(cursor.fetchone()["total"])

            attack_breakdown: Dict[str, int] = {"brute_force": 0, "exploit": 0, "probe": 0}
            cursor.execute("""
                SELECT attack_type, COUNT(*) as cnt
                FROM threat_events
                GROUP BY attack_type
            """)
            for row in cursor.fetchall():
                atype = str(row["attack_type"])
                attack_breakdown[atype] = int(row["cnt"])

            cursor.execute("""
                SELECT username, COUNT(*) as cnt
                FROM threat_events
                WHERE username IS NOT NULL AND username != ''
                GROUP BY username
                ORDER BY cnt DESC
                LIMIT 5
            """)
            top_usernames = [(str(row["username"]), int(row["cnt"])) for row in cursor.fetchall()]

            cursor.execute("""
                SELECT password, COUNT(*) as cnt
                FROM threat_events
                WHERE password IS NOT NULL AND password != ''
                GROUP BY password
                ORDER BY cnt DESC
                LIMIT 5
            """)
            top_passwords = [(str(row["password"]), int(row["cnt"])) for row in cursor.fetchall()]

            target_ports: Dict[str, int] = {"2222": 0, "2223": 0, "1883": 0}
            cursor.execute("""
                SELECT dst_port, COUNT(*) as cnt
                FROM threat_events
                GROUP BY dst_port
            """)
            for row in cursor.fetchall():
                target_ports[str(row["dst_port"])] = int(row["cnt"])

            return {
                "total_threat_events": total,
                "attack_breakdown": attack_breakdown,
                "top_usernames": top_usernames,
                "top_passwords": top_passwords,
                "target_ports": target_ports,
            }

    def get_threat_events_by_ip(self, ip: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieves historical threat events matching a specific source IP."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT timestamp, src_ip, dst_port, eventid, attack_type,
                       username, password, input_command, message
                FROM threat_events
                WHERE src_ip = ?
                ORDER BY timestamp ASC
                LIMIT ?
            """, (ip.strip(), limit))
            return [dict(row) for row in cursor.fetchall()]

    def get_recent_threat_events(self, limit: int = 500) -> List[Dict[str, Any]]:
        """Retrieves recent threat events ordered chronologically for hydration and telemetry."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT timestamp, src_ip, dst_port, eventid, attack_type,
                       username, password, input_command, message
                FROM (
                    SELECT timestamp, src_ip, dst_port, eventid, attack_type,
                           username, password, input_command, message
                    FROM threat_events
                    ORDER BY timestamp DESC
                    LIMIT ?
                )
                ORDER BY timestamp ASC
            """, (limit,))
            return [dict(row) for row in cursor.fetchall()]

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

    def update_device_name(self, device_id: str, name: str) -> bool:
        """Updates the friendly display name for a registered device."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE registered_devices SET name = ? WHERE device_id = ?",
                (name, device_id),
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

    # --- SOC User & Session Authentication Persistence ---

    def create_user(
        self,
        user_id: str,
        username: str,
        password_hash: str,
        salt: str,
        role: str = "operator",
        full_name: str = "",
        email: str = "",
        is_active: bool = True,
    ) -> bool:
        """Persists a new user record in SQLite."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO users (
                    user_id, username, password_hash, salt, role,
                    full_name, email, is_active, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    username.strip().lower(),
                    password_hash,
                    salt,
                    role.strip().lower(),
                    full_name.strip(),
                    email.strip().lower(),
                    1 if is_active else 0,
                    time.time(),
                ),
            )
            conn.commit()
            return cursor.rowcount > 0

    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """Retrieves a user by username."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT user_id, username, password_hash, salt, role,
                       full_name, email, is_active, last_login, created_at
                FROM users
                WHERE username = ?
                """,
                (username.strip().lower(),),
            )
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a user by unique ID."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT user_id, username, password_hash, salt, role,
                       full_name, email, is_active, last_login, created_at
                FROM users
                WHERE user_id = ?
                """,
                (user_id,),
            )
            row = cursor.fetchone()
            return dict(row) if row else None

    def list_users(self) -> List[Dict[str, Any]]:
        """Lists all registered users (excluding sensitive password hashes and salts)."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT user_id, username, role, full_name, email,
                       is_active, last_login, created_at
                FROM users
                ORDER BY created_at ASC
                """
            )
            return [dict(row) for row in cursor.fetchall()]

    def update_user_last_login(self, user_id: str, timestamp: float) -> bool:
        """Updates the last_login timestamp for a user."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET last_login = ? WHERE user_id = ?",
                (timestamp, user_id),
            )
            conn.commit()
            return cursor.rowcount > 0

    def create_session(
        self,
        session_id: str,
        user_id: str,
        role: str,
        expires_at: float,
        ip_address: str = "",
        user_agent: str = "",
    ) -> bool:
        """Stores a cryptographically secure user session."""
        now = time.time()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO user_sessions (
                    session_id, user_id, role, created_at,
                    expires_at, last_activity, ip_address, user_agent
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    user_id,
                    role,
                    now,
                    expires_at,
                    now,
                    ip_address,
                    user_agent[:255] if user_agent else "",
                ),
            )
            conn.commit()
            return cursor.rowcount > 0

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves session details if active and unexpired."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT s.session_id, s.user_id, s.role, s.created_at,
                       s.expires_at, s.last_activity, s.ip_address, s.user_agent,
                       u.username, u.full_name, u.email, u.is_active
                FROM user_sessions s
                JOIN users u ON s.user_id = u.user_id
                WHERE s.session_id = ?
                """,
                (session_id,),
            )
            row = cursor.fetchone()
            return dict(row) if row else None

    def touch_session(self, session_id: str, timestamp: float) -> bool:
        """Updates the last_activity timestamp for an active session."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE user_sessions SET last_activity = ? WHERE session_id = ?",
                (timestamp, session_id),
            )
            conn.commit()
            return cursor.rowcount > 0

    def delete_session(self, session_id: str) -> bool:
        """Revokes a session by session ID."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM user_sessions WHERE session_id = ?", (session_id,))
            conn.commit()
            return cursor.rowcount > 0

    def delete_user_sessions(self, user_id: str) -> int:
        """Revokes all active sessions for a user (e.g. on password change or deactivation)."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM user_sessions WHERE user_id = ?", (user_id,))
            conn.commit()
            return cursor.rowcount

    def list_active_sessions(self, current_time: float) -> List[Dict[str, Any]]:
        """Lists currently active unexpired sessions joined with user info."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT s.session_id, s.user_id, s.role, s.created_at,
                       s.expires_at, s.last_activity, s.ip_address, s.user_agent,
                       u.username, u.full_name
                FROM user_sessions s
                JOIN users u ON s.user_id = u.user_id
                WHERE s.expires_at > ?
                ORDER BY s.last_activity DESC
                """,
                (current_time,),
            )
            return [dict(row) for row in cursor.fetchall()]

    def clean_expired_sessions(self, current_time: float) -> int:
        """Removes expired sessions from the database."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM user_sessions WHERE expires_at <= ?", (current_time,))
            conn.commit()
            return cursor.rowcount

