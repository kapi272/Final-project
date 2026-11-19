"""SOC User Authentication, Session Management, and Role-Based Access Control."""

from collections import defaultdict, deque
import hashlib
import hmac
import logging
import re
import secrets
import time
from typing import Any, Dict, List, Optional, Tuple

from controller.core.db import DefenseDatabase

logger = logging.getLogger(__name__)

SESSION_TTL_SECONDS = 8 * 3600  # 8 hours
MAX_FAILED_LOGIN_ATTEMPTS = 5
FAILED_ATTEMPT_WINDOW_SECONDS = 60.0
LOCKOUT_DURATION_SECONDS = 60.0

VALID_ROLES = {"admin", "operator", "analyst"}
USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.-]{3,32}$")


class RateLimitExceeded(Exception):
    """Raised when an IP or user exceeds failed login attempts."""

    def __init__(self, message: str, retry_after: int = 60) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class InvalidCredentials(Exception):
    """Raised on invalid username or password."""
    pass


class AccountDeactivated(Exception):
    """Raised when an inactive account attempts to authenticate."""
    pass


def validate_password_strength(password: str) -> None:
    """Enforces enterprise password strength requirements."""
    if not password or len(password) < 8:
        raise ValueError("Password must be at least 8 characters long.")
    if len(password) > 128:
        raise ValueError("Password cannot exceed 128 characters.")
    if not re.search(r"[A-Z]", password):
        raise ValueError("Password must contain at least one uppercase letter (A-Z).")
    if not re.search(r"[a-z]", password):
        raise ValueError("Password must contain at least one lowercase letter (a-z).")
    if not re.search(r"[0-9]", password):
        raise ValueError("Password must contain at least one digit (0-9).")
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};\':",.<>/?\\|`~]', password):
        raise ValueError("Password must contain at least one special symbol.")


def hash_password(password: str, salt_hex: Optional[str] = None) -> Tuple[str, str]:
    """Generates a memory-hard scrypt hash using a cryptographically secure 32-byte salt."""
    salt_bytes = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(32)
    # scrypt with N=16384, r=8, p=1
    derived = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt_bytes,
        n=16384,
        r=8,
        p=1,
        maxmem=32 * 1024 * 1024,
    )
    return derived.hex(), salt_bytes.hex()


def verify_password(password: str, hash_hex: str, salt_hex: str) -> bool:
    """Verifies a plaintext password against a stored scrypt hash using constant-time comparison."""
    try:
        derived_hex, _ = hash_password(password, salt_hex=salt_hex)
        return hmac.compare_digest(derived_hex, hash_hex)
    except Exception:
        return False


class AuthService:
    """Manages user identity, password verification, rate limiting, and session lifecycle."""

    def __init__(self, db: DefenseDatabase) -> None:
        self.db = db
        # Tracking for brute-force rate limiting: ip_or_username -> deque of timestamps
        self._failed_attempts: Dict[str, deque] = defaultdict(deque)
        self._lockouts: Dict[str, float] = {}
        self.seed_default_users()

    def _is_rate_limited(self, identifier: str) -> Tuple[bool, int]:
        """Checks whether an IP address or username is temporarily locked out."""
        now = time.time()
        lockout_expiry = self._lockouts.get(identifier, 0.0)
        if now < lockout_expiry:
            return True, int(lockout_expiry - now) + 1

        window = self._failed_attempts[identifier]
        while window and window[0] < now - FAILED_ATTEMPT_WINDOW_SECONDS:
            window.popleft()

        if len(window) >= MAX_FAILED_LOGIN_ATTEMPTS:
            self._lockouts[identifier] = now + LOCKOUT_DURATION_SECONDS
            return True, int(LOCKOUT_DURATION_SECONDS)

        return False, 0

    def _record_failed_attempt(self, identifier: str) -> None:
        """Records a failed authentication attempt."""
        now = time.time()
        self._failed_attempts[identifier].append(now)

    def _clear_failed_attempts(self, identifier: str) -> None:
        """Clears failed attempts on successful login."""
        self._failed_attempts.pop(identifier, None)
        self._lockouts.pop(identifier, None)

    def seed_default_users(self) -> None:
        """Idempotently seeds standard SOC operator accounts if not present."""
        default_accounts = [
            {
                "user_id": "usr_soc_admin",
                "username": "soc_admin",
                "password": "SocAdmin@2026!",
                "role": "admin",
                "full_name": "SOC Lead Administrator",
                "email": "admin@soc.defense.local",
            },
            {
                "user_id": "usr_analyst_01",
                "username": "analyst_01",
                "password": "Analyst@2026!",
                "role": "analyst",
                "full_name": "Senior Threat Analyst",
                "email": "analyst@soc.defense.local",
            },
            {
                "user_id": "usr_operator_01",
                "username": "operator_01",
                "password": "Operator@2026!",
                "role": "operator",
                "full_name": "IoT Mesh Operator",
                "email": "operator@soc.defense.local",
            },
        ]

        for acc in default_accounts:
            existing = self.db.get_user_by_username(acc["username"])
            if not existing:
                pwd_hash, salt = hash_password(acc["password"])
                self.db.create_user(
                    user_id=acc["user_id"],
                    username=acc["username"],
                    password_hash=pwd_hash,
                    salt=salt,
                    role=acc["role"],
                    full_name=acc["full_name"],
                    email=acc["email"],
                    is_active=True,
                )
                logger.info("Initialized default SOC user: %s (role: %s)", acc["username"], acc["role"])

    def authenticate_user(
        self,
        username: str,
        password: str,
        ip_address: str = "",
        user_agent: str = "",
    ) -> Dict[str, Any]:
        """Authenticates user credentials, enforces rate limits, and issues an active session."""
        clean_user = (username or "").strip().lower()
        client_ip = (ip_address or "").strip()

        # Check rate limits for IP and username
        if client_ip:
            limited, retry_after = self._is_rate_limited(client_ip)
            if limited:
                raise RateLimitExceeded(
                    f"Too many failed login attempts from this network. Try again in {retry_after} seconds.",
                    retry_after=retry_after,
                )

        limited, retry_after = self._is_rate_limited(clean_user)
        if limited:
            raise RateLimitExceeded(
                f"Too many failed login attempts for user '{clean_user}'. Try again in {retry_after} seconds.",
                retry_after=retry_after,
            )

        user_rec = self.db.get_user_by_username(clean_user)
        if not user_rec:
            if client_ip:
                self._record_failed_attempt(client_ip)
            self._record_failed_attempt(clean_user)
            raise InvalidCredentials("Invalid username or password.")

        if not user_rec.get("is_active"):
            raise AccountDeactivated("This operator account has been deactivated. Contact your SOC administrator.")

        # Constant-time password verification
        valid = verify_password(password, user_rec["password_hash"], user_rec["salt"])
        if not valid:
            if client_ip:
                self._record_failed_attempt(client_ip)
            self._record_failed_attempt(clean_user)
            raise InvalidCredentials("Invalid username or password.")

        # Successful authentication: clear rate limits
        if client_ip:
            self._clear_failed_attempts(client_ip)
        self._clear_failed_attempts(clean_user)

        now = time.time()
        self.db.update_user_last_login(user_rec["user_id"], now)

        # Generate secure random session ID (32 bytes url-safe -> 43+ chars)
        session_id = f"soc_sess_{secrets.token_urlsafe(32)}"
        expires_at = now + SESSION_TTL_SECONDS

        self.db.create_session(
            session_id=session_id,
            user_id=user_rec["user_id"],
            role=user_rec["role"],
            expires_at=expires_at,
            ip_address=client_ip,
            user_agent=user_agent,
        )

        user_public = {
            "user_id": user_rec["user_id"],
            "username": user_rec["username"],
            "role": user_rec["role"],
            "full_name": user_rec["full_name"],
            "email": user_rec["email"],
            "last_login": now,
        }

        return {
            "session_id": session_id,
            "expires_at": expires_at,
            "user": user_public,
        }

    def validate_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Validates session token and returns authenticated operator metadata."""
        if not session_id:
            return None
        session = self.db.get_session(session_id)
        if not session:
            return None

        now = time.time()
        if session["expires_at"] <= now:
            self.db.delete_session(session_id)
            return None

        if not session.get("is_active"):
            self.db.delete_session(session_id)
            return None

        # Periodically refresh activity timestamp
        if now - session.get("last_activity", 0.0) > 60.0:
            self.db.touch_session(session_id, now)

        return {
            "session_id": session["session_id"],
            "user_id": session["user_id"],
            "username": session["username"],
            "role": session["role"],
            "full_name": session["full_name"],
            "email": session["email"],
            "expires_at": session["expires_at"],
            "last_activity": session["last_activity"],
        }

    def logout_session(self, session_id: str) -> bool:
        """Revokes an active session."""
        return self.db.delete_session(session_id)

    def create_operator(
        self,
        username: str,
        password: str,
        full_name: str,
        email: str,
        role: str = "operator",
    ) -> Dict[str, Any]:
        """Provisions a new operator account with password validation and scrypt hashing."""
        clean_user = (username or "").strip().lower()
        if not USERNAME_RE.match(clean_user):
            raise ValueError("Username must be 3-32 alphanumeric characters, dots, underscores, or hyphens.")

        existing = self.db.get_user_by_username(clean_user)
        if existing:
            raise ValueError(f"Username '{clean_user}' is already registered.")

        clean_role = (role or "operator").strip().lower()
        if clean_role not in VALID_ROLES:
            raise ValueError(f"Invalid role '{role}'. Allowed roles: {', '.join(sorted(VALID_ROLES))}.")

        clean_name = (full_name or "").strip()
        if not clean_name:
            raise ValueError("Full name is required.")

        clean_email = (email or "").strip().lower()
        if not clean_email or "@" not in clean_email:
            raise ValueError("A valid email address is required.")

        validate_password_strength(password)
        pwd_hash, salt = hash_password(password)
        user_id = f"usr_{secrets.token_hex(8)}"

        self.db.create_user(
            user_id=user_id,
            username=clean_user,
            password_hash=pwd_hash,
            salt=salt,
            role=clean_role,
            full_name=clean_name,
            email=clean_email,
            is_active=True,
        )

        return {
            "user_id": user_id,
            "username": clean_user,
            "role": clean_role,
            "full_name": clean_name,
            "email": clean_email,
            "created_at": time.time(),
        }

    def list_operators(self) -> List[Dict[str, Any]]:
        """Lists all registered operators."""
        return self.db.list_users()

    def list_active_sessions(self) -> List[Dict[str, Any]]:
        """Lists active, unexpired operator sessions."""
        now = time.time()
        self.db.clean_expired_sessions(now)
        return self.db.list_active_sessions(now)

    def revoke_session(self, session_id: str) -> bool:
        """Revokes a specific session."""
        return self.db.delete_session(session_id)
