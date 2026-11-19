"""Unit and integration tests for SOC User Authentication, Sessions, and Operator Dashboard."""

import os
import tempfile
import time
import unittest
from typing import Any, Dict

from starlette.testclient import TestClient

from controller.api.app import create_app
from controller.core.auth import (
    AuthService,
    InvalidCredentials,
    RateLimitExceeded,
    hash_password,
    validate_password_strength,
    verify_password,
)
from controller.core.db import DefenseDatabase


class TestAuthServiceAndScrypt(unittest.TestCase):
    """Verifies low-level scrypt hashing, password validation, and rate limiting."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "auth_test.db")
        self.db = DefenseDatabase(db_path=self.db_path)
        self.auth_service = AuthService(db=self.db)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_scrypt_hash_and_verification(self) -> None:
        raw_pwd = "SecureDefense@2026!"
        h1, s1 = hash_password(raw_pwd)
        self.assertEqual(len(s1), 64)  # 32 bytes hex
        self.assertGreaterEqual(len(h1), 64)

        # Verification succeeds
        self.assertTrue(verify_password(raw_pwd, h1, s1))
        # Wrong password fails
        self.assertFalse(verify_password("WrongPassword@123", h1, s1))
        # Tampered salt fails
        tampered_salt = "00" * 32
        self.assertFalse(verify_password(raw_pwd, h1, tampered_salt))

    def test_password_strength_validation(self) -> None:
        # Valid strong password
        validate_password_strength("ValidPass@1234")

        # Too short
        with self.assertRaises(ValueError) as ctx:
            validate_password_strength("Short1!")
        self.assertIn("at least 8 characters", str(ctx.exception))

        # Missing uppercase
        with self.assertRaises(ValueError) as ctx:
            validate_password_strength("lowercase123!")
        self.assertIn("uppercase", str(ctx.exception))

        # Missing digit
        with self.assertRaises(ValueError) as ctx:
            validate_password_strength("NoDigitsHere!")
        self.assertIn("digit", str(ctx.exception))

        # Missing symbol
        with self.assertRaises(ValueError) as ctx:
            validate_password_strength("NoSymbols1234")
        self.assertIn("special symbol", str(ctx.exception))

    def test_default_users_seeded(self) -> None:
        admin = self.db.get_user_by_username("soc_admin")
        self.assertIsNotNone(admin)
        self.assertEqual(admin["role"], "admin")

        analyst = self.db.get_user_by_username("analyst_01")
        self.assertIsNotNone(analyst)
        self.assertEqual(analyst["role"], "analyst")

        operator = self.db.get_user_by_username("operator_01")
        self.assertIsNotNone(operator)
        self.assertEqual(operator["role"], "operator")

    def test_login_rate_limiting(self) -> None:
        ip = "192.0.2.99"
        # 5 failed attempts
        for _ in range(5):
            with self.assertRaises(InvalidCredentials):
                self.auth_service.authenticate_user("soc_admin", "WrongPassword!99", ip_address=ip)

        # 6th attempt triggers rate limit
        with self.assertRaises(RateLimitExceeded) as ctx:
            self.auth_service.authenticate_user("soc_admin", "SocAdmin@2026!", ip_address=ip)
        self.assertIn("Too many failed login attempts", str(ctx.exception))
        self.assertGreater(ctx.exception.retry_after, 0)


class TestAuthAPIEndpoints(unittest.TestCase):
    """End-to-end API tests for Authentication, Sessions, and User Management."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "auth_api_test.db")
        os.environ["DEFENSE_DB_PATH"] = self.db_path
        self.app = create_app(enable_tailer=False)
        self.client = TestClient(self.app)

    def tearDown(self) -> None:
        os.environ.pop("DEFENSE_DB_PATH", None)
        self.temp_dir.cleanup()

    def test_login_success_and_cookie(self) -> None:
        res = self.client.post(
            "/api/auth/login",
            json={"username": "soc_admin", "password": "SocAdmin@2026!"},
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()["data"]
        self.assertIn("session_id", data)
        self.assertTrue(data["session_id"].startswith("soc_sess_"))
        self.assertEqual(data["user"]["username"], "soc_admin")
        self.assertEqual(data["user"]["role"], "admin")

        # Verify cookie is set
        self.assertIn("soc_session", res.cookies)

    def test_login_invalid_password_returns_401(self) -> None:
        res = self.client.post(
            "/api/auth/login",
            json={"username": "soc_admin", "password": "IncorrectPassword!1"},
        )
        self.assertEqual(res.status_code, 401)
        self.assertIn("Invalid username or password", res.json()["detail"])

    def test_get_current_user_profile(self) -> None:
        # Unauthenticated request returns 401
        unauth_res = self.client.get("/api/auth/me")
        self.assertEqual(unauth_res.status_code, 401)

        # Authenticate
        login_res = self.client.post(
            "/api/auth/login",
            json={"username": "analyst_01", "password": "Analyst@2026!"},
        )
        self.assertEqual(login_res.status_code, 200)
        token = login_res.json()["data"]["session_id"]

        # Request with Bearer header
        auth_res = self.client.get(
            "/api/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(auth_res.status_code, 200)
        user = auth_res.json()["data"]["user"]
        self.assertEqual(user["username"], "analyst_01")
        self.assertEqual(user["role"], "analyst")

    def test_logout_revokes_session(self) -> None:
        login_res = self.client.post(
            "/api/auth/login",
            json={"username": "operator_01", "password": "Operator@2026!"},
        )
        token = login_res.json()["data"]["session_id"]

        # Logout with token
        logout_res = self.client.post(
            "/api/auth/logout",
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(logout_res.status_code, 200)

        # Subsequent profile request returns 401
        profile_res = self.client.get(
            "/api/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(profile_res.status_code, 401)

    def test_admin_rbac_and_user_creation(self) -> None:
        # Login as analyst
        analyst_login = self.client.post(
            "/api/auth/login",
            json={"username": "analyst_01", "password": "Analyst@2026!"},
        )
        analyst_token = analyst_login.json()["data"]["session_id"]

        # Analyst cannot access /api/auth/users (403 Forbidden)
        forbidden_list = self.client.get(
            "/api/auth/users",
            headers={"Authorization": f"Bearer {analyst_token}"},
        )
        self.assertEqual(forbidden_list.status_code, 403)

        # Analyst cannot create a user (403 Forbidden)
        forbidden_create = self.client.post(
            "/api/auth/users",
            headers={"Authorization": f"Bearer {analyst_token}"},
            json={
                "username": "junior_sec",
                "password": "JuniorPassword@2026!",
                "full_name": "Junior Sec Analyst",
                "email": "junior@soc.defense.local",
                "role": "analyst",
            },
        )
        self.assertEqual(forbidden_create.status_code, 403)

        # Login as Admin
        admin_login = self.client.post(
            "/api/auth/login",
            json={"username": "soc_admin", "password": "SocAdmin@2026!"},
        )
        admin_token = admin_login.json()["data"]["session_id"]

        # Admin can list users
        admin_list = self.client.get(
            "/api/auth/users",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        self.assertEqual(admin_list.status_code, 200)
        self.assertGreaterEqual(len(admin_list.json()["data"]["users"]), 3)

        # Admin can create a new operator
        new_uname = f"op_{int(time.time() * 1000) % 100000}"
        create_res = self.client.post(
            "/api/auth/users",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={
                "username": new_uname,
                "password": "NightShift@2026!",
                "full_name": "Night Shift Operator",
                "email": f"{new_uname}@soc.defense.local",
                "role": "operator",
            },
        )
        self.assertEqual(create_res.status_code, 200)
        new_user = create_res.json()["data"]["user"]
        self.assertEqual(new_user["username"], new_uname)

        # Newly created operator can log in
        night_login = self.client.post(
            "/api/auth/login",
            json={"username": new_uname, "password": "NightShift@2026!"},
        )
        self.assertEqual(night_login.status_code, 200)

    def test_session_audit_and_revocation(self) -> None:
        # Admin logs in
        admin_login = self.client.post(
            "/api/auth/login",
            json={"username": "soc_admin", "password": "SocAdmin@2026!"},
        )
        admin_token = admin_login.json()["data"]["session_id"]

        # Operator logs in to create another session
        op_login = self.client.post(
            "/api/auth/login",
            json={"username": "operator_01", "password": "Operator@2026!"},
        )
        op_token = op_login.json()["data"]["session_id"]

        # Admin lists active sessions
        sessions_res = self.client.get(
            "/api/auth/sessions",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        self.assertEqual(sessions_res.status_code, 200)
        sessions = sessions_res.json()["data"]["sessions"]
        self.assertGreaterEqual(len(sessions), 2)

        # Admin revokes operator's session
        revoke_res = self.client.delete(
            f"/api/auth/sessions/{op_token}",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        self.assertEqual(revoke_res.status_code, 200)

        # Operator session is now invalid
        op_check = self.client.get(
            "/api/auth/me",
            headers={"Authorization": f"Bearer {op_token}"},
        )
        self.assertEqual(op_check.status_code, 401)


if __name__ == "__main__":
    unittest.main()
