"""FALCON-X Dashboard — Authentication and session management."""

import hashlib
import json
import logging
import os
import secrets
import time
from typing import Dict, Optional, Tuple

logger = logging.getLogger("falconx-web.auth")

# In-memory session store (bounded)
_sessions: Dict[str, dict] = {}
_login_attempts: Dict[str, list] = {}
MAX_SESSIONS = 50
SESSION_TTL = 1800  # 30 minutes


def _hash_password(password: str, salt: str = None) -> Tuple[str, str]:
    """Hash password with salt using SHA-256."""
    if salt is None:
        salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100000)
    return hashed.hex(), salt


def _get_credentials_file() -> str:
    return os.path.join("/etc/falconx", "web-users.json")


def _load_users() -> dict:
    """Load user credentials from file."""
    path = _get_credentials_file()
    if os.path.exists(path):
        try:
            with open(path) as f:
                return json.load(f)
        except Exception as e:
            logger.error("Failed to load users: %s", e)
    return {}


def _save_users(users: dict):
    """Save user credentials to file."""
    path = _get_credentials_file()
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump(users, f, indent=2)
        os.chmod(path, 0o600)
    except Exception as e:
        logger.error("Failed to save users: %s", e)


def create_user(username: str, password: str) -> bool:
    """Create a new user. Returns True on success."""
    users = _load_users()
    if username in users:
        return False

    hashed, salt = _hash_password(password)
    users[username] = {
        "password_hash": hashed,
        "salt": salt,
        "created": time.time(),
        "last_login": 0,
        "role": "admin",
    }
    _save_users(users)
    logger.info("User created: %s", username)
    return True


def authenticate(username: str, password: str) -> Optional[str]:
    """Authenticate user. Returns session token or None."""
    # Rate limiting
    if _is_locked_out(username):
        logger.warning("Login locked out: %s", username)
        return None

    users = _load_users()
    user = users.get(username)
    if not user:
        _record_failed_attempt(username)
        return None

    hashed, _ = _hash_password(password, user["salt"])
    if not secrets.compare_digest(hashed, user["password_hash"]):
        _record_failed_attempt(username)
        logger.warning("Failed login: %s", username)
        return None

    # Clear failed attempts
    _login_attempts.pop(username, None)

    # Create session
    token = secrets.token_urlsafe(32)
    _cleanup_sessions()
    _sessions[token] = {
        "username": username,
        "created": time.time(),
        "last_active": time.time(),
        "role": user.get("role", "admin"),
        "ip": "",
    }

    # Update last login
    user["last_login"] = time.time()
    users[username] = user
    _save_users(users)

    logger.info("Successful login: %s", username)
    return token


def validate_session(token: str) -> Optional[dict]:
    """Validate session token. Returns session info or None."""
    if not token:
        return None
    session = _sessions.get(token)
    if not session:
        return None

    # Check timeout
    if time.time() - session["last_active"] > SESSION_TTL:
        _sessions.pop(token, None)
        return None

    session["last_active"] = time.time()
    return session


def destroy_session(token: str) -> bool:
    """Destroy a session."""
    return _sessions.pop(token, None) is not None


def get_session_user(token: str) -> Optional[str]:
    """Get username from session token."""
    session = validate_session(token)
    return session["username"] if session else None


def require_auth(handler_func):
    """Decorator for requiring authentication."""
    def wrapper(self, *args, **kwargs):
        token = self._get_session_token()
        session = validate_session(token)
        if not session:
            self._send_json(401, {"error": "Authentication required"})
            return
        self._session = session
        return handler_func(self, *args, **kwargs)
    return wrapper


def _record_failed_attempt(username: str):
    now = time.time()
    if username not in _login_attempts:
        _login_attempts[username] = []
    _login_attempts[username].append(now)
    # Keep only recent attempts
    _login_attempts[username] = [
        t for t in _login_attempts[username] if now - t < 900
    ]


def _is_locked_out(username: str) -> bool:
    attempts = _login_attempts.get(username, [])
    now = time.time()
    recent = [t for t in attempts if now - t < 900]
    return len(recent) >= 5


def _cleanup_sessions():
    now = time.time()
    expired = [t for t, s in _sessions.items() if now - s["last_active"] > SESSION_TTL]
    for t in expired:
        _sessions.pop(t, None)
    if len(_sessions) >= MAX_SESSIONS:
        oldest = sorted(_sessions, key=lambda t: _sessions[t]["last_active"])[:10]
        for t in oldest:
            _sessions.pop(t, None)


def init_default_user():
    """Create default admin user if no users exist.

    Password is written to /etc/falconx/initial-password.txt only.
    NEVER logged or printed to stdout.
    """
    users = _load_users()
    if not users:
        password = secrets.token_urlsafe(12)
        create_user("admin", password)
        logger.info("Default admin user created")
        # Write password to file — NEVER to logs/stdout
        pw_file = os.path.join("/etc/falconx", "initial-password.txt")
        try:
            with open(pw_file, "w") as f:
                f.write(f"admin:{password}\n")
            os.chmod(pw_file, 0o600)
        except Exception:
            pass
