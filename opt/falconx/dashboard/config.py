"""FALCON-X Dashboard — Configuration."""

import os

# ── Server ────────────────────────────────────────────────────────
HOST = os.environ.get("FALCONX_WEB_HOST", "0.0.0.0")
PORT = int(os.environ.get("FALCONX_WEB_PORT", "8443"))
DEBUG = os.environ.get("FALCONX_WEB_DEBUG", "false").lower() == "true"

# ── Paths ─────────────────────────────────────────────────────────
FALCONX_ETC = "/etc/falconx"
FALCONX_VAR = "/var/lib/falconx"
FALCONX_LOG = "/var/log/falconx"
CONFIG_DIR = FALCONX_ETC
SECRETS_DIR = os.path.join(FALCONX_ETC, "secrets")

# ── TLS ───────────────────────────────────────────────────────────
TLS_CERT = os.path.join(SECRETS_DIR, "server.crt")
TLS_KEY = os.path.join(SECRETS_DIR, "server.key")

# ── Authentication ────────────────────────────────────────────────
SECRET_KEY_FILE = os.path.join(SECRETS_DIR, "web-secret.key")
SESSION_TIMEOUT_MINUTES = 30
MAX_SESSIONS = 50
MAX_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_MINUTES = 15

# ── Rate Limiting ─────────────────────────────────────────────────
RATE_LIMIT_API = 100        # requests per minute
RATE_LIMIT_LOGIN = 10       # login attempts per minute
RATE_LIMIT_WINDOW = 60      # seconds

# ── Engine API ────────────────────────────────────────────────────
ENGINE_API_URL = "http://127.0.0.1:9100"

# ── OmniRoute AI ──────────────────────────────────────────────────
OMNIROUTE_ENABLED = os.environ.get("FALCONX_OMNIROUTE_ENABLED", "false").lower() == "true"
OMNIROUTE_URL = os.environ.get("FALCONX_OMNIROUTE_URL", "http://127.0.0.1:11434")
OMNIROUTE_MODEL = os.environ.get("FALCONX_OMNIROUTE_MODEL", "llama3.2")
OMNIROUTE_TIMEOUT = 30
OMNIROUTE_MAX_TOKENS = 512

# ── Static Files ──────────────────────────────────────────────────
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")

# ── CORS ──────────────────────────────────────────────────────────
ALLOWED_ORIGINS = ["https://localhost:8443", "https://127.0.0.1:8443"]
