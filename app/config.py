"""
Application configuration - centralized settings for Amphoraxe Auth Service.
All configuration values should be accessed through this module.
"""

import os
from pathlib import Path


# =============================================================================
# Path Configuration
# =============================================================================

BASE_DIR = Path(__file__).resolve().parent.parent
APP_DIR = BASE_DIR / "app"
DATA_DIR = BASE_DIR / "data"
LOGS_DIR = BASE_DIR / "logs"
TEMPLATES_DIR = APP_DIR / "templates"
STATIC_DIR = APP_DIR / "static"


# =============================================================================
# Session Configuration
# =============================================================================

SESSION_DURATION_DAYS = int(os.environ.get("AUTH_SESSION_DURATION_DAYS", "7"))
SECRET_KEY = os.environ.get("AUTH_SECRET_KEY", "")


# =============================================================================
# Email Configuration
# =============================================================================

SMTP_HOST = os.environ.get("AUTH_SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("AUTH_SMTP_PORT", "587"))
SMTP_USER = os.environ.get("AUTH_SMTP_USER", "")
SMTP_FROM = os.environ.get("AUTH_SMTP_FROM", "")
ADMIN_EMAIL = os.environ.get("AUTH_ADMIN_EMAIL", "")


def get_smtp_password() -> str:
    """Get SMTP password from file or environment"""
    env_pass = os.environ.get("AUTH_SMTP_PASS", "")
    if env_pass:
        return env_pass
    password_file = Path.home() / ".vc_smtp_pass"
    if password_file.exists():
        return password_file.read_text().strip()
    return ""


SMTP_PASS = get_smtp_password()


def is_email_configured() -> bool:
    """Check if email is properly configured"""
    return bool(SMTP_HOST and SMTP_USER and SMTP_PASS)


# =============================================================================
# Database Configuration
# =============================================================================

SQLITE_DB_PATH = DATA_DIR / "auth.db"


# =============================================================================
# Application URLs
# =============================================================================

BASE_URL = os.environ.get("AUTH_BASE_URL", "https://auth.amphoraxe.ca")
DEMO_URL = os.environ.get("AUTH_DEMO_URL", "https://demo.amphoraxe.ca")


# =============================================================================
# CORS - Allowed Origins
# =============================================================================

CORS_ORIGINS = [
    "https://demo.amphoraxe.ca",
    "https://dbamp.amphoraxe.ca",
    "https://vc-dataroom.amphoraxe.ca",
    "https://amp-llm.amphoraxe.ca",
    "https://admin.amphoraxe.ca",
    "https://auth.amphoraxe.ca",
]

# Add localhost origins for development
_extra_origins = os.environ.get("AUTH_EXTRA_CORS_ORIGINS", "")
if _extra_origins:
    CORS_ORIGINS.extend(o.strip() for o in _extra_origins.split(",") if o.strip())


# =============================================================================
# Feature Flags
# =============================================================================

ENVIRONMENT = os.environ.get("AUTH_ENV", "development")
IS_PRODUCTION = ENVIRONMENT == "production"
DEBUG = os.environ.get("AUTH_DEBUG", "false").lower() == "true"


# =============================================================================
# Initial Admin (one-time creation on startup)
# =============================================================================

INITIAL_ADMIN_EMAIL = os.environ.get("AUTH_INITIAL_ADMIN_EMAIL", "")
INITIAL_ADMIN_PASSWORD = os.environ.get("AUTH_INITIAL_ADMIN_PASSWORD", "")
