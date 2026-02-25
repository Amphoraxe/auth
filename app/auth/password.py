"""
Password hashing and verification utilities.
Supports bcrypt (current) and SHA-256 (legacy, for migration).
"""

import hashlib
import bcrypt

from app.logging_config import get_logger

logger = get_logger(__name__)

BCRYPT_ROUNDS = 12


def hash_password(password: str) -> str:
    """Hash password using bcrypt"""
    password_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')


def _verify_legacy_password(password: str, password_hash: str) -> bool:
    """Verify password against legacy SHA-256 hash"""
    try:
        salt, hashed = password_hash.split("$")
        return hashlib.sha256((salt + password).encode()).hexdigest() == hashed
    except ValueError:
        return False


def verify_password(password: str, password_hash: str) -> bool:
    """Verify password against stored hash (bcrypt or legacy SHA-256)."""
    if password_hash.startswith(('$2b$', '$2a$', '$2y$')):
        try:
            return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
        except Exception as e:
            logger.error(f"Bcrypt verification error: {e}")
            return False
    else:
        return _verify_legacy_password(password, password_hash)


def is_bcrypt_hash(password_hash: str) -> bool:
    return password_hash.startswith(('$2b$', '$2a$', '$2y$'))
