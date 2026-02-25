"""
Rate Limiting - Protection against brute force attacks.
"""

import time
from collections import defaultdict
from typing import Tuple

from app.logging_config import log_security, get_logger

logger = get_logger(__name__)

LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 300
SIGNUP_MAX_ATTEMPTS = 3
SIGNUP_WINDOW_SECONDS = 3600

_login_attempts: dict = defaultdict(list)
_signup_attempts: dict = defaultdict(list)
MAX_TRACKED_IPS = 10000


def _cleanup_old_entries(attempts: dict, window_seconds: int):
    current_time = time.time()
    cutoff = current_time - window_seconds
    for ip in list(attempts.keys()):
        attempts[ip] = [ts for ts in attempts[ip] if ts > cutoff]
        if not attempts[ip]:
            del attempts[ip]
    if len(attempts) > MAX_TRACKED_IPS:
        sorted_ips = sorted(attempts.keys(), key=lambda ip: min(attempts[ip]) if attempts[ip] else 0)
        for ip in sorted_ips[:len(attempts) - MAX_TRACKED_IPS]:
            del attempts[ip]


def check_login_rate_limit(ip_address: str) -> Tuple[bool, int]:
    current_time = time.time()
    window_start = current_time - LOGIN_WINDOW_SECONDS
    _cleanup_old_entries(_login_attempts, LOGIN_WINDOW_SECONDS)
    recent_attempts = [ts for ts in _login_attempts[ip_address] if ts > window_start]
    if len(recent_attempts) >= LOGIN_MAX_ATTEMPTS:
        oldest_attempt = min(recent_attempts)
        seconds_remaining = int(oldest_attempt + LOGIN_WINDOW_SECONDS - current_time)
        log_security("LOGIN_RATE_LIMITED", f"Rate limited after {len(recent_attempts)} attempts",
                     ip_address=ip_address)
        return False, max(1, seconds_remaining)
    return True, 0


def record_login_attempt(ip_address: str):
    _login_attempts[ip_address].append(time.time())


def check_signup_rate_limit(ip_address: str) -> Tuple[bool, int]:
    current_time = time.time()
    window_start = current_time - SIGNUP_WINDOW_SECONDS
    _cleanup_old_entries(_signup_attempts, SIGNUP_WINDOW_SECONDS)
    recent_attempts = [ts for ts in _signup_attempts[ip_address] if ts > window_start]
    if len(recent_attempts) >= SIGNUP_MAX_ATTEMPTS:
        oldest_attempt = min(recent_attempts)
        seconds_remaining = int(oldest_attempt + SIGNUP_WINDOW_SECONDS - current_time)
        log_security("SIGNUP_RATE_LIMITED", f"Rate limited after {len(recent_attempts)} attempts",
                     ip_address=ip_address)
        return False, max(1, seconds_remaining)
    return True, 0


def record_signup_attempt(ip_address: str):
    _signup_attempts[ip_address].append(time.time())


def clear_login_attempts(ip_address: str):
    if ip_address in _login_attempts:
        del _login_attempts[ip_address]
