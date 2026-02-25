"""
Logging configuration for Amphoraxe Auth Service.
"""

import logging
import sys
from pathlib import Path
from logging.handlers import RotatingFileHandler
from typing import Optional


LOG_DIR = Path(__file__).resolve().parent.parent / "logs"
LOG_DIR.mkdir(exist_ok=True)

APP_LOG = LOG_DIR / "app.log"
ERROR_LOG = LOG_DIR / "error.log"
ACCESS_LOG = LOG_DIR / "access.log"
SECURITY_LOG = LOG_DIR / "security.log"
STARTUP_LOG = LOG_DIR / "startup.log"


class ContextFilter(logging.Filter):
    """Add user_id and ip_address to log records"""

    def filter(self, record):
        if not hasattr(record, 'user_id'):
            record.user_id = '-'
        if not hasattr(record, 'ip_address'):
            record.ip_address = '-'
        if not hasattr(record, 'action'):
            record.action = '-'
        return True


def setup_logging(log_level: str = "INFO"):
    detailed_formatter = logging.Formatter(
        '[%(asctime)s] %(levelname)s [%(name)s:%(lineno)d] [user:%(user_id)s] [ip:%(ip_address)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    simple_formatter = logging.Formatter(
        '[%(asctime)s] %(levelname)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))
    root_logger.handlers = []

    context_filter = ContextFilter()
    root_logger.addFilter(context_filter)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(simple_formatter)
    root_logger.addHandler(console_handler)

    app_handler = RotatingFileHandler(APP_LOG, maxBytes=10*1024*1024, backupCount=10, encoding='utf-8')
    app_handler.setLevel(logging.DEBUG)
    app_handler.addFilter(context_filter)
    app_handler.setFormatter(detailed_formatter)
    root_logger.addHandler(app_handler)

    error_handler = RotatingFileHandler(ERROR_LOG, maxBytes=10*1024*1024, backupCount=10, encoding='utf-8')
    error_handler.setLevel(logging.ERROR)
    error_handler.addFilter(context_filter)
    error_handler.setFormatter(detailed_formatter)
    root_logger.addHandler(error_handler)

    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.error").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)

    return root_logger


def setup_access_logger() -> logging.Logger:
    access_logger = logging.getLogger("access")
    access_logger.setLevel(logging.DEBUG)
    access_logger.propagate = False
    access_logger.addFilter(ContextFilter())
    handler = RotatingFileHandler(ACCESS_LOG, maxBytes=10*1024*1024, backupCount=10, encoding='utf-8')
    handler.setFormatter(logging.Formatter(
        '[%(asctime)s] [user:%(user_id)s] [ip:%(ip_address)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    ))
    access_logger.addHandler(handler)
    return access_logger


def setup_security_logger() -> logging.Logger:
    security_logger = logging.getLogger("security")
    security_logger.setLevel(logging.DEBUG)
    security_logger.propagate = False
    security_logger.addFilter(ContextFilter())
    handler = RotatingFileHandler(SECURITY_LOG, maxBytes=10*1024*1024, backupCount=20, encoding='utf-8')
    handler.setFormatter(logging.Formatter(
        '[%(asctime)s] [SECURITY] [user:%(user_id)s] [ip:%(ip_address)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    ))
    security_logger.addHandler(handler)
    return security_logger


def setup_startup_logger() -> logging.Logger:
    startup_logger = logging.getLogger("startup")
    startup_logger.setLevel(logging.DEBUG)
    startup_logger.propagate = False
    startup_logger.addFilter(ContextFilter())
    formatter = logging.Formatter(
        '[%(asctime)s] [STARTUP] %(levelname)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    handler = RotatingFileHandler(STARTUP_LOG, maxBytes=5*1024*1024, backupCount=5, encoding='utf-8')
    handler.setFormatter(formatter)
    startup_logger.addHandler(handler)
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(formatter)
    startup_logger.addHandler(console)
    return startup_logger


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)


class LogContext:
    _user_id: Optional[int] = None
    _ip_address: Optional[str] = None

    @classmethod
    def set(cls, user_id: Optional[int] = None, ip_address: Optional[str] = None):
        cls._user_id = user_id
        cls._ip_address = ip_address

    @classmethod
    def get_user_id(cls) -> str:
        return str(cls._user_id) if cls._user_id else '-'

    @classmethod
    def get_ip(cls) -> str:
        return cls._ip_address or '-'

    @classmethod
    def clear(cls):
        cls._user_id = None
        cls._ip_address = None


def log_access(event: str, details: str = "",
               user_id: Optional[int] = None, ip_address: Optional[str] = None):
    uid = user_id if user_id else LogContext.get_user_id()
    ip = ip_address if ip_address else LogContext.get_ip()
    access_logger.info(f"[{event}] {details}", extra={'user_id': uid, 'ip_address': ip})


def log_security(event: str, details: str = "",
                 user_id: Optional[int] = None, ip_address: Optional[str] = None):
    uid = user_id if user_id else LogContext.get_user_id()
    ip = ip_address if ip_address else LogContext.get_ip()
    security_logger.warning(f"[{event}] {details}", extra={'user_id': uid, 'ip_address': ip})


def log_startup(level: str, message: str):
    log_func = getattr(startup_logger, level.lower(), startup_logger.info)
    log_func(message, extra={'user_id': '-', 'ip_address': '-', 'action': '-'})


# Initialize on import
logger = setup_logging()
access_logger = setup_access_logger()
security_logger = setup_security_logger()
startup_logger = setup_startup_logger()
