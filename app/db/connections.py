"""
Database connection management for SQLite.
"""

import sqlite3
from contextlib import contextmanager
from typing import Generator

from app.config import SQLITE_DB_PATH
from app.logging_config import get_logger

logger = get_logger(__name__)

# Ensure data directory exists
SQLITE_DB_PATH.parent.mkdir(exist_ok=True)


def get_db_connection() -> sqlite3.Connection:
    """Get a SQLite database connection with row factory"""
    conn = sqlite3.connect(str(SQLITE_DB_PATH), timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


@contextmanager
def get_db() -> Generator[sqlite3.Connection, None, None]:
    """Context manager for SQLite database connections"""
    conn = get_db_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
